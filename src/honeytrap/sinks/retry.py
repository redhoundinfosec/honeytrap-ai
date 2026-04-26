"""Backoff policies and circuit breaker shared by every sink.

Goals:

* Bounded retries with exponential delay and jitter so transient
  network blips don't reorder events.
* A simple three-state circuit breaker so a downed SIEM doesn't
  burn CPU retrying every batch -- we open the circuit, drop fast,
  and probe again after a cool-down.

The breaker is kept tiny on purpose: ten consecutive failures opens
it, the next attempt after thirty seconds half-opens it, and a single
success closes it back. No sliding windows, no rate limiters --
honeypot traffic is bursty and the consumers are downstream services
that we cannot tune.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class BreakerState(str, Enum):
    """Circuit breaker state."""

    CLOSED = "closed"
    HALF_OPEN = "half_open"
    OPEN = "open"


@dataclass
class CircuitBreaker:
    """Three-state circuit breaker with consecutive-failure tripping."""

    failure_threshold: int = 10
    cooldown_seconds: float = 30.0
    state: BreakerState = BreakerState.CLOSED
    consecutive_failures: int = 0
    opened_at: float = 0.0
    last_error: str | None = None

    def allow(self) -> bool:
        """Return True when a new attempt should be made."""
        if self.state is BreakerState.CLOSED:
            return True
        if self.state is BreakerState.OPEN:
            if (time.monotonic() - self.opened_at) >= self.cooldown_seconds:
                self.state = BreakerState.HALF_OPEN
                return True
            return False
        # half-open: allow exactly one probe at a time
        return True

    def record_success(self) -> None:
        """Reset the breaker after a successful call."""
        self.consecutive_failures = 0
        self.state = BreakerState.CLOSED
        self.last_error = None

    def record_failure(self, error: str) -> None:
        """Bump the failure counter and possibly trip the breaker."""
        self.consecutive_failures += 1
        self.last_error = error
        if self.consecutive_failures >= self.failure_threshold:
            self.state = BreakerState.OPEN
            self.opened_at = time.monotonic()


@dataclass
class RetryPolicy:
    """Exponential backoff with jitter and a hard retry ceiling."""

    base_seconds: float = 0.25
    max_seconds: float = 30.0
    max_attempts: int = 5
    jitter: float = 0.1
    rng: random.Random = field(default_factory=random.Random)

    def delay_for(self, attempt: int) -> float:
        """Return the delay (in seconds) before retry #``attempt`` (0-based)."""
        if attempt < 0:
            attempt = 0
        raw = self.base_seconds * (2**attempt)
        capped = min(self.max_seconds, raw)
        # Symmetric jitter inside +/- self.jitter * capped, never negative.
        spread = capped * self.jitter
        offset = self.rng.uniform(-spread, spread)
        return max(0.0, capped + offset)


async def execute_with_retry(
    coro_factory,
    *,
    policy: RetryPolicy,
    breaker: CircuitBreaker,
    sleep=asyncio.sleep,
) -> None:
    """Run ``coro_factory()`` honoring ``policy`` and ``breaker``.

    ``coro_factory`` is a zero-argument callable returning a fresh
    awaitable each call so we don't reuse a consumed coroutine.

    Raises:
        RuntimeError: when the breaker is open.
        Exception: the last error if all attempts fail.
    """
    if not breaker.allow():
        raise RuntimeError(f"circuit breaker open: {breaker.last_error or 'unknown'}")

    last_error: BaseException | None = None
    for attempt in range(policy.max_attempts):
        try:
            await coro_factory()
            breaker.record_success()
            return
        except Exception as exc:  # noqa: BLE001 -- rethrow at end of loop
            last_error = exc
            breaker.record_failure(str(exc))
            if not breaker.allow():
                raise RuntimeError(f"circuit breaker open: {exc}") from exc
            if attempt < policy.max_attempts - 1:
                await sleep(policy.delay_for(attempt))
    assert last_error is not None
    raise last_error
