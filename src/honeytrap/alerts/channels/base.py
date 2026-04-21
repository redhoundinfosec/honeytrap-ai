"""Abstract base class for alert channels plus the token bucket limiter."""

from __future__ import annotations

import abc
import asyncio
import logging
import time
from typing import Any

from honeytrap.alerts.models import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class TokenBucket:
    """Async-safe token bucket used for per-channel rate limiting.

    The bucket starts full. Each :meth:`try_consume` takes one token
    (if available) and refills at a rate of ``rate_per_minute / 60``
    tokens per second, capped at ``capacity``.
    """

    def __init__(
        self,
        rate_per_minute: int,
        *,
        capacity: int | None = None,
        clock: Any = None,
    ) -> None:
        """Create a bucket of the given refill rate and capacity."""
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        self.rate_per_minute = int(rate_per_minute)
        self.capacity = int(capacity if capacity is not None else rate_per_minute)
        self._tokens: float = float(self.capacity)
        self._clock = clock or time.monotonic
        self._last = self._clock()
        self._lock = asyncio.Lock()

    async def try_consume(self, amount: float = 1.0) -> bool:
        """Attempt to consume ``amount`` tokens. Returns True on success."""
        async with self._lock:
            now = self._clock()
            elapsed = max(0.0, now - self._last)
            self._last = now
            refill = elapsed * (self.rate_per_minute / 60.0)
            self._tokens = min(float(self.capacity), self._tokens + refill)
            if self._tokens >= amount:
                self._tokens -= amount
                return True
            return False

    @property
    def tokens(self) -> float:
        """Return the current (non-refilled) token count. Useful for tests."""
        return self._tokens


class AlertChannel(abc.ABC):
    """Abstract async-sending alert channel.

    Subclasses implement :meth:`_send` with the protocol-specific logic.
    :meth:`send` handles severity filtering, rate limiting, and error
    propagation. The ABC is kept intentionally small so new channels
    (PagerDuty, Opsgenie, etc.) can be added trivially.
    """

    def __init__(
        self,
        name: str,
        *,
        min_severity: AlertSeverity = AlertSeverity.MEDIUM,
        rate_limit_per_minute: int = 60,
    ) -> None:
        """Initialize common channel state."""
        if not name:
            raise ValueError("channel name required")
        self.name = name
        self.min_severity = AlertSeverity.from_name(min_severity)
        self.rate_limit_per_minute = int(rate_limit_per_minute)
        self._bucket = TokenBucket(
            self.rate_limit_per_minute,
            capacity=max(1, self.rate_limit_per_minute),
        )

    def accepts(self, alert: Alert) -> bool:
        """Return True if the channel wants to see ``alert`` at all."""
        return alert.severity >= self.min_severity

    async def allow(self) -> bool:
        """Return True if the rate limiter permits sending another alert now."""
        return await self._bucket.try_consume(1.0)

    async def send(self, alert: Alert) -> None:
        """Send the alert after checking severity and rate-limit budget."""
        if not self.accepts(alert):
            return
        if not await self.allow():
            raise RateLimitExceeded(self.name)
        await self._send(alert)

    @abc.abstractmethod
    async def _send(self, alert: Alert) -> None:
        """Protocol-specific send implementation — overridden by subclasses."""
        raise NotImplementedError

    async def close(self) -> None:
        """Release any channel-held resources. Default is a no-op."""
        return None


class RateLimitExceeded(RuntimeError):  # noqa: N818 — name kept for public API
    """Raised by :meth:`AlertChannel.send` when the bucket has no tokens left."""

    def __init__(self, channel_name: str) -> None:
        """Record the name of the channel that rejected the alert."""
        super().__init__(f"Rate limit exceeded for channel {channel_name!r}")
        self.channel_name = channel_name
