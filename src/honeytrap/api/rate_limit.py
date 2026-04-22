"""Per-API-key token-bucket rate limiter.

Each key has a bucket sized to its role's requests-per-minute budget.
Buckets refill continuously (capacity / 60 tokens per second). When a
request arrives we try to consume one token; failure means the caller
is over budget and we return how many seconds until the next token is
available so the server can emit ``Retry-After``.

All bookkeeping is in memory and thread-safe. There is no persistence:
restarting the server resets budgets, which is the correct behaviour for
a control-plane API that expects to be restarted rarely.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    """Internal state of a single token bucket."""

    capacity: float
    tokens: float
    refill_per_sec: float
    last: float


class RateLimiter:
    """Token-bucket rate limiter keyed by API key id."""

    def __init__(self, limits: dict[str, int]) -> None:
        """Create a limiter with ``limits`` mapping role name -> req/min."""
        self._limits = {k: max(1, int(v)) for k, v in limits.items()}
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _capacity_for(self, role: str) -> int:
        return self._limits.get(role, 60)

    def check(self, *, key_id: str, role: str, now: float | None = None) -> tuple[bool, float]:
        """Try to consume a token. Return ``(allowed, retry_after_seconds)``.

        ``retry_after_seconds`` is 0 on the allowed path and a positive
        float on the rejection path equal to the time until one more
        token becomes available.
        """
        current = time.monotonic() if now is None else float(now)
        capacity = float(self._capacity_for(role))
        refill = capacity / 60.0
        with self._lock:
            bucket = self._buckets.get(key_id)
            if bucket is None or bucket.capacity != capacity:
                bucket = _Bucket(
                    capacity=capacity,
                    tokens=capacity,
                    refill_per_sec=refill,
                    last=current,
                )
                self._buckets[key_id] = bucket
            elapsed = max(0.0, current - bucket.last)
            bucket.tokens = min(bucket.capacity, bucket.tokens + elapsed * bucket.refill_per_sec)
            bucket.last = current
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0.0
            deficit = 1.0 - bucket.tokens
            retry = deficit / bucket.refill_per_sec if bucket.refill_per_sec > 0 else 1.0
            return False, retry

    def reset(self, key_id: str | None = None) -> None:
        """Reset one key (or all when ``None``). Primarily for tests."""
        with self._lock:
            if key_id is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key_id, None)
