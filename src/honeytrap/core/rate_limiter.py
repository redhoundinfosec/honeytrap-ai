"""Per-IP and global connection rate limiting.

Implements a token-bucket rate limiter per source IP along with a pair of
concurrent-connection caps (global and per-IP). The limiter is purely
in-memory and async-safe: every mutation happens under an ``asyncio.Lock``
so handlers running across many tasks don't race.

Design notes
------------
* Token buckets favor attacker-realistic workloads: small bursts are fine,
  sustained floods are not. The ``capacity`` parameter is the burst size;
  ``refill_per_second`` is the steady-state allowance.
* Concurrent caps protect us from the other half of DoS — slow-open
  connections that don't need fresh tokens because they never close.
* Stale IP entries are pruned after ``stale_after_seconds`` of inactivity
  to keep memory bounded under scanner fleets rotating IPs.
* When a limit is hit the caller can choose between rejecting the
  connection outright or "tarpitting" (delaying the response) so the
  attacker wastes their own resources instead of ours.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class _Bucket:
    """Per-IP token bucket plus concurrency counter."""

    tokens: float
    last_refill: float
    active: int = 0
    total_blocked: int = 0
    last_seen: float = field(default_factory=time.monotonic)


class RateLimitDecision:
    """Result of a rate-limit check."""

    __slots__ = ("allowed", "reason", "retry_after", "tarpit_seconds")

    def __init__(
        self,
        allowed: bool,
        *,
        reason: str = "",
        retry_after: float = 0.0,
        tarpit_seconds: float = 0.0,
    ) -> None:
        """Create a decision.

        Args:
            allowed: Whether the connection should proceed.
            reason: Short, human-readable cause when ``allowed`` is False.
            retry_after: Seconds the client would need to wait for a token.
            tarpit_seconds: If > 0, handler should sleep this long before
                closing — used when ``tarpit_on_limit`` is enabled.
        """
        self.allowed = allowed
        self.reason = reason
        self.retry_after = retry_after
        self.tarpit_seconds = tarpit_seconds

    def __bool__(self) -> bool:  # pragma: no cover — convenience
        return self.allowed


class RateLimiter:
    """Async-safe token-bucket limiter with concurrency caps."""

    def __init__(
        self,
        *,
        max_per_minute: int = 30,
        burst: int = 10,
        global_concurrent: int = 500,
        per_ip_concurrent: int = 20,
        stale_after_seconds: float = 600.0,
        tarpit_on_limit: bool = False,
        tarpit_seconds: float = 2.0,
        enabled: bool = True,
    ) -> None:
        """Configure the limiter.

        Args:
            max_per_minute: Steady-state allowance per IP per minute.
            burst: Bucket capacity — the size of the allowed burst.
            global_concurrent: Maximum concurrent connections across all IPs.
            per_ip_concurrent: Maximum concurrent connections from one IP.
            stale_after_seconds: IPs not seen for this long are pruned.
            tarpit_on_limit: If True, ``check`` returns ``allowed=False``
                with ``tarpit_seconds`` set — the handler should sleep
                before closing instead of dropping immediately.
            tarpit_seconds: Default tarpit delay when tarpitting is active.
            enabled: Global on/off switch.
        """
        self.enabled = enabled
        self.max_per_minute = max(1, max_per_minute)
        self.burst = max(1, burst)
        self.refill_per_second = self.max_per_minute / 60.0
        self.global_concurrent_cap = max(1, global_concurrent)
        self.per_ip_concurrent_cap = max(1, per_ip_concurrent)
        self.stale_after_seconds = stale_after_seconds
        self.tarpit_on_limit = tarpit_on_limit
        self.tarpit_seconds = tarpit_seconds

        self._buckets: dict[str, _Bucket] = {}
        self._global_active = 0
        self._lock = asyncio.Lock()
        self._blocked_ips: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def check(self, ip: str) -> RateLimitDecision:
        """Decide whether a new connection from ``ip`` should proceed.

        Returns a :class:`RateLimitDecision`. Callers must still call
        :meth:`acquire` afterwards if they intend to hold a slot (the
        check and acquire are separate so handlers can log rejections
        without incrementing counters).
        """
        if not self.enabled:
            return RateLimitDecision(True)
        now = time.monotonic()
        async with self._lock:
            self._prune_locked(now)

            if self._global_active >= self.global_concurrent_cap:
                self._record_block_locked(ip, "global_concurrent_cap")
                return self._reject("global concurrent connection cap reached")

            bucket = self._buckets.get(ip)
            if bucket is None:
                bucket = _Bucket(tokens=float(self.burst), last_refill=now, last_seen=now)
                self._buckets[ip] = bucket
            else:
                elapsed = now - bucket.last_refill
                # Cap refill at ``burst`` — this is what gives token buckets
                # their signature burst-then-steady behavior.
                bucket.tokens = min(
                    float(self.burst),
                    bucket.tokens + elapsed * self.refill_per_second,
                )
                bucket.last_refill = now
                bucket.last_seen = now

            if bucket.active >= self.per_ip_concurrent_cap:
                self._record_block_locked(ip, "per_ip_concurrent_cap")
                return self._reject(f"per-IP concurrent cap reached for {ip}")

            if bucket.tokens < 1.0:
                needed = 1.0 - bucket.tokens
                retry_after = needed / self.refill_per_second
                self._record_block_locked(ip, "rate_limit")
                bucket.total_blocked += 1
                return self._reject(
                    f"rate limit exceeded for {ip}",
                    retry_after=retry_after,
                )
            # Reserve one token now; acquire() will increment ``active``.
            bucket.tokens -= 1.0
            return RateLimitDecision(True)

    async def acquire(self, ip: str) -> None:
        """Record that a connection slot is now in use for ``ip``."""
        if not self.enabled:
            return
        async with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is None:
                bucket = _Bucket(
                    tokens=float(self.burst) - 1.0,
                    last_refill=time.monotonic(),
                    last_seen=time.monotonic(),
                )
                self._buckets[ip] = bucket
            bucket.active += 1
            bucket.last_seen = time.monotonic()
            self._global_active += 1

    async def release(self, ip: str) -> None:
        """Release a previously-acquired slot for ``ip``."""
        if not self.enabled:
            return
        async with self._lock:
            bucket = self._buckets.get(ip)
            if bucket is not None and bucket.active > 0:
                bucket.active -= 1
                bucket.last_seen = time.monotonic()
            if self._global_active > 0:
                self._global_active -= 1

    async def stats(self) -> dict[str, Any]:
        """Return a snapshot of current limiter state."""
        async with self._lock:
            top_blocked = sorted(self._blocked_ips.items(), key=lambda kv: kv[1], reverse=True)[:20]
            return {
                "enabled": self.enabled,
                "global_active": self._global_active,
                "global_cap": self.global_concurrent_cap,
                "per_ip_cap": self.per_ip_concurrent_cap,
                "max_per_minute": self.max_per_minute,
                "burst": self.burst,
                "tracked_ips": len(self._buckets),
                "top_blocked_ips": top_blocked,
                "total_blocks": sum(self._blocked_ips.values()),
                "tarpit_enabled": self.tarpit_on_limit,
            }

    async def reset(self) -> None:
        """Clear all state — intended for tests."""
        async with self._lock:
            self._buckets.clear()
            self._blocked_ips.clear()
            self._global_active = 0

    async def force_cleanup(self) -> int:
        """Run stale-entry cleanup immediately. Returns count pruned."""
        async with self._lock:
            return self._prune_locked(time.monotonic(), force=True)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _prune_locked(self, now: float, *, force: bool = False) -> int:
        """Drop buckets idle beyond ``stale_after_seconds``.

        Runs opportunistically on every ``check`` call; ``force=True``
        bypasses the active-connection guard (tests use this path).
        """
        cutoff = now - self.stale_after_seconds
        to_delete = [
            ip
            for ip, bucket in self._buckets.items()
            if bucket.last_seen < cutoff and (force or bucket.active == 0)
        ]
        for ip in to_delete:
            del self._buckets[ip]
            self._blocked_ips.pop(ip, None)
        if to_delete:
            logger.debug("RateLimiter pruned %d stale IP entries", len(to_delete))
        return len(to_delete)

    def _record_block_locked(self, ip: str, reason: str) -> None:
        """Bookkeeping for dashboard + logs; emission is up to the caller."""
        self._blocked_ips[ip] = self._blocked_ips.get(ip, 0) + 1
        logger.info("RateLimiter blocked %s (%s)", ip, reason)

    def _reject(self, reason: str, retry_after: float = 0.0) -> RateLimitDecision:
        """Build a rejection decision, honoring the tarpit setting."""
        tarpit = self.tarpit_seconds if self.tarpit_on_limit else 0.0
        return RateLimitDecision(
            False,
            reason=reason,
            retry_after=retry_after,
            tarpit_seconds=tarpit,
        )
