"""Resource guardian — runtime self-defense against DoS.

This module runs as a background asyncio task and periodically checks
key pressure points: total concurrent connections, process memory, log
directory size. When thresholds are crossed the guardian flips a flag
(``should_refuse``) that the base protocol handler consults before
accepting new connections.

The guardian does *not* attempt to unwind existing sessions — ripping
connections mid-flight tends to destabilize asyncio handlers and loses
intelligence we could have captured. The invariant is "don't get
bigger," not "shrink."

Memory inspection tries :mod:`psutil` first and falls back to reading
``/proc/self/status`` on Linux; on other platforms without psutil the
memory check is a no-op and we rely on the connection cap alone.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from honeytrap.core.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


DEFAULT_MEMORY_LIMIT_MB = 256
DEFAULT_CHECK_INTERVAL = 5.0
DEFAULT_LOG_DIR_WARN_MB = 2048


@dataclass
class GuardianStats:
    """Snapshot of current guardian state."""

    memory_mb: float = 0.0
    memory_limit_mb: float = 0.0
    connections: int = 0
    connections_cap: int = 0
    log_dir_bytes: int = 0
    log_dir_warn_bytes: int = 0
    should_refuse: bool = False
    refusal_reason: str = ""
    last_check: float = 0.0
    checks_run: int = 0
    refusals_triggered: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)


class ResourceGuardian:
    """Background monitor that gates new connections under load."""

    def __init__(
        self,
        *,
        log_directory: str | Path,
        memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
        check_interval_seconds: float = DEFAULT_CHECK_INTERVAL,
        log_dir_warn_mb: int = DEFAULT_LOG_DIR_WARN_MB,
        rate_limiter: RateLimiter | None = None,
        enabled: bool = True,
    ) -> None:
        """Configure the guardian.

        Args:
            log_directory: Directory to size-check.
            memory_limit_mb: RSS threshold above which we refuse.
            check_interval_seconds: Sleep between checks.
            log_dir_warn_mb: Emit a warning above this log-dir size.
            rate_limiter: Shared limiter; used to read current connection
                counts in a single source-of-truth way.
            enabled: Global on/off.
        """
        self.enabled = enabled
        self.log_directory = Path(log_directory)
        self.memory_limit_mb = memory_limit_mb
        self.check_interval = max(1.0, check_interval_seconds)
        self.log_dir_warn_bytes = log_dir_warn_mb * 1024 * 1024
        self.rate_limiter = rate_limiter

        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()
        self._stats = GuardianStats(
            memory_limit_mb=float(memory_limit_mb),
            log_dir_warn_bytes=self.log_dir_warn_bytes,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Spin up the background monitor task."""
        if not self.enabled:
            logger.debug("ResourceGuardian disabled by config")
            return
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="resource-guardian")
        logger.info(
            "ResourceGuardian started (mem=%dMB, interval=%.1fs)",
            self.memory_limit_mb,
            self.check_interval,
        )

    async def stop(self) -> None:
        """Stop the background monitor task."""
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def should_accept_connection(self) -> tuple[bool, str]:
        """Gate check called by handlers on every new connection.

        Returns a ``(allow, reason)`` tuple. Fast path returns ``(True, "")``
        without taking the lock so the hot path stays cheap.
        """
        if not self.enabled:
            return True, ""
        if self._stats.should_refuse:
            return False, self._stats.refusal_reason or "resource pressure"
        return True, ""

    async def stats(self) -> dict[str, Any]:
        """Return a snapshot of current guardian state."""
        async with self._lock:
            return {
                "enabled": self.enabled,
                "memory_mb": round(self._stats.memory_mb, 1),
                "memory_limit_mb": self._stats.memory_limit_mb,
                "connections": self._stats.connections,
                "connections_cap": self._stats.connections_cap,
                "log_dir_bytes": self._stats.log_dir_bytes,
                "log_dir_warn_bytes": self._stats.log_dir_warn_bytes,
                "should_refuse": self._stats.should_refuse,
                "refusal_reason": self._stats.refusal_reason,
                "last_check": self._stats.last_check,
                "checks_run": self._stats.checks_run,
                "refusals_triggered": self._stats.refusals_triggered,
            }

    async def check_once(self) -> GuardianStats:
        """Perform a single resource sweep.

        Exposed primarily for tests — the background task calls the same
        private helper. We update ``_stats`` atomically under the lock so
        readers see a consistent snapshot.
        """
        memory_mb = _read_memory_mb()
        log_bytes = _safe_dir_size(self.log_directory)
        connections = 0
        conn_cap = 0
        if self.rate_limiter is not None:
            # Access private members directly — avoiding another lock
            # round-trip during the hot-path check is worth the small
            # encapsulation break here.
            connections = self.rate_limiter._global_active
            conn_cap = self.rate_limiter.global_concurrent_cap

        refuse = False
        reason = ""
        if memory_mb > 0 and memory_mb >= self.memory_limit_mb:
            refuse = True
            reason = f"memory {memory_mb:.0f}MB >= limit {self.memory_limit_mb}MB"
        elif conn_cap and connections >= conn_cap:
            refuse = True
            reason = f"connections {connections} >= cap {conn_cap}"

        async with self._lock:
            self._stats.memory_mb = memory_mb
            self._stats.connections = connections
            self._stats.connections_cap = conn_cap
            self._stats.log_dir_bytes = log_bytes
            self._stats.last_check = time.time()
            self._stats.checks_run += 1
            if refuse and not self._stats.should_refuse:
                self._stats.refusals_triggered += 1
                logger.critical("ResourceGuardian REFUSING new connections: %s", reason)
            elif not refuse and self._stats.should_refuse:
                logger.warning("ResourceGuardian recovered — accepting new connections again")
            self._stats.should_refuse = refuse
            self._stats.refusal_reason = reason

            if log_bytes >= self.log_dir_warn_bytes:
                logger.warning(
                    "Log directory %s is %.1fMB — consider rotation",
                    self.log_directory,
                    log_bytes / (1024 * 1024),
                )
            return self._stats

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _run(self) -> None:
        """Monitor loop — wake at the configured interval and self-report."""
        while not self._stop.is_set():
            try:
                await self.check_once()
            except Exception as exc:  # noqa: BLE001 — never let the loop die
                logger.exception("Guardian check failed: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.check_interval)
            except asyncio.TimeoutError:
                continue


def _read_memory_mb() -> float:
    """Return current process RSS in megabytes, or 0 if unavailable."""
    try:
        import psutil  # type: ignore[import-not-found]

        return float(psutil.Process(os.getpid()).memory_info().rss) / (1024 * 1024)
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.debug("psutil RSS read failed: %s", exc)

    # /proc fallback — Linux-only but dependency-free.
    status = Path("/proc/self/status")
    if status.exists():
        try:
            for line in status.read_text().splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return float(parts[1]) / 1024.0
        except OSError:
            return 0.0
    return 0.0


def _safe_dir_size(path: Path) -> int:
    """Sum file sizes under ``path``; survive permission errors silently."""
    if not path.exists():
        return 0
    total = 0
    try:
        for entry in path.rglob("*"):
            try:
                if entry.is_file():
                    total += entry.stat().st_size
            except (OSError, FileNotFoundError):
                continue
    except OSError:
        return total
    return total
