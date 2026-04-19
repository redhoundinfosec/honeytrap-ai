"""Smart log manager.

Responsibilities:

* Writing events as JSON lines to ``events/events_YYYY-MM-DD.jsonl``.
* Writing per-session transcripts to ``sessions/<session>.jsonl``.
* Rotating and compressing old logs in the background.
* Enforcing a total size cap (``max_size_mb``) with tiered pruning.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from honeytrap.logging.models import Event

logger = logging.getLogger(__name__)

_TIERS: dict[str, dict[str, Any]] = {
    "critical": {"compress_after_hours": None, "delete_after_days": None},
    "sessions": {"compress_after_hours": 24, "delete_after_days": 30},
    "events": {"compress_after_hours": 6, "delete_after_days": 14},
    "scans": {"compress_after_hours": 1, "delete_after_days": 7},
}


class LogManager:
    """Async, size-bounded JSONL log manager."""

    def __init__(
        self,
        base_dir: Path,
        *,
        max_size_mb: int = 500,
        retention_days: int = 30,
        interval_seconds: float = 300.0,
    ) -> None:
        """Initialize the log manager with rotation and size policies.

        Args:
            base_dir: Directory for log files.
            max_size_mb: Maximum total log storage in megabytes.
            retention_days: Number of days to retain uncompressed logs.
            interval_seconds: How often to check and enforce size limits.
        """
        self.base_dir = Path(base_dir)
        self.events_dir = self.base_dir / "events"
        self.sessions_dir = self.base_dir / "sessions"
        self.scans_dir = self.base_dir / "scans"
        for d in (self.events_dir, self.sessions_dir, self.scans_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.max_size_mb = max_size_mb
        self.retention_days = retention_days
        self.interval_seconds = interval_seconds
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._buffer: list[Event] = []

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    async def write_event(self, event: Event) -> None:
        """Append an event to the daily event log and, if present, its session."""
        async with self._lock:
            try:
                daily_path = self._daily_events_path(event.timestamp)
                daily_path.parent.mkdir(parents=True, exist_ok=True)
                line = json.dumps(event.to_dict(), ensure_ascii=False)
                with daily_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                if event.session_id:
                    sess_path = self.sessions_dir / f"{event.session_id}.jsonl"
                    with sess_path.open("a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
            except OSError as exc:
                logger.warning("Falling back to in-memory buffer: %s", exc)
                self._buffer.append(event)
                # Cap buffer so we don't OOM.
                if len(self._buffer) > 5000:
                    self._buffer = self._buffer[-5000:]

    def _daily_events_path(self, ts: datetime) -> Path:
        """Return the JSONL path for a particular UTC date."""
        day = ts.astimezone(timezone.utc).strftime("%Y-%m-%d")
        return self.events_dir / f"events_{day}.jsonl"

    # ------------------------------------------------------------------
    # Background monitoring
    # ------------------------------------------------------------------
    async def monitor(self) -> None:
        """Background task: enforce size and retention policies."""
        while not self._stop.is_set():
            try:
                await self.enforce_limits()
            except Exception as exc:  # noqa: BLE001
                logger.exception("Log manager enforcement failed: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                continue

    async def close(self) -> None:
        """Stop the monitor loop."""
        self._stop.set()

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------
    async def enforce_limits(self) -> None:
        """Compress or delete logs to stay under the configured size cap."""
        total_bytes = self._total_size()
        threshold = self.max_size_mb * 1024 * 1024

        # Age-based compression/deletion per tier.
        for tier_name, rules in _TIERS.items():
            directory = self._tier_dir(tier_name)
            if directory is None:
                continue
            compress_hours = rules["compress_after_hours"]
            delete_days = rules["delete_after_days"]
            if compress_hours is not None:
                self._compress_old(directory, hours=compress_hours)
            if delete_days is not None:
                effective_days = min(delete_days, self.retention_days)
                self._delete_older_than(directory, days=effective_days)

        # Size-based pruning if still over the cap.
        total_bytes = self._total_size()
        if total_bytes > threshold:
            logger.info(
                "Logs exceed cap (%.1fMB > %dMB); pruning",
                total_bytes / 1024 / 1024,
                self.max_size_mb,
            )
            for tier in ("scans", "events", "sessions"):
                directory = self._tier_dir(tier)
                if directory is None:
                    continue
                self._remove_oldest(directory, until_bytes=int(threshold * 0.8))
                if self._total_size() <= threshold * 0.8:
                    break

    def _tier_dir(self, tier: str) -> Path | None:
        return {
            "sessions": self.sessions_dir,
            "events": self.events_dir,
            "scans": self.scans_dir,
            "critical": None,
        }.get(tier)

    def _total_size(self) -> int:
        """Return total bytes across managed directories."""
        total = 0
        for directory in (self.events_dir, self.sessions_dir, self.scans_dir):
            if not directory.exists():
                continue
            for p in directory.rglob("*"):
                try:
                    if p.is_file():
                        total += p.stat().st_size
                except OSError:
                    continue
        return total

    def _compress_old(self, directory: Path, *, hours: int) -> None:
        """GZIP files older than ``hours`` that aren't already compressed."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        for path in directory.glob("*.jsonl"):
            try:
                mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            except OSError:
                continue
            if mtime >= cutoff:
                continue
            gz_path = path.with_suffix(path.suffix + ".gz")
            try:
                with path.open("rb") as src, gzip.open(gz_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                path.unlink()
                logger.debug("Compressed %s -> %s", path.name, gz_path.name)
            except OSError as exc:
                logger.warning("Compression failed for %s: %s", path, exc)

    def _delete_older_than(self, directory: Path, *, days: int) -> None:
        """Delete any file older than ``days`` days."""
        if days <= 0:
            return
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        for path in directory.iterdir():
            try:
                mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            except OSError:
                continue
            if mtime < cutoff and path.is_file():
                try:
                    path.unlink()
                except OSError as exc:
                    logger.warning("Delete failed for %s: %s", path, exc)

    def _remove_oldest(self, directory: Path, *, until_bytes: int) -> None:
        """Remove oldest files in ``directory`` until total size is under cap."""
        files = [p for p in directory.iterdir() if p.is_file()]
        files.sort(key=lambda p: p.stat().st_mtime)
        for path in files:
            if self._total_size() <= until_bytes:
                return
            try:
                path.unlink()
            except OSError as exc:
                logger.warning("Could not remove %s: %s", path, exc)
