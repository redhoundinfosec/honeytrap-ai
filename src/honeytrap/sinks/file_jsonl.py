"""Local NDJSON file sink with daily rotation.

The sink writes one event per line into ``<root>/honeytrap-YYYY-MM-DD.jsonl``.
File handles are opened for the lifetime of one local date, then
rolled when the next batch lands in a new day. Writes are guarded by
an :class:`asyncio.Lock` so concurrent workers cannot interleave
partial lines.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from honeytrap.sinks.ecs import event_to_ecs
from honeytrap.sinks.sink_base import Sink


@dataclass
class FileJsonlConfig:
    """Configuration for :class:`FileJsonlSink`."""

    path: str | Path
    prefix: str = "honeytrap"
    use_ecs: bool = True


class FileJsonlSink(Sink):
    """NDJSON sink with daily rotation."""

    def __init__(self, config: FileJsonlConfig, *, name: str = "file_jsonl") -> None:
        """Materialise the output directory and prepare for first write."""
        super().__init__(name=name)
        self.config = config
        self._root = Path(config.path)
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._current_day: str = ""
        self._current_path: Path | None = None

    def _path_for(self, when: datetime) -> Path:
        """Return the rotated file path for the day of ``when``."""
        return self._root / f"{self.config.prefix}-{when.strftime('%Y-%m-%d')}.jsonl"

    async def send_batch(self, batch: list[dict[str, Any]]) -> None:
        """Append every event in ``batch`` to today's file."""
        if not batch:
            return
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        target = self._path_for(now)
        async with self._lock:
            if day != self._current_day:
                self._current_day = day
                self._current_path = target
            assert self._current_path is not None
            await asyncio.to_thread(self._append, self._current_path, batch)

    def _append(self, path: Path, batch: list[dict[str, Any]]) -> None:
        """Synchronous helper: serialize ``batch`` line-by-line."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("ab") as fh:
            for event in batch:
                payload = event_to_ecs(event) if self.config.use_ecs else event
                line = json.dumps(payload, separators=(",", ":"), sort_keys=True)
                fh.write(line.encode("utf-8"))
                fh.write(b"\n")

    async def shutdown(self) -> None:
        """Reset rotation state. There is no buffered output to flush."""
        async with self._lock:
            self._current_day = ""
            self._current_path = None
