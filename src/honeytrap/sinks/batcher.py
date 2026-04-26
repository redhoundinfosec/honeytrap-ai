"""Size + time-window batching helper used by the delivery pipeline.

The batcher accumulates events until either ``max_size`` events have
been seen or ``window_seconds`` have elapsed since the first event in
the current batch. ``flush`` is idempotent and safe to call from
multiple coroutines.

We keep the implementation synchronous because the pipeline already
owns the asyncio queue; the batcher is just a small state machine
that the worker pokes between dequeue and ``Sink.send_batch``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Batcher:
    """In-memory batch accumulator with size + time triggers."""

    max_size: int = 500
    window_seconds: float = 1.0
    _buffer: list[dict[str, Any]] = field(default_factory=list)
    _opened_at: float = 0.0

    def add(self, event: dict[str, Any]) -> bool:
        """Add ``event`` and return True when the batch should flush."""
        if not self._buffer:
            self._opened_at = time.monotonic()
        self._buffer.append(event)
        return len(self._buffer) >= self.max_size

    def time_due(self) -> bool:
        """Return True when the batch is non-empty and past the window."""
        if not self._buffer:
            return False
        return (time.monotonic() - self._opened_at) >= self.window_seconds

    def has_data(self) -> bool:
        """Return True if any events are buffered."""
        return bool(self._buffer)

    def flush(self) -> list[dict[str, Any]]:
        """Take the buffered batch and reset internal state."""
        out = self._buffer
        self._buffer = []
        self._opened_at = 0.0
        return out

    def __len__(self) -> int:
        """Number of events currently buffered."""
        return len(self._buffer)
