"""Abstract sink interface used by the shared delivery pipeline.

A :class:`Sink` is the destination for a batch of events. The pipeline
calls :meth:`send_batch` from a worker coroutine; sinks are expected
to handle their own HTTP transport (with timeouts) and to surface
failure as a raised exception so the retry / circuit-breaker layer
can react.

Sinks are deliberately thin: they should not own queues, batchers,
or retry state. Those concerns belong to the pipeline so every sink
benefits from a single, well-tested implementation.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any


@dataclass
class SinkHealth:
    """Snapshot of one sink's runtime state."""

    name: str
    state: str  # closed|half_open|open
    last_error: str | None
    queue_depth: int
    dropped_total: int
    sent_total: int


class Sink(abc.ABC):
    """Abstract base class every sink must subclass."""

    name: str

    def __init__(self, name: str) -> None:
        """Set the sink's identifying ``name``."""
        self.name = name

    @abc.abstractmethod
    async def send_batch(self, batch: list[dict[str, Any]]) -> None:
        """Deliver ``batch`` to the sink. Raise on failure."""

    async def health(self) -> SinkHealth:
        """Return a default-shaped health snapshot. Subclasses may extend."""
        return SinkHealth(
            name=self.name,
            state="closed",
            last_error=None,
            queue_depth=0,
            dropped_total=0,
            sent_total=0,
        )

    async def shutdown(self) -> None:
        """Release any held resources. Default is a no-op."""
        return None
