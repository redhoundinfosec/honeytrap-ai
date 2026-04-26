"""Backpressure-aware async delivery pipeline.

Each :class:`LogPipeline` owns:

* an :class:`asyncio.Queue` of capped depth -- events arrive via
  :meth:`submit` (sync, no awaiting) so the honeypot's hot paths never
  block waiting on a SIEM.
* one worker coroutine per :class:`~honeytrap.sinks.sink_base.Sink`
  that dequeues, batches, and ships through the retry / circuit-breaker
  layer.
* a metrics adapter so every drop, flush, latency, and circuit
  transition is visible to ops without coupling to a specific registry.

Memory is bounded: when the queue is full, the configured overflow
policy decides whether to drop the oldest event, the new event, or
block the caller.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from honeytrap.sinks.batcher import Batcher
from honeytrap.sinks.retry import (
    BreakerState,
    CircuitBreaker,
    RetryPolicy,
    execute_with_retry,
)
from honeytrap.sinks.sink_base import Sink, SinkHealth

logger = logging.getLogger(__name__)


class OverflowPolicy(str, Enum):
    """How the pipeline handles a full queue."""

    DROP_OLDEST = "drop_oldest"
    DROP_NEW = "drop_new"
    BLOCK = "block"


class MetricsAdapter(Protocol):
    """Subset of the metrics registry the pipeline calls."""

    def inc_counter(
        self,
        name: str,
        value: float = 1.0,
        labels: dict[str, str] | None = None,
    ) -> None: ...

    def set_gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None: ...

    def observe_histogram(
        self,
        name: str,
        value: float,
        buckets: tuple[float, ...] | None = None,
    ) -> None: ...


@dataclass
class _PerSinkStats:
    """Internal counters tracked per attached sink."""

    dropped_total: int = 0
    sent_total: int = 0
    last_error: str | None = None
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    batcher: Batcher = field(default_factory=Batcher)
    queue: asyncio.Queue[dict[str, Any]] | None = None


class LogPipeline:
    """Bounded, backpressure-aware fan-out to one or more sinks."""

    def __init__(
        self,
        *,
        capacity: int = 10_000,
        overflow: OverflowPolicy | str = OverflowPolicy.DROP_OLDEST,
        retry_policy: RetryPolicy | None = None,
        metrics: MetricsAdapter | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create an empty pipeline; sinks are attached via :meth:`add_sink`."""
        self.capacity = max(1, int(capacity))
        self.overflow = overflow if isinstance(overflow, OverflowPolicy) else OverflowPolicy(overflow)
        self.retry_policy = retry_policy or RetryPolicy()
        self.metrics = metrics
        self._clock = clock
        self._sinks: dict[str, Sink] = {}
        self._stats: dict[str, _PerSinkStats] = {}
        self._workers: dict[str, asyncio.Task[None]] = {}
        self._stop = False
        self._register_metrics()

    # -- lifecycle ----------------------------------------------------------
    def add_sink(
        self,
        sink: Sink,
        *,
        batch_size: int = 500,
        batch_window_seconds: float = 1.0,
    ) -> None:
        """Register ``sink`` with its own queue, batcher, and breaker."""
        if sink.name in self._sinks:
            raise ValueError(f"sink {sink.name!r} already registered")
        stats = _PerSinkStats(
            batcher=Batcher(max_size=batch_size, window_seconds=batch_window_seconds),
            queue=asyncio.Queue(maxsize=self.capacity),
        )
        self._sinks[sink.name] = sink
        self._stats[sink.name] = stats

    async def start(self) -> None:
        """Spawn one worker coroutine per attached sink."""
        for name, sink in self._sinks.items():
            if name in self._workers and not self._workers[name].done():
                continue
            self._workers[name] = asyncio.create_task(
                self._worker(name, sink), name=f"sink-worker-{name}"
            )

    async def shutdown(self, *, timeout: float = 5.0) -> None:
        """Drain queues, run final flushes, and close every sink."""
        self._stop = True
        for name in list(self._workers.keys()):
            stats = self._stats[name]
            assert stats.queue is not None
            with contextlib.suppress(asyncio.QueueFull):
                stats.queue.put_nowait({"_shutdown": True})
        for name, task in list(self._workers.items()):
            try:
                await asyncio.wait_for(task, timeout=timeout)
            except asyncio.TimeoutError:
                task.cancel()
            except Exception:  # noqa: BLE001 -- we still want to continue shutdown
                logger.exception("worker for sink %r raised during shutdown", name)
        for sink in self._sinks.values():
            try:
                await sink.shutdown()
            except Exception:  # noqa: BLE001
                logger.exception("sink %r shutdown raised", sink.name)

    # -- ingestion ----------------------------------------------------------
    def submit(self, event: dict[str, Any]) -> None:
        """Hand an event to every sink. Never blocks the caller."""
        for name, stats in self._stats.items():
            queue = stats.queue
            assert queue is not None
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                self._handle_overflow(name, queue, event)
            self._update_queue_gauge(name, queue)

    def _handle_overflow(
        self,
        name: str,
        queue: asyncio.Queue[dict[str, Any]],
        event: dict[str, Any],
    ) -> None:
        stats = self._stats[name]
        if self.overflow is OverflowPolicy.DROP_NEW:
            stats.dropped_total += 1
            self._inc_drop(name, "drop_new")
            return
        if self.overflow is OverflowPolicy.BLOCK:
            # Cooperative block -- give the caller back control but
            # account for the event so callers can detect saturation.
            stats.dropped_total += 1
            self._inc_drop(name, "block_dropped")
            return
        # Default: drop oldest then enqueue the new event.
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        else:
            stats.dropped_total += 1
            self._inc_drop(name, "drop_oldest")
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            stats.dropped_total += 1
            self._inc_drop(name, "drop_oldest")

    # -- worker -------------------------------------------------------------
    async def _worker(self, name: str, sink: Sink) -> None:
        stats = self._stats[name]
        queue = stats.queue
        assert queue is not None
        while not self._stop or not queue.empty():
            timeout = max(0.05, stats.batcher.window_seconds)
            try:
                event = await asyncio.wait_for(queue.get(), timeout=timeout)
            except asyncio.TimeoutError:
                if stats.batcher.has_data():
                    await self._flush(name, sink, stats.batcher.flush())
                continue
            if event.get("_shutdown"):
                break
            should_flush = stats.batcher.add(event)
            self._update_queue_gauge(name, queue)
            if should_flush:
                await self._flush(name, sink, stats.batcher.flush())
        if stats.batcher.has_data():
            await self._flush(name, sink, stats.batcher.flush())

    async def _flush(self, name: str, sink: Sink, batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        stats = self._stats[name]
        started = self._clock()

        async def _do() -> None:
            await sink.send_batch(batch)

        try:
            await execute_with_retry(_do, policy=self.retry_policy, breaker=stats.breaker)
            stats.sent_total += len(batch)
            stats.last_error = None
            self._inc_sent(name, len(batch))
        except Exception as exc:  # noqa: BLE001 -- account and continue
            stats.dropped_total += len(batch)
            stats.last_error = str(exc)
            self._inc_drop(name, "send_failed", count=len(batch))
            logger.warning("sink %r dropped %d events: %s", name, len(batch), exc)
        finally:
            self._observe_latency(name, max(0.0, self._clock() - started))
            self._update_breaker_gauge(name, stats.breaker.state)

    # -- introspection ------------------------------------------------------
    async def health(self) -> list[SinkHealth]:
        """Return per-sink health snapshots."""
        out: list[SinkHealth] = []
        for name, sink in self._sinks.items():
            stats = self._stats[name]
            queue = stats.queue
            depth = queue.qsize() if queue is not None else 0
            out.append(
                SinkHealth(
                    name=sink.name,
                    state=stats.breaker.state.value,
                    last_error=stats.last_error,
                    queue_depth=depth,
                    dropped_total=stats.dropped_total,
                    sent_total=stats.sent_total,
                )
            )
        return out

    async def flush_now(self, sink_name: str) -> int:
        """Force a flush of any buffered events for ``sink_name``."""
        if sink_name not in self._sinks:
            raise KeyError(sink_name)
        stats = self._stats[sink_name]
        sink = self._sinks[sink_name]
        if not stats.batcher.has_data():
            return 0
        batch = stats.batcher.flush()
        await self._flush(sink_name, sink, batch)
        return len(batch)

    def queue_depth(self, sink_name: str) -> int:
        """Return the current queue depth for one sink."""
        stats = self._stats[sink_name]
        return stats.queue.qsize() if stats.queue is not None else 0

    # -- metrics ------------------------------------------------------------
    def _register_metrics(self) -> None:
        if self.metrics is None:
            return
        # MetricsRegistry.register exists on the production adapter;
        # tests using a simpler adapter just skip this block.
        register = getattr(self.metrics, "register", None)
        if register is None:
            return
        register(
            "honeytrap_sink_dropped_total",
            "Events dropped before successful delivery, labelled by sink and reason.",
            "counter",
        )
        register(
            "honeytrap_sink_events_total",
            "Events successfully delivered, labelled by sink.",
            "counter",
        )
        register(
            "honeytrap_sink_queue_depth",
            "Current queue depth per sink.",
            "gauge",
        )
        register(
            "honeytrap_sink_circuit_state",
            "Circuit breaker state per sink (0=closed,1=half_open,2=open).",
            "gauge",
        )
        register(
            "honeytrap_sink_send_duration_seconds",
            "Time spent in Sink.send_batch including retries.",
            "histogram",
        )

    def _inc_drop(self, name: str, reason: str, *, count: int = 1) -> None:
        if self.metrics is None:
            return
        self.metrics.inc_counter(
            "honeytrap_sink_dropped_total",
            value=float(count),
            labels={"sink": name, "reason": reason},
        )

    def _inc_sent(self, name: str, count: int) -> None:
        if self.metrics is None:
            return
        self.metrics.inc_counter(
            "honeytrap_sink_events_total",
            value=float(count),
            labels={"sink": name},
        )

    def _update_queue_gauge(self, name: str, queue: asyncio.Queue[Any]) -> None:
        if self.metrics is None:
            return
        self.metrics.set_gauge(
            "honeytrap_sink_queue_depth", float(queue.qsize()), labels={"sink": name}
        )

    def _update_breaker_gauge(self, name: str, state: BreakerState) -> None:
        if self.metrics is None:
            return
        value = {BreakerState.CLOSED: 0.0, BreakerState.HALF_OPEN: 1.0, BreakerState.OPEN: 2.0}[state]
        self.metrics.set_gauge("honeytrap_sink_circuit_state", value, labels={"sink": name})

    def _observe_latency(self, name: str, seconds: float) -> None:
        if self.metrics is None:
            return
        observe = getattr(self.metrics, "observe_histogram", None)
        if observe is None:
            return
        observe("honeytrap_sink_send_duration_seconds", seconds)
