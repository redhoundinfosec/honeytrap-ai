"""Tests for the shared delivery pipeline (queue + retry + breaker)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from honeytrap.sinks import (
    BreakerState,
    CircuitBreaker,
    LogPipeline,
    OverflowPolicy,
    RetryPolicy,
    Sink,
    execute_with_retry,
)
from honeytrap.sinks.batcher import Batcher


class _RecordingSink(Sink):
    """Sink that records every batch it receives."""

    def __init__(self, name: str = "record", *, fail_count: int = 0) -> None:
        super().__init__(name=name)
        self.received: list[list[dict[str, Any]]] = []
        self.fail_count = fail_count
        self.calls = 0

    async def send_batch(self, batch: list[dict[str, Any]]) -> None:
        self.calls += 1
        if self.calls <= self.fail_count:
            raise RuntimeError("synthetic failure")
        self.received.append(list(batch))


class _FakeMetrics:
    """Minimal metrics adapter capturing every call."""

    def __init__(self) -> None:
        self.counters: list[tuple[str, float, dict[str, str] | None]] = []
        self.gauges: list[tuple[str, float, dict[str, str] | None]] = []
        self.histos: list[tuple[str, float]] = []

    def register(self, *_a: Any, **_k: Any) -> None:
        return None

    def inc_counter(self, name: str, value: float = 1.0, labels: dict[str, str] | None = None) -> None:
        self.counters.append((name, value, dict(labels) if labels else None))

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        self.gauges.append((name, value, dict(labels) if labels else None))

    def observe_histogram(self, name: str, value: float, buckets: tuple[float, ...] | None = None) -> None:
        self.histos.append((name, value))


@pytest.mark.asyncio
async def test_batcher_size_and_window_triggers() -> None:
    b = Batcher(max_size=2, window_seconds=0.05)
    assert not b.add({"x": 1})
    assert b.add({"x": 2}) is True
    assert b.flush() == [{"x": 1}, {"x": 2}]
    b.add({"x": 3})
    await asyncio.sleep(0.06)
    assert b.time_due() is True


@pytest.mark.asyncio
async def test_pipeline_delivers_one_batch() -> None:
    sink = _RecordingSink()
    pipeline = LogPipeline(capacity=10)
    pipeline.add_sink(sink, batch_size=2, batch_window_seconds=0.05)
    await pipeline.start()
    try:
        pipeline.submit({"a": 1})
        pipeline.submit({"a": 2})
        for _ in range(20):
            if sink.received:
                break
            await asyncio.sleep(0.05)
    finally:
        await pipeline.shutdown(timeout=2.0)
    assert sink.received and sink.received[0][0] == {"a": 1}


@pytest.mark.asyncio
async def test_pipeline_drop_oldest_on_overflow() -> None:
    sink = _RecordingSink()
    metrics = _FakeMetrics()
    pipeline = LogPipeline(capacity=2, overflow=OverflowPolicy.DROP_OLDEST, metrics=metrics)
    pipeline.add_sink(sink, batch_size=10, batch_window_seconds=10)
    pipeline.submit({"a": 1})
    pipeline.submit({"a": 2})
    pipeline.submit({"a": 3})
    drop_counters = [c for c in metrics.counters if c[0] == "honeytrap_sink_dropped_total"]
    assert any(c[2] and c[2].get("reason") == "drop_oldest" for c in drop_counters)


@pytest.mark.asyncio
async def test_pipeline_drop_new_increments_metric() -> None:
    sink = _RecordingSink()
    metrics = _FakeMetrics()
    pipeline = LogPipeline(capacity=1, overflow=OverflowPolicy.DROP_NEW, metrics=metrics)
    pipeline.add_sink(sink, batch_size=10, batch_window_seconds=10)
    pipeline.submit({"a": 1})
    pipeline.submit({"a": 2})
    drops = [c for c in metrics.counters if c[0] == "honeytrap_sink_dropped_total"]
    assert any(c[2] and c[2].get("reason") == "drop_new" for c in drops)


@pytest.mark.asyncio
async def test_retry_policy_succeeds_after_transient_failure() -> None:
    sink = _RecordingSink(fail_count=2)
    policy = RetryPolicy(base_seconds=0.0, max_seconds=0.0, max_attempts=5, jitter=0)
    breaker = CircuitBreaker(failure_threshold=10)

    async def _do() -> None:
        await sink.send_batch([{"x": 1}])

    await execute_with_retry(_do, policy=policy, breaker=breaker, sleep=lambda _x: asyncio.sleep(0))
    assert sink.calls == 3
    assert breaker.state is BreakerState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_opens_after_threshold() -> None:
    sink = _RecordingSink(fail_count=100)
    policy = RetryPolicy(base_seconds=0.0, max_seconds=0.0, max_attempts=1, jitter=0)
    breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=0.05)
    for _ in range(3):
        with pytest.raises(RuntimeError):

            async def _do() -> None:
                await sink.send_batch([{"x": 1}])

            await execute_with_retry(_do, policy=policy, breaker=breaker, sleep=lambda _x: asyncio.sleep(0))
    assert breaker.state is BreakerState.OPEN
    with pytest.raises(RuntimeError):

        async def _do2() -> None:
            await sink.send_batch([{"x": 1}])

        await execute_with_retry(_do2, policy=policy, breaker=breaker, sleep=lambda _x: asyncio.sleep(0))


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_after_cooldown() -> None:
    breaker = CircuitBreaker(failure_threshold=1, cooldown_seconds=0)
    breaker.record_failure("boom")
    assert breaker.state is BreakerState.OPEN
    assert breaker.allow() is True
    assert breaker.state is BreakerState.HALF_OPEN
    breaker.record_success()
    assert breaker.state is BreakerState.CLOSED


@pytest.mark.asyncio
async def test_pipeline_shutdown_drains_buffered_events() -> None:
    sink = _RecordingSink()
    pipeline = LogPipeline(capacity=10)
    pipeline.add_sink(sink, batch_size=100, batch_window_seconds=10)
    await pipeline.start()
    pipeline.submit({"a": 1})
    pipeline.submit({"a": 2})
    await pipeline.shutdown(timeout=2.0)
    assert sink.received and sum(len(b) for b in sink.received) == 2


@pytest.mark.asyncio
async def test_pipeline_health_reports_state() -> None:
    sink = _RecordingSink()
    pipeline = LogPipeline(capacity=4)
    pipeline.add_sink(sink)
    health = await pipeline.health()
    assert len(health) == 1
    assert health[0].name == sink.name
    assert health[0].state == "closed"


@pytest.mark.asyncio
async def test_pipeline_flush_now_returns_count() -> None:
    sink = _RecordingSink()
    pipeline = LogPipeline(capacity=4)
    pipeline.add_sink(sink, batch_size=10, batch_window_seconds=10)
    pipeline.submit({"a": 1})
    pipeline.submit({"a": 2})
    # No worker started: nothing is in the batcher yet, only in the queue.
    assert await pipeline.flush_now(sink.name) == 0
    # Manually populate the batcher to exercise the flush path.
    pipeline._stats[sink.name].batcher.add({"forced": 1})  # type: ignore[attr-defined]
    assert await pipeline.flush_now(sink.name) == 1


@pytest.mark.asyncio
async def test_retry_delay_is_bounded_and_non_negative() -> None:
    policy = RetryPolicy(base_seconds=0.5, max_seconds=2.0, jitter=0.5)
    delays = [policy.delay_for(i) for i in range(0, 8)]
    assert all(d >= 0.0 for d in delays)
    assert all(d <= 2.0 * (1 + 0.5) for d in delays)
