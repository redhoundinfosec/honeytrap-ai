"""Throughput benchmarks for the in-process event bus.

Honeytrap fans :class:`Event` records out to subscribers via bounded
``asyncio.Queue`` instances. These benchmarks measure publish throughput
with one and four subscribers at 1k and 10k event volumes so we can
catch regressions in queue fan-out cost.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from honeytrap.logging.models import Event

pytestmark = pytest.mark.benchmark


def _make_event(i: int) -> Event:
    """Construct a single representative :class:`Event` for fan-out tests."""
    return Event(
        protocol="ssh",
        event_type="auth_attempt",
        remote_ip="192.0.2.1",
        remote_port=12345,
        session_id=f"session-{i}",
        username="root",
        password="toor",
        message=f"benchmark event {i}",
        timestamp=datetime.now(timezone.utc),
    )


async def _fan_out(events: list[Event], subscriber_count: int) -> int:
    """Fan ``events`` out to ``subscriber_count`` queues and drain them.

    Returns the total events received across all subscribers.
    """
    queues: list[asyncio.Queue[Event]] = [
        asyncio.Queue(maxsize=len(events) + 1) for _ in range(subscriber_count)
    ]
    for event in events:
        for q in queues:
            q.put_nowait(event)
    received = 0
    for q in queues:
        while not q.empty():
            q.get_nowait()
            received += 1
    return received


def _run_fan_out(event_count: int, subscriber_count: int) -> int:
    """Build ``event_count`` events and synchronously drive ``_fan_out``."""
    events = [_make_event(i) for i in range(event_count)]
    return asyncio.new_event_loop().run_until_complete(_fan_out(events, subscriber_count))


def test_bench_event_bus_1k_one_subscriber(benchmark) -> None:
    """1,000 events -> 1 subscriber pure put_nowait/get_nowait throughput."""
    received = benchmark(_run_fan_out, 1000, 1)
    assert received == 1000


def test_bench_event_bus_1k_four_subscribers(benchmark) -> None:
    """1,000 events -> 4 subscribers fan-out throughput."""
    received = benchmark(_run_fan_out, 1000, 4)
    assert received == 4000


def test_bench_event_bus_10k_one_subscriber(benchmark) -> None:
    """10,000 events -> 1 subscriber sustained throughput."""
    received = benchmark(_run_fan_out, 10_000, 1)
    assert received == 10_000


def test_bench_event_bus_10k_four_subscribers(benchmark) -> None:
    """10,000 events -> 4 subscribers fan-out under load."""
    received = benchmark(_run_fan_out, 10_000, 4)
    assert received == 40_000


@pytest.mark.slow
def test_bench_event_bus_100k_one_subscriber(benchmark) -> None:
    """Optional 100,000-event sustained throughput test (slow marker)."""
    received = benchmark(_run_fan_out, 100_000, 1)
    assert received == 100_000
