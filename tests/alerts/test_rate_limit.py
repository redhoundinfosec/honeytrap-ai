"""Tests for the per-channel token-bucket rate limiter."""

from __future__ import annotations

import pytest

from honeytrap.alerts import Alert, AlertManager, AlertSeverity
from honeytrap.alerts.channels.base import AlertChannel, TokenBucket


class FakeClock:
    """Manual clock so tests can step time deterministically."""

    def __init__(self) -> None:
        """Start at t=0."""
        self.now = 0.0

    def __call__(self) -> float:
        """Return the current simulated time."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Move the clock forward by ``seconds``."""
        self.now += seconds


class RecorderChannel(AlertChannel):
    """Records every delivered alert (used to exercise the manager)."""

    def __init__(self, name: str = "recorder", rate: int = 60) -> None:
        """Store a ``sent`` list populated by ``_send``."""
        super().__init__(name, min_severity=AlertSeverity.INFO, rate_limit_per_minute=rate)
        self.sent: list[Alert] = []

    async def _send(self, alert: Alert) -> None:
        self.sent.append(alert)


async def test_token_bucket_allows_burst_up_to_capacity() -> None:
    """A freshly constructed bucket should accept its full capacity as a burst."""
    bucket = TokenBucket(rate_per_minute=60, capacity=5)
    for _ in range(5):
        assert await bucket.try_consume() is True


async def test_token_bucket_rejects_when_exceeded_and_metric_increments() -> None:
    """Once drained the bucket rejects and the manager records a drop."""
    dropped_events: list[tuple[str, dict[str, str]]] = []

    channel = RecorderChannel(rate=2)
    manager = AlertManager(
        channels=[channel],
        min_severity=AlertSeverity.INFO,
        metric_dropped=lambda reason, labels: dropped_events.append((reason, dict(labels))),
    )
    alert = Alert(title="t", summary="s", severity=AlertSeverity.HIGH)
    for _ in range(4):
        await manager._dispatch(alert)  # noqa: SLF001 — test hook
    assert len(channel.sent) == 2
    rate_drops = [evt for evt in dropped_events if evt[0] == "rate-limited"]
    assert len(rate_drops) == 2
    assert rate_drops[0][1]["channel"] == "recorder"


async def test_token_bucket_refills_over_time() -> None:
    """Waiting long enough should let the bucket accept another request."""
    clock = FakeClock()
    bucket = TokenBucket(rate_per_minute=60, capacity=1, clock=clock)
    assert await bucket.try_consume() is True
    assert await bucket.try_consume() is False
    clock.advance(2.0)  # 60/min -> 1 token per second; 2s should refill fully
    assert await bucket.try_consume() is True


def test_token_bucket_rejects_non_positive_rate() -> None:
    """A zero or negative rate must be rejected at construction time."""
    with pytest.raises(ValueError):
        TokenBucket(rate_per_minute=0)
