"""Tests for :class:`honeytrap.alerts.AlertManager` and the config loader."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from honeytrap.alerts import (
    Alert,
    AlertManager,
    AlertRuleContext,
    AlertRuleEngine,
    AlertSeverity,
    parse_alerts_config,
)
from honeytrap.alerts.channels.base import AlertChannel


class DummyChannel(AlertChannel):
    """Recording channel whose ``_send`` call count is exposed for assertions."""

    def __init__(
        self,
        name: str,
        *,
        min_severity: AlertSeverity = AlertSeverity.LOW,
        raise_exc: Exception | None = None,
    ) -> None:
        """Optionally raise ``raise_exc`` on every send."""
        super().__init__(name, min_severity=min_severity, rate_limit_per_minute=600)
        self.sent: list[Alert] = []
        self._raise_exc = raise_exc

    async def _send(self, alert: Alert) -> None:
        if self._raise_exc is not None:
            raise self._raise_exc
        self.sent.append(alert)


async def test_manager_dispatches_to_channels_meeting_min_severity() -> None:
    """Only channels whose min_severity is met should see the alert."""
    low = DummyChannel("low", min_severity=AlertSeverity.LOW)
    high = DummyChannel("high", min_severity=AlertSeverity.HIGH)
    rules = AlertRuleEngine(rules=(), context=AlertRuleContext())

    def shell_rule(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
        return [
            Alert(title="shell", summary="ran", severity=AlertSeverity.MEDIUM),
        ]

    rules.register_rule(shell_rule)
    manager = AlertManager(channels=[low, high], rules=rules, min_severity=AlertSeverity.LOW)
    await manager.handle_event({"event_type": "x"})
    assert len(low.sent) == 1
    assert len(high.sent) == 0


async def test_failing_channel_does_not_block_siblings() -> None:
    """One channel raising must not prevent others from receiving the alert."""
    good = DummyChannel("good")
    bad = DummyChannel("bad", raise_exc=RuntimeError("boom"))
    manager = AlertManager(channels=[bad, good], min_severity=AlertSeverity.INFO)
    alert = Alert(title="x", summary="y", severity=AlertSeverity.HIGH)
    await manager._dispatch(alert)  # noqa: SLF001 — test hook
    assert len(good.sent) == 1
    assert len(bad.sent) == 0


async def test_dry_run_does_not_call_channel_send() -> None:
    """In dry-run mode channels must not receive any alerts."""
    ch = DummyChannel("dry")
    sent_metric_calls: list[tuple[str, dict[str, str]]] = []
    manager = AlertManager(
        channels=[ch],
        dry_run=True,
        min_severity=AlertSeverity.INFO,
        metric_sent=lambda c, labels: sent_metric_calls.append((c, dict(labels))),
    )
    alert = Alert(title="x", summary="y", severity=AlertSeverity.HIGH)
    await manager._dispatch(alert)  # noqa: SLF001 — test hook
    assert ch.sent == []
    # Metric still increments so ops can see dry-run activity.
    assert any(name == "dry" for name, _ in sent_metric_calls)


async def test_shutdown_flushes_in_flight_alerts() -> None:
    """shutdown should await any outstanding deliveries before returning."""

    loop_event = asyncio.Event()

    class SlowChannel(AlertChannel):
        def __init__(self) -> None:
            super().__init__(
                "slow",
                min_severity=AlertSeverity.INFO,
                rate_limit_per_minute=600,
            )
            self.done = False

        async def _send(self, alert: Alert) -> None:
            await asyncio.sleep(0.05)
            self.done = True
            loop_event.set()

    ch = SlowChannel()
    manager = AlertManager(channels=[ch], min_severity=AlertSeverity.INFO)
    alert = Alert(title="x", summary="y", severity=AlertSeverity.HIGH)
    # Fire-and-forget the dispatch so shutdown has something to flush.
    task = asyncio.create_task(manager._dispatch(alert))  # noqa: SLF001
    await asyncio.sleep(0)
    await manager.shutdown(timeout=1.0)
    await task
    assert ch.done is True


def test_config_loader_skips_channels_with_missing_env_vars(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Channels whose referenced env var is absent must be skipped with a warning."""
    monkeypatch.delenv("HONEYTRAP_TEST_MISSING_HOOK", raising=False)
    raw = {
        "enabled": True,
        "min_severity": "MEDIUM",
        "channels": [
            {
                "type": "slack",
                "webhook_url_env": "HONEYTRAP_TEST_MISSING_HOOK",
                "min_severity": "HIGH",
            },
            {
                "type": "slack",
                "name": "slack-ok",
                "webhook_url": "https://hooks.slack.example/OK",
                "min_severity": "HIGH",
            },
        ],
    }
    cfg = parse_alerts_config(raw)
    names = {c.name for c in cfg.channels}
    assert names == {"slack-ok"}
    assert any("missing webhook_url" in w for w in cfg.warnings)
    assert cfg.enabled is True


async def test_config_loader_reads_env_referenced_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """A channel referencing an env var that exists should be built correctly."""
    monkeypatch.setenv("HONEYTRAP_TEST_HOOK", "https://hooks.example/ABC")
    raw = {
        "enabled": True,
        "channels": [
            {"type": "slack", "webhook_url_env": "HONEYTRAP_TEST_HOOK", "min_severity": "LOW"}
        ],
    }
    cfg = parse_alerts_config(raw)
    assert len(cfg.channels) == 1
    channel = cfg.channels[0]
    assert getattr(channel, "webhook_url", None) == "https://hooks.example/ABC"
