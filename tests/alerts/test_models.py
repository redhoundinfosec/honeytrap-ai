"""Tests for :mod:`honeytrap.alerts.models`."""

from __future__ import annotations

from datetime import datetime, timezone

from honeytrap.alerts import Alert, AlertSeverity


def test_alert_round_trips_to_and_from_dict() -> None:
    """An Alert should survive a to_dict/from_dict round trip intact."""
    alert = Alert(
        title="Shell command executed",
        summary="Attacker ran whoami",
        severity=AlertSeverity.HIGH,
        source_ip="198.51.100.7",
        protocol="ssh",
        session_id="sess-42",
        attck_techniques=["T1059"],
        iocs={"ip": ["198.51.100.7"]},
        tags={"command-exec"},
        raw_event={"event_type": "shell_command"},
        timestamp=datetime(2026, 4, 21, 12, 30, 0, tzinfo=timezone.utc),
    )
    payload = alert.to_dict()
    restored = Alert.from_dict(payload)

    assert restored.id == alert.id
    assert restored.title == alert.title
    assert restored.summary == alert.summary
    assert restored.severity == AlertSeverity.HIGH
    assert restored.source_ip == alert.source_ip
    assert restored.protocol == alert.protocol
    assert restored.session_id == alert.session_id
    assert restored.attck_techniques == alert.attck_techniques
    assert restored.iocs == alert.iocs
    assert restored.tags == alert.tags
    assert restored.raw_event == alert.raw_event
    assert restored.timestamp == alert.timestamp


def test_severity_ordering_is_monotonic() -> None:
    """Higher severities should compare greater than lower ones."""
    assert AlertSeverity.CRITICAL > AlertSeverity.HIGH
    assert AlertSeverity.HIGH > AlertSeverity.MEDIUM
    assert AlertSeverity.MEDIUM > AlertSeverity.LOW
    assert AlertSeverity.LOW > AlertSeverity.INFO
    assert AlertSeverity.from_name("high") is AlertSeverity.HIGH
    assert AlertSeverity.from_name(AlertSeverity.LOW) is AlertSeverity.LOW
