"""Tests for the TLS-fingerprint alert rule."""

from __future__ import annotations

from honeytrap.alerts.models import AlertSeverity
from honeytrap.alerts.rules import AlertRuleContext, rule_tls_fingerprint


def _event(match_name: str, category: str) -> dict[str, object]:
    return {
        "remote_ip": "203.0.113.5",
        "protocol": "http",
        "session_id": "s1",
        "event_type": "http_request",
        "data": {
            "tls_fingerprint": {
                "ja3": "deadbeefdeadbeefdeadbeefdeadbeef",
                "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
                "matches": [
                    {
                        "name": match_name,
                        "category": category,
                        "confidence": "high",
                    }
                ],
            }
        },
    }


def test_malware_match_triggers_high_alert() -> None:
    ctx = AlertRuleContext()
    alerts = rule_tls_fingerprint(_event("Cobalt Strike", "malware"), ctx)
    assert len(alerts) == 1
    assert alerts[0].severity is AlertSeverity.HIGH
    assert "Cobalt Strike" in alerts[0].title
    assert "tls-fingerprint" in alerts[0].tags


def test_scanner_match_triggers_medium_alert() -> None:
    ctx = AlertRuleContext()
    alerts = rule_tls_fingerprint(_event("nmap", "scanner"), ctx)
    assert len(alerts) == 1
    assert alerts[0].severity is AlertSeverity.MEDIUM


def test_browser_match_triggers_no_alert() -> None:
    ctx = AlertRuleContext()
    alerts = rule_tls_fingerprint(_event("Firefox", "browser"), ctx)
    assert alerts == []


def test_no_tls_block_returns_empty() -> None:
    ctx = AlertRuleContext()
    event: dict[str, object] = {"remote_ip": "203.0.113.5", "data": {}}
    assert rule_tls_fingerprint(event, ctx) == []
