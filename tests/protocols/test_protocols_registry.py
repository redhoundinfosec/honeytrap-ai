"""Cross-cutting tests covering the new protocols' integration points."""

from __future__ import annotations

import pytest

from honeytrap.alerts.rules import (
    AlertRuleContext,
    rule_coap_amplification,
    rule_coap_sensitive_path,
    rule_mqtt_c2_topic,
    rule_mqtt_scanner_client,
    rule_rdp_scanner_cookie,
)
from honeytrap.core.engine import PROTOCOL_NAMES
from honeytrap.core.profile import load_profile
from honeytrap.intel.attack_mapper import TECHNIQUE_DB, ATTACKMapper


def test_protocol_registry_includes_eleven_protocols() -> None:
    assert set(PROTOCOL_NAMES) >= {
        "http",
        "https",
        "ssh",
        "telnet",
        "ftp",
        "smb",
        "smtp",
        "mysql",
        "imap",
        "rdp",
        "mqtt",
        "coap",
    }
    # Eleven distinct *first-class* protocols (https shares HTTP handler).
    distinct = set(PROTOCOL_NAMES) - {"https"}
    assert len(distinct) == 11


def test_attack_db_includes_new_techniques() -> None:
    for tid in ("T1114", "T1114.002", "T1021.001", "T1071", "T1602", "T1090"):
        assert tid in TECHNIQUE_DB


def test_attack_mapper_imap_auth_attempt() -> None:
    mapper = ATTACKMapper()
    mappings = mapper.map_event(
        {
            "protocol": "imap",
            "event_type": "auth_attempt",
            "username": "admin",
            "password": "admin",
        }
    )
    ids = {m.technique_id for m in mappings}
    assert "T1110" in ids  # parent of T1110.001 / T1110.004


def test_attack_mapper_rdp_x224_request_emits_t1021_001() -> None:
    mapper = ATTACKMapper()
    mappings = mapper.map_event(
        {
            "protocol": "rdp",
            "event_type": "x224_connect_request",
            "data": {"mstshash": "kali"},
        }
    )
    ids = {m.technique_id for m in mappings}
    sub_ids = {m.sub_technique_id for m in mappings if m.sub_technique_id}
    assert "T1021.001" in sub_ids
    assert "T1021" in ids


def test_attack_mapper_mqtt_c2_topic_emits_t1190() -> None:
    mapper = ATTACKMapper()
    mappings = mapper.map_event(
        {
            "protocol": "mqtt",
            "event_type": "publish",
            "data": {"topic": "/cmd/run"},
        }
    )
    ids = {m.technique_id for m in mappings}
    assert "T1190" in ids
    assert "T1071" in ids


def test_attack_mapper_coap_sensitive_path_emits_t1602() -> None:
    mapper = ATTACKMapper()
    mappings = mapper.map_event(
        {
            "protocol": "coap",
            "event_type": "coap_request",
            "data": {"uri_path": "/.well-known/core"},
        }
    )
    ids = {m.technique_id for m in mappings}
    sub_ids = {m.sub_technique_id for m in mappings if m.sub_technique_id}
    assert "T1602" in ids
    assert "T1071.001" in sub_ids


def test_alert_rule_rdp_scanner_cookie() -> None:
    ctx = AlertRuleContext()
    alerts = rule_rdp_scanner_cookie(
        {
            "protocol": "rdp",
            "event_type": "x224_connect_request",
            "remote_ip": "1.2.3.4",
            "data": {"scanner_like_cookie": True, "mstshash": "kali"},
        },
        ctx,
    )
    assert len(alerts) == 1
    assert alerts[0].severity.name == "MEDIUM"


def test_alert_rule_mqtt_c2_topic() -> None:
    ctx = AlertRuleContext()
    alerts = rule_mqtt_c2_topic(
        {
            "protocol": "mqtt",
            "event_type": "publish",
            "remote_ip": "1.2.3.4",
            "data": {"topic": "/cmd/exec"},
        },
        ctx,
    )
    assert len(alerts) == 1
    assert alerts[0].severity.name == "HIGH"


def test_alert_rule_mqtt_scanner_client() -> None:
    ctx = AlertRuleContext()
    alerts = rule_mqtt_scanner_client(
        {
            "protocol": "mqtt",
            "event_type": "mqtt_connect",
            "remote_ip": "1.2.3.4",
            "data": {"scanner_like_client_id": True, "client_id": "mqtt-explorer-1"},
        },
        ctx,
    )
    assert len(alerts) == 1
    assert alerts[0].severity.name == "MEDIUM"


def test_alert_rule_coap_sensitive_path() -> None:
    ctx = AlertRuleContext()
    alerts = rule_coap_sensitive_path(
        {
            "protocol": "coap",
            "event_type": "coap_request",
            "remote_ip": "1.2.3.4",
            "data": {"uri_path": "/config/admin"},
        },
        ctx,
    )
    assert len(alerts) == 1
    assert alerts[0].severity.name == "MEDIUM"


def test_alert_rule_coap_amplification() -> None:
    ctx = AlertRuleContext()
    alerts = rule_coap_amplification(
        {
            "protocol": "coap",
            "event_type": "amplification_probe",
            "remote_ip": "1.2.3.4",
            "data": {"amplification_ratio": 25.4},
        },
        ctx,
    )
    assert len(alerts) == 1
    assert alerts[0].severity.name == "HIGH"


@pytest.mark.parametrize(
    "name,expected_protocols",
    [
        ("windows_workstation", {"rdp", "smb", "http"}),
        ("iot_industrial", {"mqtt", "coap", "http"}),
    ],
)
def test_new_profiles_contain_expected_services(name: str, expected_protocols: set[str]) -> None:
    profile = load_profile(name)
    protocols = {s.protocol for s in profile.services}
    assert expected_protocols <= protocols


def test_full_enterprise_now_includes_new_protocols() -> None:
    profile = load_profile("full_enterprise")
    protocols = {s.protocol for s in profile.services}
    assert {"imap", "rdp", "mqtt", "coap"} <= protocols


def test_mail_server_profile_now_offers_imap() -> None:
    profile = load_profile("mail_server")
    assert any(s.protocol == "imap" for s in profile.services)
