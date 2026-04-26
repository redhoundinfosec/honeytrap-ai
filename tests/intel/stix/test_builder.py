"""Tests for the STIX 2.1 bundle builder, validator, and patterns."""

from __future__ import annotations

import json
import re

import pytest

from honeytrap.intel.stix import (
    STIX_SPEC_VERSION,
    StixBundleBuilder,
    StixValidationError,
    dump_compact,
    dump_pretty,
    stix_from_attck,
    stix_from_ioc,
    stix_from_session,
    stix_from_tls,
    validate_bundle,
    validate_object,
)
from honeytrap.intel.stix.patterns import (
    domain_pattern,
    hash_pattern,
    ipv4_pattern,
    pattern_for_ioc,
    url_pattern,
)

_STIX_ID_RE = re.compile(r"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def test_pattern_helpers_emit_quoted_predicates() -> None:
    assert ipv4_pattern("1.2.3.4") == "[ipv4-addr:value = '1.2.3.4']"
    assert domain_pattern("Bad.example") == "[domain-name:value = 'bad.example']"
    assert url_pattern("https://x/y") == "[url:value = 'https://x/y']"
    assert hash_pattern("sha256", "abc") == "[file:hashes.'SHA-256' = 'abc']"


def test_pattern_for_ioc_dispatches_by_type() -> None:
    assert pattern_for_ioc("ip", "10.0.0.5").startswith("[ipv4-addr:value")
    assert pattern_for_ioc("domain", "EXAMPLE.com").endswith("'example.com']")
    assert pattern_for_ioc("hash", "a" * 32).startswith("[file:hashes.'MD5'")
    with pytest.raises(ValueError):
        pattern_for_ioc("nope", "x")


def test_builder_seeds_identity_and_emits_valid_bundle() -> None:
    builder = StixBundleBuilder(identity_name="Lab Honeypot")
    bundle = builder.build()
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    types = {obj["type"] for obj in bundle["objects"]}
    assert types == {"identity"}
    validate_bundle(bundle)
    assert _STIX_ID_RE.match(bundle["objects"][0]["id"])


def test_builder_dedupes_objects_by_natural_key() -> None:
    builder = StixBundleBuilder()
    a = stix_from_ioc(builder, {"type": "ip", "value": "1.2.3.4"})
    b = stix_from_ioc(builder, {"type": "ip", "value": "1.2.3.4"})
    assert a == b
    indicator_count = sum(1 for o in builder.objects() if o["type"] == "indicator")
    assert indicator_count == 1


def test_builder_attck_includes_external_reference() -> None:
    builder = StixBundleBuilder()
    sid = stix_from_attck(
        builder,
        "T1110",
        name="Brute Force",
        tactic="Credential Access",
    )
    ap = next(o for o in builder.objects() if o["id"] == sid)
    refs = ap["external_references"]
    assert refs[0]["source_name"] == "mitre-attack"
    assert refs[0]["external_id"] == "T1110"
    assert "kill_chain_phases" in ap


def test_builder_session_creates_relationships_and_campaign() -> None:
    builder = StixBundleBuilder()
    refs = stix_from_session(
        builder,
        {
            "session_id": "sess-1",
            "remote_ip": "203.0.113.5",
            "protocol": "ssh",
            "started_at": "2026-04-23T10:00:00.000Z",
            "ended_at": "2026-04-23T10:05:00.000Z",
        },
        iocs=[{"type": "ip", "value": "203.0.113.5", "session_id": "sess-1"}],
        techniques=["T1110"],
        tls={"ja3": "abc", "ja4": "t13"},
    )
    assert refs["campaign"].startswith("campaign--")
    rels = [o for o in builder.objects() if o["type"] == "relationship"]
    rel_types = {r["relationship_type"] for r in rels}
    assert {"related-to", "indicates", "based-on", "targets"}.issubset(rel_types)
    notes = [o for o in builder.objects() if o["type"] == "note"]
    assert any("x_ja3" in n for n in notes)


def test_builder_tls_note_carries_custom_fields() -> None:
    builder = StixBundleBuilder()
    nid = stix_from_tls(builder, ja3="aaaa", ja4="t13d", matched_label="nmap")
    note = next(o for o in builder.objects() if o["id"] == nid)
    assert note["x_ja3"] == "aaaa"
    assert note["x_ja4"] == "t13d"


def test_validate_object_rejects_missing_required_fields() -> None:
    with pytest.raises(StixValidationError):
        validate_object({"type": "indicator", "id": "indicator--bad"})


def test_validate_bundle_rejects_bad_top_level() -> None:
    with pytest.raises(StixValidationError):
        validate_bundle({"type": "not-a-bundle", "id": "bundle--x", "objects": []})


def test_serializer_compact_and_pretty_are_stable() -> None:
    builder = StixBundleBuilder()
    stix_from_ioc(builder, {"type": "ip", "value": "1.1.1.1"})
    bundle = builder.build()
    compact = dump_compact(bundle)
    pretty = dump_pretty(bundle)
    assert compact == dump_compact(json.loads(compact))
    assert json.loads(pretty) == bundle
    assert "\n" not in compact
    assert "\n" in pretty


def test_object_count_by_type_used_for_metric_labels() -> None:
    builder = StixBundleBuilder()
    stix_from_ioc(builder, {"type": "ip", "value": "8.8.8.8"})
    counts = builder.object_count_by_type()
    assert counts["identity"] == 1
    assert counts["indicator"] == 1
    assert counts["observed-data"] == 1


def test_spec_version_is_constant() -> None:
    builder = StixBundleBuilder()
    bundle = builder.build()
    assert all(obj["spec_version"] == STIX_SPEC_VERSION for obj in bundle["objects"])
