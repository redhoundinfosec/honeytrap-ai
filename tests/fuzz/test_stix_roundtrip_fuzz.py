"""Property-based fuzz tests for STIX 2.1 export round-tripping.

These tests synthesise sequences of IOC and session records, push them
through :class:`StixBundleBuilder`, serialize the resulting bundle to
JSON, parse it back, and assert the bundle still validates against the
internal schema. The goal is to catch regressions in deduplication,
JSON serialization, and required-field handling under random input.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from honeytrap.intel.stix import (
    StixBundleBuilder,
    dump_compact,
    stix_from_ioc,
    stix_from_session,
    validate_bundle,
)

pytestmark = pytest.mark.fuzz


def _ipv4_strategy() -> st.SearchStrategy[str]:
    """Return a strategy for syntactically-valid IPv4 dotted-quads."""
    octet = st.integers(min_value=0, max_value=255)
    return st.tuples(octet, octet, octet, octet).map(lambda t: ".".join(str(x) for x in t))


def _domain_strategy() -> st.SearchStrategy[str]:
    """Return a strategy for plausible domain names."""
    label = st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
        min_size=1,
        max_size=12,
    ).filter(lambda s: not s.startswith("-") and not s.endswith("-"))
    return st.lists(label, min_size=1, max_size=4).map(lambda parts: ".".join(parts) + ".test")


def _ioc_strategy() -> st.SearchStrategy[dict]:
    """Synthesize a HoneyTrap-internal IOC dict (ip / domain / hash)."""
    return st.one_of(
        st.builds(
            lambda v: {"type": "ip", "value": v, "confidence": 0.7},
            _ipv4_strategy(),
        ),
        st.builds(
            lambda v: {"type": "domain", "value": v, "confidence": 0.6},
            _domain_strategy(),
        ),
        st.builds(
            lambda v: {"type": "hash", "value": v, "confidence": 0.9},
            st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
        ),
    )


@settings(deadline=None, max_examples=50, suppress_health_check=[HealthCheck.too_slow])
@given(iocs=st.lists(_ioc_strategy(), min_size=0, max_size=12))
def test_ioc_bundle_roundtrips(iocs: list[dict]) -> None:
    """An IOC list always serialises into a self-validating STIX bundle."""
    builder = StixBundleBuilder()
    for ioc in iocs:
        try:
            stix_from_ioc(builder, ioc)
        except ValueError:
            continue
    bundle = builder.build()
    blob = dump_compact(bundle)
    parsed = json.loads(blob)
    validate_bundle(parsed)
    assert parsed["type"] == "bundle"
    assert isinstance(parsed["objects"], list)


@settings(deadline=None, max_examples=30)
@given(
    sessions=st.lists(
        st.builds(
            lambda sid, ip, proto: {
                "session_id": sid,
                "remote_ip": ip,
                "protocol": proto,
                "started_at": "2026-01-01T00:00:00.000Z",
                "ended_at": "2026-01-01T00:01:00.000Z",
            },
            st.text(alphabet="abcdef0123456789-", min_size=8, max_size=16),
            _ipv4_strategy(),
            st.sampled_from(["ssh", "http", "telnet", "ftp", "smtp"]),
        ),
        min_size=0,
        max_size=8,
    ),
    iocs=st.lists(_ioc_strategy(), min_size=0, max_size=8),
)
def test_session_bundle_roundtrips(sessions: list[dict], iocs: list[dict]) -> None:
    """Sessions + IOCs serialise into a valid bundle and parse back cleanly."""
    builder = StixBundleBuilder()
    for session in sessions:
        try:
            stix_from_session(builder, session, iocs=iocs)
        except (ValueError, KeyError):
            continue
    bundle = builder.build()
    parsed = json.loads(dump_compact(bundle))
    validate_bundle(parsed)
    # Bundle id should be a fresh UUID-shaped string.
    assert parsed["id"].startswith("bundle--")


@settings(deadline=None, max_examples=30)
@given(iocs=st.lists(_ioc_strategy(), min_size=2, max_size=8))
def test_duplicate_iocs_are_merged(iocs: list[dict]) -> None:
    """Adding the same IOC twice must not produce duplicate STIX objects."""
    builder = StixBundleBuilder()
    for ioc in iocs:
        try:
            stix_from_ioc(builder, ioc)
        except ValueError:
            continue
    # Add them all again -- builder must dedupe by id.
    for ioc in iocs:
        try:
            stix_from_ioc(builder, ioc)
        except ValueError:
            continue
    bundle = builder.build()
    ids = [obj["id"] for obj in bundle["objects"]]
    assert len(ids) == len(set(ids))
    parsed = json.loads(dump_compact(bundle))
    validate_bundle(parsed)


def test_empty_bundle_is_valid() -> None:
    """A builder that has no IOCs/sessions still produces a valid bundle."""
    builder = StixBundleBuilder()
    bundle = builder.build()
    parsed = json.loads(dump_compact(bundle))
    validate_bundle(parsed)
    # Only the seeded identity object is present.
    types = {obj["type"] for obj in parsed["objects"]}
    assert "identity" in types
