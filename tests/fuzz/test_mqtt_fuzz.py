"""Property-based fuzz tests for MQTT parsers.

The MQTT broker shell handler must never crash on attacker input. Each
parser raises only :class:`ProtocolParseError` for structural problems
(callers convert these to events and close the connection); any other
exception is a bug. These tests also exercise the variable-byte
remaining-length encoder and the CONNACK / PUBACK / SUBACK builders to
keep the round-trip total.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from honeytrap.protocols.mqtt_handler import (
    ProtocolParseError,
    _decode_remaining_length,
    _encode_remaining_length,
    build_connack,
    build_puback,
    build_pubrec,
    build_suback,
    parse_connect,
    parse_publish,
    parse_subscribe,
)

pytestmark = pytest.mark.fuzz


@settings(deadline=None, max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(buf=st.binary(min_size=0, max_size=4096))
def test_parse_connect_never_raises_unhandled(buf: bytes) -> None:
    """``parse_connect`` only emits ``ProtocolParseError`` on malformed input."""
    try:
        info = parse_connect(buf)
    except ProtocolParseError:
        return
    assert isinstance(info, dict)
    for required in ("protocol", "level", "flags", "client_id"):
        assert required in info


@settings(deadline=None, max_examples=100)
@given(buf=st.binary(min_size=0, max_size=4096), level=st.sampled_from([3, 4, 5]))
def test_parse_subscribe_never_raises_unhandled(buf: bytes, level: int) -> None:
    """``parse_subscribe`` only emits ``ProtocolParseError`` on bad input."""
    try:
        info = parse_subscribe(buf, level)
    except ProtocolParseError:
        return
    assert isinstance(info, dict)
    assert "filters" in info


@settings(deadline=None, max_examples=100)
@given(
    buf=st.binary(min_size=0, max_size=4096),
    fixed_flags=st.integers(min_value=0, max_value=0x0F),
    level=st.sampled_from([3, 4, 5]),
)
def test_parse_publish_never_raises_unhandled(buf: bytes, fixed_flags: int, level: int) -> None:
    """``parse_publish`` rejects bad input with ``ProtocolParseError``."""
    try:
        info = parse_publish(buf, fixed_flags, level)
    except ProtocolParseError:
        return
    assert isinstance(info, dict)
    assert "topic" in info
    assert info["payload_size"] >= 0


@settings(deadline=None, max_examples=100)
@given(buf=st.binary(min_size=0, max_size=8))
def test_remaining_length_decoder_total(buf: bytes) -> None:
    """The variable-byte remaining-length decoder is exception-bounded."""
    try:
        value, consumed = _decode_remaining_length(buf, 0)
    except ProtocolParseError:
        return
    assert value >= 0
    assert 1 <= consumed <= 4


@settings(deadline=None, max_examples=100)
@given(value=st.integers(min_value=0, max_value=268_435_455))
def test_remaining_length_roundtrip(value: int) -> None:
    """Every legal remaining-length round-trips through encode/decode."""
    encoded = _encode_remaining_length(value)
    decoded_value, _consumed = _decode_remaining_length(encoded, 0)
    assert decoded_value == value


@settings(deadline=None, max_examples=50)
@given(
    proto_name=st.binary(min_size=0, max_size=16),
    level=st.integers(min_value=0, max_value=255),
    flags=st.integers(min_value=0, max_value=255),
    keepalive=st.integers(min_value=0, max_value=0xFFFF),
    client_id=st.binary(min_size=0, max_size=64),
)
def test_parse_connect_with_structured_garbage(
    proto_name: bytes,
    level: int,
    flags: int,
    keepalive: int,
    client_id: bytes,
) -> None:
    """A 'looks-like-CONNECT' packet with malformed fields stays parser-safe."""
    payload = (
        struct.pack(">H", len(proto_name))
        + proto_name
        + bytes([level, flags])
        + struct.pack(">H", keepalive)
        + struct.pack(">H", len(client_id))
        + client_id
    )
    try:
        info = parse_connect(payload)
    except ProtocolParseError:
        return
    assert info["client_id"] is not None


@settings(deadline=None, max_examples=20)
@given(
    packet_id=st.integers(min_value=0, max_value=0xFFFF),
    level=st.sampled_from([3, 4, 5]),
)
def test_response_builders_stable(packet_id: int, level: int) -> None:
    """All response builders produce non-empty bytes and never raise."""
    connack = build_connack(level=level)
    puback = build_puback(packet_id, level)
    pubrec = build_pubrec(packet_id, level)
    suback = build_suback(packet_id, [{"topic": "x", "qos": 0}], level)
    for buf in (connack, puback, pubrec, suback):
        assert isinstance(buf, bytes)
        assert len(buf) >= 2
