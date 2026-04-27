"""Property-based fuzz tests for the RDP TPKT / X.224 parsers.

These ensure that arbitrary attacker input cannot drive the parser
into a hang, an unbounded allocation, or an unhandled exception.
The TPKT parser has well-defined success and failure modes:

* ``None`` for short / incomplete frames (caller will read more).
* A ``ProtocolParseError`` for structurally bad frames (caller drops).
* A ``(length, payload)`` tuple on success.

Anything else is a bug; the tests assert that no other behavior leaks.
"""

from __future__ import annotations

import struct
import sys

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from honeytrap.protocols.rdp_handler import (
    ProtocolParseError,
    _build_x224_connection_confirm,
    _parse_ntlm_negotiate,
    _parse_tpkt,
    _parse_x224_connection_request,
)

pytestmark = pytest.mark.fuzz


@settings(deadline=None, max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(buf=st.binary(min_size=0, max_size=4096))
def test_tpkt_never_raises_unhandled(buf: bytes) -> None:
    """The TPKT parser only raises ``ProtocolParseError`` -- never any other type."""
    try:
        result = _parse_tpkt(buf)
    except ProtocolParseError:
        return
    assert result is None or (
        isinstance(result, tuple)
        and len(result) == 2
        and isinstance(result[0], int)
        and isinstance(result[1], bytes)
    )


@settings(deadline=None, max_examples=100)
@given(buf=st.binary(min_size=4, max_size=4096))
def test_tpkt_payload_bounded(buf: bytes) -> None:
    """A TPKT result's payload size is bounded by the input length."""
    pre = sys.getsizeof(buf)
    try:
        result = _parse_tpkt(buf)
    except ProtocolParseError:
        return
    if result is None:
        return
    _length, payload = result
    assert len(payload) <= len(buf)
    # Memory bound: parser must not allocate > 64 KiB from a 1 KiB input.
    if len(buf) <= 1024:
        assert sys.getsizeof(payload) < 64 * 1024 + pre


@settings(deadline=None, max_examples=100)
@given(buf=st.binary(min_size=0, max_size=2048))
def test_x224_connection_request_never_raises_unhandled(buf: bytes) -> None:
    """The X.224 CR parser only raises ``ProtocolParseError``."""
    try:
        info = _parse_x224_connection_request(buf)
    except ProtocolParseError:
        return
    assert isinstance(info, dict)
    assert "mstshash" in info
    assert "requested_protocols" in info
    assert "negreq_present" in info


@settings(deadline=None, max_examples=100)
@given(buf=st.binary(min_size=0, max_size=2048))
def test_ntlm_negotiate_never_raises(buf: bytes) -> None:
    """The NTLM ``NEGOTIATE_MESSAGE`` finder must be exception-free."""
    try:
        result = _parse_ntlm_negotiate(buf)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"_parse_ntlm_negotiate raised: {type(exc).__name__}: {exc}")
    assert result is None or isinstance(result, dict)


@settings(deadline=None, max_examples=50)
@given(
    declared_length=st.integers(min_value=0, max_value=0xFFFF),
    body=st.binary(min_size=0, max_size=512),
)
def test_tpkt_invalid_length_field_rejected(declared_length: int, body: bytes) -> None:
    """A TPKT with a length field below 4 must raise; oversize lengths must too."""
    header = struct.pack(">BBH", 0x03, 0x00, declared_length)
    try:
        result = _parse_tpkt(header + body)
    except ProtocolParseError:
        return
    if declared_length < 4 or declared_length > 256 * 1024:
        pytest.fail(f"length {declared_length} should have been rejected")
    assert result is None or isinstance(result, tuple)


@settings(deadline=None, max_examples=20)
@given(selected=st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_x224_connection_confirm_roundtrip(selected: int) -> None:
    """A built CC-TPDU is always parseable back as a TPKT envelope."""
    packet = _build_x224_connection_confirm(selected & 0xFFFFFFFF)
    parsed = _parse_tpkt(packet)
    assert parsed is not None
    length, body = parsed
    assert length == len(packet)
    assert len(body) == length - 4
