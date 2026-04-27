"""Property-based fuzz tests for the CoAP message parser.

CoAP datagrams arrive over UDP from any source. The parser must therefore
be total: ``ProtocolParseError`` for malformed inputs, a fully-typed
:class:`CoAPMessage` for valid inputs, and nothing else escapes.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from honeytrap.protocols.coap_handler import (
    COAP_TYPE_CON,
    CoAPMessage,
    ProtocolParseError,
    build_response,
    parse_message,
)

pytestmark = pytest.mark.fuzz


@settings(deadline=None, max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(buf=st.binary(min_size=0, max_size=4096))
def test_parse_message_never_raises_unhandled(buf: bytes) -> None:
    """``parse_message`` raises only ``ProtocolParseError`` on bad input."""
    try:
        msg = parse_message(buf)
    except ProtocolParseError:
        return
    assert isinstance(msg, CoAPMessage)
    assert 0 <= msg.version <= 3
    assert 0 <= msg.type_ <= 3
    assert 0 <= len(msg.token) <= 8


@settings(deadline=None, max_examples=100)
@given(
    first=st.integers(min_value=0, max_value=255),
    code=st.integers(min_value=0, max_value=255),
    mid=st.integers(min_value=0, max_value=0xFFFF),
    body=st.binary(min_size=0, max_size=512),
)
def test_random_first_byte_safe(first: int, code: int, mid: int, body: bytes) -> None:
    """A datagram with a fully random header byte must be parser-safe."""
    raw = bytes([first, code]) + struct.pack(">H", mid) + body
    try:
        parse_message(raw)
    except ProtocolParseError:
        return


@settings(deadline=None, max_examples=100)
@given(
    delta_nibble=st.integers(min_value=0, max_value=15),
    length_nibble=st.integers(min_value=0, max_value=15),
    body=st.binary(min_size=0, max_size=64),
)
def test_malformed_option_delta_or_length(
    delta_nibble: int, length_nibble: int, body: bytes
) -> None:
    """Reserved option-delta / option-length nibbles must raise cleanly."""
    # Header: ver=1, type=0, tkl=0, code=GET=0x01, mid=0x0001
    header = bytes([0x40, 0x01, 0x00, 0x01])
    option = bytes([(delta_nibble << 4) | length_nibble]) + body
    try:
        parse_message(header + option)
    except ProtocolParseError:
        return


@settings(deadline=None, max_examples=50)
@given(
    type_=st.integers(min_value=0, max_value=3),
    code=st.integers(min_value=0, max_value=255),
    mid=st.integers(min_value=0, max_value=0xFFFF),
    token=st.binary(min_size=0, max_size=8),
    payload=st.binary(min_size=0, max_size=256),
)
def test_build_response_round_trip(
    type_: int, code: int, mid: int, token: bytes, payload: bytes
) -> None:
    """``build_response`` output round-trips through ``parse_message`` cleanly."""
    raw = build_response(type_=type_, code=code, message_id=mid, token=token, payload=payload)
    msg = parse_message(raw)
    assert msg.type_ == type_
    assert msg.code == code
    assert msg.message_id == mid
    assert msg.token == token
    assert msg.payload == payload


@settings(deadline=None, max_examples=100)
@given(buf=st.binary(min_size=4, max_size=4))
def test_minimum_size_input_either_parses_or_raises(buf: bytes) -> None:
    """Inputs at exactly the 4-byte minimum either parse or raise cleanly."""
    try:
        msg = parse_message(buf)
        assert isinstance(msg, CoAPMessage)
    except ProtocolParseError:
        return


def test_parse_message_rejects_under_minimum() -> None:
    """A datagram shorter than 4 bytes is structurally malformed."""
    for size in range(0, 4):
        with pytest.raises(ProtocolParseError):
            parse_message(b"\x40" * size)


def test_build_response_rejects_oversize_token() -> None:
    """Tokens longer than 8 bytes must be rejected at build time."""
    with pytest.raises(ValueError):
        build_response(type_=COAP_TYPE_CON, code=0, message_id=0, token=b"\x00" * 9)
