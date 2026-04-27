"""Property-based fuzz tests for the TLS ClientHello parser.

The parser MUST be total: any attacker-controlled byte sequence must
either parse to a partial :class:`ClientHello` or yield ``None``,
without raising or hanging. These tests synthesize both random and
structured inputs that target known parser edge cases.
"""

from __future__ import annotations

import struct
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from honeytrap.intel.tls.clienthello import (
    TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_RECORD_HANDSHAKE,
    parse_client_hello,
    parse_tls_record,
)

pytestmark = pytest.mark.fuzz


def _build_minimal_clienthello(*, ciphers: bytes, ext_blob: bytes, sni_extra: bytes = b"") -> bytes:
    """Construct a TLS handshake-only ClientHello (no record header) buffer.

    ``ciphers`` is a raw byte sequence used as the cipher suite list
    body (its length will be validated by the parser). ``ext_blob`` is
    the raw extension list body. ``sni_extra`` is appended to provoke
    overflow conditions when needed.
    """
    legacy_version = struct.pack(">H", 0x0303)
    random_bytes = b"\x00" * 32
    session_id = b"\x00"  # length 0
    cipher_section = struct.pack(">H", len(ciphers)) + ciphers
    compression = b"\x01\x00"  # length 1, null method
    ext_section = struct.pack(">H", len(ext_blob)) + ext_blob + sni_extra
    body = legacy_version + random_bytes + session_id + cipher_section + compression + ext_section
    handshake_header = bytes([TLS_HANDSHAKE_CLIENT_HELLO]) + struct.pack(">I", len(body))[1:]
    return handshake_header + body


@settings(deadline=None, max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(buf=st.binary(min_size=0, max_size=4096))
def test_random_bytes_never_raise(buf: bytes) -> None:
    """Any random byte buffer must not raise when fed to the parser."""
    start = time.monotonic()
    result = parse_client_hello(buf)
    duration = time.monotonic() - start
    assert duration < 1.0, f"parse took {duration:.3f}s for {len(buf)} bytes"
    assert result is None or hasattr(result, "cipher_suites")


@settings(deadline=None, max_examples=100)
@given(
    record_type=st.integers(min_value=0, max_value=255),
    fake_len=st.integers(min_value=0, max_value=0xFFFF),
    body=st.binary(min_size=0, max_size=2048),
)
def test_record_header_never_raises(record_type: int, fake_len: int, body: bytes) -> None:
    """Any 5-byte record header + body combo parses to bytes or None."""
    header = bytes([record_type, 0x03, 0x03]) + struct.pack(">H", fake_len)
    out = parse_tls_record(header + body)
    assert out is None or isinstance(out, bytes)


@settings(deadline=None, max_examples=100)
@given(ciphers=st.binary(min_size=0, max_size=512), ext_blob=st.binary(min_size=0, max_size=2048))
def test_malformed_extensions_never_raise(ciphers: bytes, ext_blob: bytes) -> None:
    """A ClientHello with arbitrary extension bytes must not crash."""
    payload = _build_minimal_clienthello(ciphers=ciphers, ext_blob=ext_blob)
    record = bytes([TLS_RECORD_HANDSHAKE, 0x03, 0x03]) + struct.pack(">H", len(payload)) + payload
    result = parse_client_hello(record)
    assert result is None or hasattr(result, "extensions")


@settings(deadline=None, max_examples=100)
@given(host=st.binary(min_size=0, max_size=2048))
def test_oversized_or_nonutf8_sni_never_raises(host: bytes) -> None:
    """A SNI extension carrying random / non-UTF-8 host bytes must be safe."""
    # Build server_name extension: u16 list length, u8 name type=0, u16 host length, host bytes.
    name_entry = b"\x00" + struct.pack(">H", len(host)) + host
    list_blob = struct.pack(">H", len(name_entry)) + name_entry
    ext_blob = struct.pack(">H", 0x0000) + struct.pack(">H", len(list_blob)) + list_blob
    payload = _build_minimal_clienthello(ciphers=b"\x13\x01", ext_blob=ext_blob)
    record = bytes([TLS_RECORD_HANDSHAKE, 0x03, 0x03]) + struct.pack(">H", len(payload)) + payload
    result = parse_client_hello(record)
    assert result is None or hasattr(result, "server_name")


@settings(deadline=None, max_examples=100)
@given(garbage=st.binary(min_size=0, max_size=64))
def test_zero_length_cipher_list_is_handled(garbage: bytes) -> None:
    """A ClientHello with an empty cipher suite list must parse to None or partial."""
    payload = _build_minimal_clienthello(ciphers=b"", ext_blob=garbage)
    record = bytes([TLS_RECORD_HANDSHAKE, 0x03, 0x03]) + struct.pack(">H", len(payload)) + payload
    result = parse_client_hello(record)
    assert result is None or result.cipher_suites == ()


@settings(deadline=None, max_examples=100)
@given(
    bogus_length=st.integers(min_value=0, max_value=0xFFFFFF),
    body=st.binary(min_size=0, max_size=512),
)
def test_oversize_handshake_length_is_safe(bogus_length: int, body: bytes) -> None:
    """A handshake header with a wildly inflated length must not over-read."""
    header = bytes([TLS_HANDSHAKE_CLIENT_HELLO]) + bogus_length.to_bytes(3, "big")
    result = parse_client_hello(header + body)
    assert result is None or hasattr(result, "extensions")


@settings(deadline=None, max_examples=50)
@given(prefix=st.binary(min_size=0, max_size=4))
def test_truncated_inputs_return_none(prefix: bytes) -> None:
    """Inputs shorter than a handshake header must yield None."""
    assert parse_client_hello(prefix) is None
