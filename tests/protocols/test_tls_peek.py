"""Async tests for the tls_peek helper."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from honeytrap.intel.tls.fingerprinter import TLSFingerprinter
from honeytrap.protocols.tls_peek import MAX_PEEK_BYTES, peek_tls_client_hello

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "tls"


def _make_reader(chunks: list[bytes]) -> asyncio.StreamReader:
    """Build a StreamReader pre-loaded with ``chunks`` as feed payloads."""
    reader = asyncio.StreamReader()
    for c in chunks:
        reader.feed_data(c)
    reader.feed_eof()
    return reader


@pytest.mark.asyncio
async def test_peek_tls_clienthello() -> None:
    data = (FIXTURES / "firefox.bin").read_bytes()
    reader = _make_reader([data])
    fp = TLSFingerprinter()
    result = await peek_tls_client_hello(reader, fp, timeout=1.0)
    assert result.is_tls
    assert result.fingerprint is not None
    assert result.fingerprint.client_hello.server_name == "www.mozilla.org"
    assert result.consumed_bytes == data


@pytest.mark.asyncio
async def test_peek_non_tls_returns_bytes_unchanged() -> None:
    data = b"GET / HTTP/1.1\r\nHost: honeytrap.local\r\n\r\n"
    reader = _make_reader([data])
    fp = TLSFingerprinter()
    result = await peek_tls_client_hello(reader, fp, timeout=1.0)
    assert not result.is_tls
    assert result.fingerprint is None
    assert result.consumed_bytes == data


@pytest.mark.asyncio
async def test_peek_cap_enforced() -> None:
    # Feed a record header advertising > 16 KiB, followed by arbitrary bytes.
    huge_len = 0xFFFF
    header = b"\x16\x03\x01" + huge_len.to_bytes(2, "big")
    filler = b"A" * (MAX_PEEK_BYTES + 1024)
    reader = _make_reader([header + filler])
    fp = TLSFingerprinter()
    result = await peek_tls_client_hello(reader, fp, timeout=1.0)
    assert len(result.consumed_bytes) <= MAX_PEEK_BYTES


@pytest.mark.asyncio
async def test_peek_timeout_is_non_fatal() -> None:
    # A reader that never produces data forces the inner
    # asyncio.wait_for to time out. tls_peek must not raise.
    reader = asyncio.StreamReader()
    fp = TLSFingerprinter()
    result = await peek_tls_client_hello(reader, fp, timeout=0.05)
    assert result.timed_out
    assert result.fingerprint is None


@pytest.mark.asyncio
async def test_peek_handles_partial_reads() -> None:
    data = (FIXTURES / "curl.bin").read_bytes()
    # Feed the payload in single-byte chunks to exercise the read loop.
    reader = _make_reader([bytes([b]) for b in data])
    fp = TLSFingerprinter()
    result = await peek_tls_client_hello(reader, fp, timeout=1.0)
    assert result.is_tls
    assert result.fingerprint is not None
    assert result.fingerprint.client_hello.server_name == "example.com"
