"""Benchmarks for JA3/JA4 generation cost.

The TLS fingerprinter is on the hot path for every TLS-tagged
connection (HTTPS honeypot, RDP/SSL upgrade). These benchmarks
synthesize a population of 20 known-good ClientHello byte sequences
and measure parse + JA3/JA4 derivation throughput.
"""

from __future__ import annotations

import struct

import pytest

from honeytrap.intel.tls.clienthello import (
    TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_RECORD_HANDSHAKE,
    parse_client_hello,
)
from honeytrap.intel.tls.fingerprinter import TLSFingerprinter
from honeytrap.intel.tls.ja3 import compute_ja3
from honeytrap.intel.tls.ja4 import compute_ja4

pytestmark = pytest.mark.benchmark


def _build_clienthello(
    *,
    sni: str,
    ciphers: list[int],
    alpn: list[str],
    versions: list[int],
) -> bytes:
    """Build a valid TLS ClientHello record with the requested attributes.

    Returns the bytes including the 5-byte record header so callers can
    feed them straight into the parser.
    """
    cipher_blob = b"".join(struct.pack(">H", c) for c in ciphers)
    cipher_section = struct.pack(">H", len(cipher_blob)) + cipher_blob
    legacy_version = struct.pack(">H", 0x0303)
    random_bytes = b"\x42" * 32
    session_id = b"\x00"
    compression = b"\x01\x00"

    # Server-name extension.
    sni_bytes = sni.encode("ascii")
    name_entry = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack(">H", len(name_entry)) + name_entry
    sni_ext = struct.pack(">H", 0x0000) + struct.pack(">H", len(sni_list)) + sni_list

    # ALPN extension.
    alpn_list = b""
    for proto in alpn:
        proto_bytes = proto.encode("ascii")
        alpn_list += bytes([len(proto_bytes)]) + proto_bytes
    alpn_blob = struct.pack(">H", len(alpn_list)) + alpn_list
    alpn_ext = struct.pack(">H", 0x0010) + struct.pack(">H", len(alpn_blob)) + alpn_blob

    # Supported-versions extension.
    versions_blob = b"".join(struct.pack(">H", v) for v in versions)
    sv_blob = bytes([len(versions_blob)]) + versions_blob
    sv_ext = struct.pack(">H", 0x002B) + struct.pack(">H", len(sv_blob)) + sv_blob

    extensions = sni_ext + alpn_ext + sv_ext
    ext_section = struct.pack(">H", len(extensions)) + extensions

    body = legacy_version + random_bytes + session_id + cipher_section + compression + ext_section
    handshake_header = bytes([TLS_HANDSHAKE_CLIENT_HELLO]) + struct.pack(">I", len(body))[1:]
    handshake = handshake_header + body
    record_header = bytes([TLS_RECORD_HANDSHAKE, 0x03, 0x03]) + struct.pack(">H", len(handshake))
    return record_header + handshake


def _sample_corpus() -> list[bytes]:
    """Return 20 distinct known-good ClientHello byte sequences."""
    base_ciphers = [
        [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C, 0xC02F, 0xC030],
        [0xC02C, 0xC030, 0x009F, 0xCCA9, 0xCCA8, 0x009E, 0x0033],
        [0x1301, 0x1302, 0xCCA9, 0xC02B, 0xC02F, 0x009C],
        [0xC014, 0xC013, 0x002F, 0x0035, 0xC012, 0xC011, 0x000A],
    ]
    snis = [
        "example.com",
        "api.test",
        "honey.example",
        "service.local",
        "scanner.test",
    ]
    alpns = [
        ["h2", "http/1.1"],
        ["http/1.1"],
        ["h2"],
        ["acme-tls/1"],
        ["http/1.0"],
    ]
    versions = [
        [0x0304, 0x0303],
        [0x0303],
        [0x0304, 0x0303, 0x0302],
        [0x0304],
    ]
    corpus: list[bytes] = []
    for i in range(20):
        corpus.append(
            _build_clienthello(
                sni=snis[i % len(snis)],
                ciphers=base_ciphers[i % len(base_ciphers)],
                alpn=alpns[i % len(alpns)],
                versions=versions[i % len(versions)],
            )
        )
    return corpus


_CORPUS = _sample_corpus()


def test_bench_tls_parse_only(benchmark) -> None:
    """Pure ClientHello parser throughput across the synthetic corpus."""

    def _parse_all() -> int:
        n = 0
        for buf in _CORPUS:
            if parse_client_hello(buf) is not None:
                n += 1
        return n

    n = benchmark(_parse_all)
    assert n == len(_CORPUS)


def test_bench_tls_ja3_ja4(benchmark) -> None:
    """JA3 + JA4 derivation cost on already-parsed ClientHellos."""
    parsed = [parse_client_hello(buf) for buf in _CORPUS]
    parsed = [p for p in parsed if p is not None]
    assert len(parsed) == len(_CORPUS)

    def _hash_all() -> int:
        n = 0
        for hello in parsed:
            compute_ja3(hello)
            compute_ja4(hello)
            n += 1
        return n

    n = benchmark(_hash_all)
    assert n == len(parsed)


def test_bench_tls_fingerprinter_end_to_end(benchmark) -> None:
    """End-to-end :class:`TLSFingerprinter` cost on raw bytes."""
    fp = TLSFingerprinter()

    def _fingerprint_all() -> int:
        n = 0
        for buf in _CORPUS:
            if fp.fingerprint(buf) is not None:
                n += 1
        return n

    n = benchmark(_fingerprint_all)
    assert n == len(_CORPUS)
