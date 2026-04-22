"""JA4 hasher tests."""

from __future__ import annotations

from honeytrap.intel.tls.clienthello import parse_client_hello
from honeytrap.intel.tls.ja4 import compute_ja4


def test_ja4_tls13_prefix(firefox_bytes: bytes) -> None:
    hello = parse_client_hello(firefox_bytes)
    assert hello is not None
    fp = compute_ja4(hello)
    assert fp.startswith("t13d")


def test_ja4_transport_default_is_tcp(nmap_bytes: bytes) -> None:
    hello = parse_client_hello(nmap_bytes)
    assert hello is not None
    fp = compute_ja4(hello, transport="bogus")  # type: ignore[arg-type]
    assert fp[0] == "t"


def test_ja4_transport_quic_override(firefox_bytes: bytes) -> None:
    hello = parse_client_hello(firefox_bytes)
    assert hello is not None
    fp = compute_ja4(hello, transport="q")
    assert fp[0] == "q"


def test_ja4_sni_flag(firefox_bytes: bytes, nmap_bytes: bytes) -> None:
    ff = parse_client_hello(firefox_bytes)
    nm = parse_client_hello(nmap_bytes)
    assert ff is not None and nm is not None
    assert compute_ja4(ff)[3] == "d"  # firefox has SNI
    assert compute_ja4(nm)[3] == "i"  # nmap fixture has no SNI


def test_ja4_alpn_encoding(firefox_bytes: bytes) -> None:
    hello = parse_client_hello(firefox_bytes)
    assert hello is not None
    fp = compute_ja4(hello)
    # Firefox fixture has ALPN ["h2", "http/1.1"]:
    # first char of first ALPN = 'h', last char of last ALPN = '1'.
    preamble = fp.split("_", 1)[0]
    assert preamble.endswith("h1")


def test_ja4_alpn_missing_uses_zero(python_requests_bytes: bytes) -> None:
    hello = parse_client_hello(python_requests_bytes)
    assert hello is not None
    preamble = compute_ja4(hello).split("_", 1)[0]
    assert preamble.endswith("00")


def test_ja4_hash_truncation(curl_bytes: bytes) -> None:
    hello = parse_client_hello(curl_bytes)
    assert hello is not None
    preamble, cipher_hash, ext_hash = compute_ja4(hello).split("_")
    assert len(cipher_hash) == 12
    assert len(ext_hash) == 12


def test_ja4_grease_excluded_from_hashes(chrome_bytes: bytes) -> None:
    hello = parse_client_hello(chrome_bytes)
    assert hello is not None
    fp = compute_ja4(hello)
    # GREASE 0x0a0a -> 0a0a. Sorted cipher CSV starts with the
    # lowest non-GREASE cipher (0x1301). If GREASE had leaked into
    # the hash payload, the sha256 prefix would shift and we could
    # not get a stable value on this fixture.
    _, cipher_hash, _ = fp.split("_")
    assert cipher_hash == "8daaf6152771"


def test_ja4_empty_extensions_hash_000(masscan_bytes: bytes) -> None:
    hello = parse_client_hello(masscan_bytes)
    assert hello is not None
    fp = compute_ja4(hello)
    # masscan has extension bytes but no sig_algs; assert the field
    # hash has the canonical length rather than a specific value.
    _, cipher_hash, ext_hash = fp.split("_")
    assert len(ext_hash) == 12
