"""ClientHello parser tests."""

from __future__ import annotations

from honeytrap.intel.tls.clienthello import GREASE_VALUES, parse_client_hello


def test_parse_firefox(firefox_bytes: bytes) -> None:
    hello = parse_client_hello(firefox_bytes)
    assert hello is not None
    assert hello.server_name == "www.mozilla.org"
    assert hello.highest_version() == 0x0304
    assert len(hello.cipher_suites) == 15
    assert 0x0010 in hello.extensions  # ALPN
    assert hello.alpn_protocols == ("h2", "http/1.1")


def test_parse_chrome(chrome_bytes: bytes) -> None:
    hello = parse_client_hello(chrome_bytes)
    assert hello is not None
    assert hello.server_name == "www.google.com"
    # GREASE 0x0a0a present in the fixture but retained in the raw
    # parse; the JA3/JA4 layers filter it.
    assert 0x0A0A in hello.cipher_suites
    assert hello.highest_version() == 0x0304


def test_parse_curl(curl_bytes: bytes) -> None:
    hello = parse_client_hello(curl_bytes)
    assert hello is not None
    assert hello.server_name == "example.com"
    assert 0x1301 in hello.cipher_suites
    assert hello.alpn_protocols == ("h2", "http/1.1")


def test_parse_python_requests(python_requests_bytes: bytes) -> None:
    hello = parse_client_hello(python_requests_bytes)
    assert hello is not None
    assert hello.server_name == "pypi.org"
    # Python requests in this fixture does not advertise supported_versions,
    # so the highest version collapses to the legacy field.
    assert hello.highest_version() == 0x0303
    assert hello.alpn_protocols == ()


def test_parse_nmap(nmap_bytes: bytes) -> None:
    hello = parse_client_hello(nmap_bytes)
    assert hello is not None
    assert hello.server_name is None
    assert len(hello.cipher_suites) == 9


def test_parse_malformed_returns_none(malformed_short_bytes: bytes) -> None:
    assert parse_client_hello(malformed_short_bytes) is None


def test_parse_non_tls_returns_none(non_tls_bytes: bytes) -> None:
    assert parse_client_hello(non_tls_bytes) is None


def test_grease_values_are_preserved_in_raw_parse(chrome_bytes: bytes) -> None:
    hello = parse_client_hello(chrome_bytes)
    assert hello is not None
    grease_ciphers = [c for c in hello.cipher_suites if c in GREASE_VALUES]
    assert grease_ciphers, "chrome fixture intentionally carries GREASE"
    grease_exts = [e for e in hello.extensions if e in GREASE_VALUES]
    assert grease_exts


def test_partial_record_returns_none() -> None:
    # Just the TLS record header with no body.
    assert parse_client_hello(b"\x16\x03\x01\x00\x10") is None


def test_empty_input_returns_none() -> None:
    assert parse_client_hello(b"") is None


def test_random_bytes_return_none() -> None:
    # Deterministic pseudo-random sequence that should not happen to
    # look like a ClientHello.
    blob = bytes((i * 7 + 3) % 256 for i in range(512))
    # Ensure first byte is not the handshake marker by construction.
    assert blob[0] != 0x16
    assert parse_client_hello(blob) is None
