"""JA3 hasher tests."""

from __future__ import annotations

import hashlib

from honeytrap.intel.tls.clienthello import parse_client_hello
from honeytrap.intel.tls.ja3 import compute_ja3


def test_ja3_string_layout(curl_bytes: bytes) -> None:
    hello = parse_client_hello(curl_bytes)
    assert hello is not None
    fp = compute_ja3(hello)
    parts = fp.ja3_string.split(",")
    assert len(parts) == 5
    # SSLVersion section is a plain decimal integer.
    assert parts[0].isdigit()
    # Ciphers section is dash-separated decimals.
    assert all(token.isdigit() for token in parts[1].split("-") if token)


def test_ja3_md5_is_hex_and_stable(firefox_bytes: bytes) -> None:
    hello = parse_client_hello(firefox_bytes)
    assert hello is not None
    fp = compute_ja3(hello)
    assert len(fp.ja3_hash) == 32
    assert all(c in "0123456789abcdef" for c in fp.ja3_hash)
    # Stable snapshot: same input -> same hash.
    again = compute_ja3(hello)
    assert again.ja3_hash == fp.ja3_hash
    assert again.ja3_hash == hashlib.md5(fp.ja3_string.encode()).hexdigest()


def test_ja3_empty_sections_preserved(masscan_bytes: bytes) -> None:
    hello = parse_client_hello(masscan_bytes)
    assert hello is not None
    fp = compute_ja3(hello)
    # masscan fixture: no ec_point_formats extension -> trailing
    # section is an empty string between commas.
    parts = fp.ja3_string.split(",")
    assert len(parts) == 5
    assert parts[-1] == ""


def test_ja3_filters_grease(chrome_bytes: bytes) -> None:
    hello = parse_client_hello(chrome_bytes)
    assert hello is not None
    fp = compute_ja3(hello)
    # GREASE cipher 0x0a0a = 2570 must not appear in decimal form.
    cipher_section = fp.ja3_string.split(",")[1]
    assert "2570" not in cipher_section.split("-")
