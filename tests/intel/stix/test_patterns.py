"""Unit tests for ``honeytrap.intel.stix.patterns`` builders."""

from __future__ import annotations

import pytest

from honeytrap.intel.stix import patterns as P


def test_ipv4_pattern_quotes_value() -> None:
    assert P.ipv4_pattern("1.2.3.4") == "[ipv4-addr:value = '1.2.3.4']"


def test_ipv6_pattern_quotes_value() -> None:
    assert P.ipv6_pattern("::1") == "[ipv6-addr:value = '::1']"


def test_domain_pattern_lowercases() -> None:
    assert P.domain_pattern("EXAMPLE.com") == "[domain-name:value = 'example.com']"


def test_url_pattern_preserves_case() -> None:
    assert P.url_pattern("HTTPS://X") == "[url:value = 'HTTPS://X']"


def test_email_pattern_lowercases() -> None:
    assert P.email_pattern("Foo@Bar.COM") == "[email-addr:value = 'foo@bar.com']"


@pytest.mark.parametrize(
    "alg,canonical",
    [
        ("md5", "MD5"),
        ("sha1", "SHA-1"),
        ("sha256", "SHA-256"),
        ("sha512", "SHA-512"),
        ("CRC32", "CRC32"),
    ],
)
def test_hash_pattern_canonical_names(alg: str, canonical: str) -> None:
    out = P.hash_pattern(alg, "AABBCC")
    assert f"hashes.'{canonical}'" in out
    assert "'aabbcc'" in out


def test_user_agent_pattern_uses_extension_path() -> None:
    out = P.user_agent_pattern("curl/8.0")
    assert "http-request-ext" in out
    assert "User-Agent" in out


def test_quote_escapes_backslash_and_quote() -> None:
    out = P.url_pattern("a'b\\c")
    assert "a\\'b" in out
    assert "\\\\c" in out


def test_joined_or_empty_returns_empty_string() -> None:
    assert P.joined_or([]) == ""


def test_joined_or_filters_falsy() -> None:
    assert P.joined_or(["", "[a:b='1']", ""]) == "[a:b='1']"


def test_joined_or_joins_multiple() -> None:
    out = P.joined_or(["[a:b='1']", "[c:d='2']"])
    assert " OR " in out


def test_pattern_for_ioc_dispatches_known_types() -> None:
    assert "ipv4-addr" in P.pattern_for_ioc("ip", "1.2.3.4")
    assert "ipv6-addr" in P.pattern_for_ioc("ipv6", "::1")
    assert "domain-name" in P.pattern_for_ioc("domain", "x")
    assert "url" in P.pattern_for_ioc("url", "https://x")
    assert "email-addr" in P.pattern_for_ioc("email", "a@b")


def test_pattern_for_ioc_hash_inferred_from_length() -> None:
    md5 = P.pattern_for_ioc("hash", "a" * 32)
    sha1 = P.pattern_for_ioc("hash", "a" * 40)
    sha256 = P.pattern_for_ioc("hash", "a" * 64)
    sha512 = P.pattern_for_ioc("hash", "a" * 128)
    assert "MD5" in md5
    assert "SHA-1" in sha1
    assert "SHA-256" in sha256
    assert "SHA-512" in sha512


def test_pattern_for_ioc_user_agent() -> None:
    out = P.pattern_for_ioc("user_agent", "curl/8.0")
    assert "http-request-ext" in out


def test_pattern_for_ioc_unknown_raises() -> None:
    with pytest.raises(ValueError):
        P.pattern_for_ioc("imaginary", "x")
