"""STIX 2.1 pattern construction helpers.

The functions in this module emit pattern strings that conform to the
STIX 2.1 patterning grammar. Only the subset HoneyTrap actually uses
is implemented -- equality predicates over the SCOs we care about
(ipv4-addr, ipv6-addr, domain-name, url, file-hash, network-traffic,
user-account). Patterns are kept simple, readable, and deterministic
so bundle output is byte-for-byte stable across runs.
"""

from __future__ import annotations

from collections.abc import Iterable


def _quote(value: str) -> str:
    """Quote a STIX pattern string literal with doubled single-quotes."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def ipv4_pattern(value: str) -> str:
    """Build ``[ipv4-addr:value = '...']``."""
    return f"[ipv4-addr:value = {_quote(value)}]"


def ipv6_pattern(value: str) -> str:
    """Build ``[ipv6-addr:value = '...']``."""
    return f"[ipv6-addr:value = {_quote(value)}]"


def domain_pattern(value: str) -> str:
    """Build ``[domain-name:value = '...']``."""
    return f"[domain-name:value = {_quote(value.lower())}]"


def url_pattern(value: str) -> str:
    """Build ``[url:value = '...']``."""
    return f"[url:value = {_quote(value)}]"


def hash_pattern(algorithm: str, digest: str) -> str:
    """Build ``[file:hashes.'<ALGO>' = '...']`` with the canonical algo name."""
    canonical = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
        "sha512": "SHA-512",
    }.get(algorithm.lower(), algorithm.upper())
    return f"[file:hashes.'{canonical}' = {_quote(digest.lower())}]"


def email_pattern(value: str) -> str:
    """Build ``[email-addr:value = '...']``."""
    return f"[email-addr:value = {_quote(value.lower())}]"


def user_agent_pattern(value: str) -> str:
    """Build a network-traffic extension pattern carrying the user-agent."""
    return f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = {_quote(value)}]"


def joined_or(parts: Iterable[str]) -> str:
    """Join multiple atomic patterns with the ``OR`` operator."""
    items = [p for p in parts if p]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return " OR ".join(items)


def pattern_for_ioc(ioc_type: str, value: str, *, hash_alg: str | None = None) -> str:
    """Dispatch the right pattern builder for an internal IOC type."""
    t = ioc_type.lower()
    if t in {"ip", "ipv4"}:
        return ipv4_pattern(value)
    if t in {"ipv6"}:
        return ipv6_pattern(value)
    if t in {"domain", "host"}:
        return domain_pattern(value)
    if t == "url":
        return url_pattern(value)
    if t == "email":
        return email_pattern(value)
    if t == "hash":
        if not hash_alg:
            length = len(value)
            hash_alg = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(length, "sha256")
        return hash_pattern(hash_alg, value)
    if t in {"user_agent", "useragent"}:
        return user_agent_pattern(value)
    raise ValueError(f"Unsupported IOC type for STIX pattern: {ioc_type!r}")
