"""JA4 TLS client fingerprinting.

Implements the FoxIO JA4 specification
(https://github.com/FoxIO-LLC/ja4). The fingerprint format is::

    (q|t)(version)(sni|no_sni)(ciphers_count)(extensions_count)(alpn_a+b)
        _ sha256_12(sorted_ciphers_csv)
        _ sha256_12(sorted_extensions_csv, sig_algs_csv)

Example::

    t13d1516h2_8daaf6152771_e5627efa2ab1

* ``t`` = TCP (``q`` would be QUIC; we emit ``t`` because the
  honeypot speaks TCP and the QUIC detection lives a layer up).
* ``13`` = highest TLS version (TLS 1.3 from supported_versions;
  legacy_version when that extension is absent).
* ``d`` = SNI present, ``i`` otherwise.
* ``15`` = cipher count, ``16`` = extension count, both zero-padded
  to two digits and capped at 99.
* ``h2`` = first character of first ALPN + last character of last
  ALPN, both lowercased. ``00`` when no ALPN is offered.
* The two trailing 12-character truncations are SHA-256 of the
  comma-separated hex lists; GREASE and SNI/ALPN extensions are
  excluded from the extension list.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from honeytrap.intel.tls.clienthello import (
    EXT_ALPN,
    EXT_SERVER_NAME,
    GREASE_VALUES,
    ClientHello,
)


def _version_code(version: int) -> str:
    mapping = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0002: "s2",
    }
    return mapping.get(version, "00")


def _alpn_code(alpn: tuple[str, ...]) -> str:
    """Return the 2-char JA4 ALPN code.

    Per the FoxIO JA4 spec this is the first character of the first
    ALPN value concatenated with the last character of the last ALPN
    value (lowercased). Returns ``"00"`` when no ALPN is advertised.
    """
    if not alpn:
        return "00"
    first, last = alpn[0], alpn[-1]
    if not first or not last:
        return "00"
    return (first[0] + last[-1]).lower()


def _hex4(value: int) -> str:
    return f"{value:04x}"


def _sha256_12(payload: str) -> str:
    if not payload:
        return "000000000000"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest[:12]


def _two_digit(count: int) -> str:
    return f"{min(count, 99):02d}"


def compute_ja4(
    hello: ClientHello,
    *,
    transport: Literal["t", "q"] = "t",
) -> str:
    """Compute the FoxIO JA4 fingerprint string.

    Args:
        hello: Parsed ClientHello.
        transport: ``"t"`` for TCP (default) or ``"q"`` for QUIC/UDP.
    """
    if transport not in ("t", "q"):
        transport = "t"

    version = hello.highest_version()
    version_code = _version_code(version)
    sni_flag = "d" if hello.server_name else "i"

    non_grease_ciphers = [c for c in hello.cipher_suites if c not in GREASE_VALUES]
    non_grease_extensions = [e for e in hello.extensions if e not in GREASE_VALUES]
    # SNI and ALPN extensions are counted in the preamble but excluded
    # from the sorted extension hash per the JA4 spec.
    hashable_extensions = [e for e in non_grease_extensions if e not in (EXT_SERVER_NAME, EXT_ALPN)]

    ciphers_count = _two_digit(len(non_grease_ciphers))
    ext_count = _two_digit(len(non_grease_extensions))
    alpn_code = _alpn_code(hello.alpn_protocols)

    preamble = f"{transport}{version_code}{sni_flag}{ciphers_count}{ext_count}{alpn_code}"

    sorted_ciphers_csv = ",".join(_hex4(c) for c in sorted(non_grease_ciphers))
    sorted_ext_csv = ",".join(_hex4(e) for e in sorted(hashable_extensions))
    sig_algs_csv = ",".join(_hex4(s) for s in hello.signature_algorithms if s not in GREASE_VALUES)
    if sorted_ext_csv and sig_algs_csv:
        ext_payload = f"{sorted_ext_csv}_{sig_algs_csv}"
    else:
        ext_payload = sorted_ext_csv or sig_algs_csv

    cipher_hash = _sha256_12(sorted_ciphers_csv)
    ext_hash = _sha256_12(ext_payload)

    return f"{preamble}_{cipher_hash}_{ext_hash}"
