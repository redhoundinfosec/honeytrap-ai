"""JA3 TLS client fingerprinting.

Per the reference implementation at https://github.com/salesforce/ja3
the JA3 string is::

    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

Each section is a dash-separated list of decimal integers. GREASE
values (RFC 8701) are removed before hashing. The final fingerprint
is the lowercase hex MD5 of the UTF-8 encoded string.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from honeytrap.intel.tls.clienthello import GREASE_VALUES, ClientHello


@dataclass(frozen=True)
class JA3Fingerprint:
    """A JA3 fingerprint in both raw string and MD5 hash forms."""

    ja3_string: str
    ja3_hash: str


def _join_nongrease(values: tuple[int, ...]) -> str:
    return "-".join(str(v) for v in values if v not in GREASE_VALUES)


def compute_ja3(hello: ClientHello) -> JA3Fingerprint:
    """Compute the JA3 fingerprint for a parsed :class:`ClientHello`."""
    version = hello.legacy_version
    ciphers = _join_nongrease(hello.cipher_suites)
    extensions = _join_nongrease(hello.extensions)
    curves = _join_nongrease(hello.supported_groups)
    point_formats = "-".join(str(v) for v in hello.ec_point_formats if v not in GREASE_VALUES)
    ja3_string = f"{version},{ciphers},{extensions},{curves},{point_formats}"
    ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()
    return JA3Fingerprint(ja3_string=ja3_string, ja3_hash=ja3_hash)
