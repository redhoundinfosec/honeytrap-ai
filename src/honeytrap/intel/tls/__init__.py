"""JA3 / JA4 TLS client fingerprinting.

Public surface::

    from honeytrap.intel.tls import (
        ClientHello,
        JA3Fingerprint,
        JA4Fingerprint,
        TLSFingerprinter,
        FingerprintDatabase,
    )
"""

from honeytrap.intel.tls.clienthello import ClientHello, parse_client_hello
from honeytrap.intel.tls.database import (
    FingerprintCategory,
    FingerprintConfidence,
    FingerprintDatabase,
    FingerprintDatabaseError,
    FingerprintEntry,
    Match,
)
from honeytrap.intel.tls.fingerprinter import FingerprintResult, TLSFingerprinter
from honeytrap.intel.tls.ja3 import JA3Fingerprint, compute_ja3
from honeytrap.intel.tls.ja4 import compute_ja4

# Historical naming: we expose ``JA4Fingerprint`` as an alias for the
# string-returning ``compute_ja4`` helper since JA4 is defined as a
# single canonical string rather than a string+hash pair.
JA4Fingerprint = str

__all__ = [
    "ClientHello",
    "FingerprintCategory",
    "FingerprintConfidence",
    "FingerprintDatabase",
    "FingerprintDatabaseError",
    "FingerprintEntry",
    "FingerprintResult",
    "JA3Fingerprint",
    "JA4Fingerprint",
    "Match",
    "TLSFingerprinter",
    "compute_ja3",
    "compute_ja4",
    "parse_client_hello",
]
