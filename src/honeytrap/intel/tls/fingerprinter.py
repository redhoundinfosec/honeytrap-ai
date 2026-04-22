"""Top-level orchestrator turning raw TLS bytes into a fingerprint record."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from honeytrap.intel.tls.clienthello import ClientHello, parse_client_hello
from honeytrap.intel.tls.database import FingerprintDatabase, Match
from honeytrap.intel.tls.ja3 import JA3Fingerprint, compute_ja3
from honeytrap.intel.tls.ja4 import compute_ja4

logger = logging.getLogger(__name__)

_CACHE_MAX = 512


@dataclass(frozen=True)
class FingerprintResult:
    """End-to-end TLS fingerprint + lookup result."""

    ja3: str
    ja3_str: str
    ja4: str
    client_hello: ClientHello
    matches: tuple[Match, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation for event records."""
        return {
            "ja3": self.ja3,
            "ja3_str": self.ja3_str,
            "ja4": self.ja4,
            "sni": self.client_hello.server_name,
            "alpn": list(self.client_hello.alpn_protocols),
            "version": self.client_hello.highest_version(),
            "matches": [m.to_dict() for m in self.matches],
        }


class TLSFingerprinter:
    """Parses ClientHellos, computes JA3/JA4, and looks up a database."""

    def __init__(self, database: FingerprintDatabase | None = None) -> None:
        """Create a fingerprinter backed by ``database`` (default: bundled)."""
        self.database = database or FingerprintDatabase.default()
        # Bound the cache; callers hit it with repeat ClientHellos from
        # reconnecting scanners and the cost of the parse + hash is
        # non-trivial under load.
        self._cached_from_bytes = lru_cache(maxsize=_CACHE_MAX)(self._compute_from_bytes_uncached)

    def fingerprint(self, raw: bytes) -> FingerprintResult | None:
        """Fingerprint raw ClientHello bytes.

        ``raw`` may include the TLS record header or be the bare
        handshake. Returns ``None`` if the bytes do not contain a
        valid ClientHello.
        """
        if not raw:
            return None
        key = hashlib.sha256(raw).digest()
        return self._cached_from_bytes(key, raw)

    def _compute_from_bytes_uncached(
        self, _cache_key: bytes, raw: bytes
    ) -> FingerprintResult | None:
        hello = parse_client_hello(raw)
        if hello is None:
            return None
        return self.from_client_hello(hello)

    def from_client_hello(self, hello: ClientHello) -> FingerprintResult:
        """Compute JA3/JA4 and look up matches for an already-parsed hello."""
        ja3: JA3Fingerprint = compute_ja3(hello)
        ja4_str = compute_ja4(hello)
        matches = tuple(self.database.lookup(ja3=ja3.ja3_hash, ja4=ja4_str))
        return FingerprintResult(
            ja3=ja3.ja3_hash,
            ja3_str=ja3.ja3_string,
            ja4=ja4_str,
            client_hello=hello,
            matches=matches,
        )

    def cache_clear(self) -> None:
        """Clear the internal LRU cache (mostly used in tests)."""
        self._cached_from_bytes.cache_clear()

    def cache_info(self) -> Any:
        """Return the underlying LRU cache info."""
        return self._cached_from_bytes.cache_info()
