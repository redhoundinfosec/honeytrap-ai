"""LRU response cache for the adaptive AI layer.

The cache is keyed by ``(protocol, normalized_inbound, memory_hash_short)``
so repeated probes — very common in real attacker scripts — can be served
the same canned response without paying the LLM/template cost twice.

Normalization rules:

* Whitespace collapsed to single spaces and stripped.
* HTTP keys are lower-cased (the protocol is case-insensitive on headers
  and tokens, so this matches attacker behavior). Other protocols leave
  the byte payload alone so we don't hide meaningful casing differences
  (SSH command ``RM -rf`` is not the same as ``rm -rf``).

The cache is explicitly strict on key equality — we intentionally avoid
fuzzy matching because a wrong hit would produce an implausible response.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from honeytrap.ai.backends.base import ResponseResult

_WS_RE = re.compile(r"\s+")


@dataclass
class CacheStats:
    """Simple hit/miss counters for the metrics endpoint."""

    hits: int = 0
    misses: int = 0

    @property
    def ratio(self) -> float:
        """Return the hit/(hit+miss) ratio or 0.0 when empty."""
        total = self.hits + self.misses
        return (self.hits / total) if total else 0.0


class ResponseCache:
    """TTL-aware LRU cache keyed by ``(protocol, inbound, memory)``."""

    def __init__(self, *, capacity: int = 5_000, ttl_seconds: float = 1_800.0) -> None:
        """Create an empty cache with the given capacity and TTL."""
        self.capacity = max(1, int(capacity))
        self.ttl = float(ttl_seconds)
        self._lock = threading.Lock()
        self._store: OrderedDict[str, tuple[float, ResponseResult]] = OrderedDict()
        self.stats = CacheStats()

    def _normalize(self, protocol: str, inbound: str | bytes) -> str:
        if isinstance(inbound, bytes):
            try:
                inbound = inbound.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                inbound = inbound.decode("latin-1", errors="replace")
        text = _WS_RE.sub(" ", inbound).strip()
        if protocol.lower() in {"http", "https"}:
            text = text.lower()
        return text

    def _memory_hash(self, memory_snapshot: str | None) -> str:
        if not memory_snapshot:
            return "0"
        digest = hashlib.blake2b(memory_snapshot.encode("utf-8"), digest_size=8).hexdigest()
        return digest

    def key(
        self,
        *,
        protocol: str,
        inbound: str | bytes,
        memory_snapshot: str | None = None,
    ) -> str:
        """Compute the canonical cache key for ``(protocol, inbound, memory)``."""
        return f"{protocol.lower()}::{self._memory_hash(memory_snapshot)}::{self._normalize(protocol, inbound)}"

    def get(self, key: str) -> ResponseResult | None:
        """Return the cached result or ``None`` if missing/expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            ts, value = entry
            if time.time() - ts > self.ttl:
                self._store.pop(key, None)
                self.stats.misses += 1
                return None
            self._store.move_to_end(key)
            self.stats.hits += 1
            return value

    def set(self, key: str, value: ResponseResult) -> None:
        """Store ``value`` at ``key``, evicting the oldest entry if full."""
        with self._lock:
            self._store[key] = (time.time(), value)
            self._store.move_to_end(key)
            while len(self._store) > self.capacity:
                self._store.popitem(last=False)

    def clear(self) -> None:
        """Empty the cache and reset stats."""
        with self._lock:
            self._store.clear()
            self.stats = CacheStats()

    def __len__(self) -> int:
        """Return the current number of cached entries."""
        with self._lock:
            return len(self._store)
