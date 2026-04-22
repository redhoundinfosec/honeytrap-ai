"""Cardinality-bounded metric emitter for TLS fingerprints.

Prometheus labels have unbounded cardinality in principle, which can
blow up scrape payloads when attackers rotate through thousands of
JA3s. This helper keeps a rolling set of the most-seen (up to
``max_labels``) fingerprints; anything beyond that is collapsed into
``name="other"`` so the time series stays tractable.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Protocol

DEFAULT_MAX_LABELS: int = 100


class _Counter(Protocol):
    def inc_counter(
        self, name: str, value: float = 1.0, labels: dict[str, str] | None = None
    ) -> None: ...


class BoundedFingerprintMetrics:
    """Emit JA3 fingerprint counters with a bounded label set."""

    def __init__(self, registry: _Counter, *, max_labels: int = DEFAULT_MAX_LABELS) -> None:
        """Wrap ``registry`` so only the top ``max_labels`` JA3s keep unique labels."""
        self._registry = registry
        self._max = int(max_labels)
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def observe(
        self,
        *,
        ja3: str,
        category: str = "unknown",
        name: str = "unknown",
    ) -> None:
        """Increment the TLS fingerprint counter for one observation."""
        ja3_key = (ja3 or "unknown").lower()
        with self._lock:
            if ja3_key in self._seen:
                self._seen.move_to_end(ja3_key)
                labels = {"ja3_hash": ja3_key, "category": category, "name": name}
            elif len(self._seen) < self._max:
                self._seen[ja3_key] = None
                labels = {"ja3_hash": ja3_key, "category": category, "name": name}
            else:
                labels = {"ja3_hash": "other", "category": category, "name": "other"}
        self._registry.inc_counter("honeytrap_tls_fingerprint_total", labels=labels)

    def reset(self) -> None:
        """Forget the tracked label set. Mostly used in tests."""
        with self._lock:
            self._seen.clear()

    def snapshot(self) -> list[str]:
        """Return the currently tracked JA3 labels for diagnostic use."""
        with self._lock:
            return list(self._seen.keys())


def observe_fingerprint_event(
    metrics: BoundedFingerprintMetrics | None, fp: dict[str, Any]
) -> None:
    """Emit fingerprint metrics for a single event's ``tls_fingerprint`` block."""
    if metrics is None or not fp:
        return
    ja3 = str(fp.get("ja3") or "")
    matches = fp.get("matches") or []
    if matches:
        first = matches[0]
        metrics.observe(
            ja3=ja3,
            category=str(first.get("category") or "unknown"),
            name=str(first.get("name") or "unknown"),
        )
    else:
        metrics.observe(ja3=ja3, category="unknown", name="unknown")
