"""Benchmarks for the adaptive AI response cache.

Three operations are benchmarked: pure cache hits, pure cache misses,
and cache inserts under capacity-bounded eviction. The cache is keyed
by ``(protocol, normalized inbound, memory hash)`` so the benchmarks
build a representative key population to mirror real attacker flows.
"""

from __future__ import annotations

import pytest

from honeytrap.ai.backends.base import ResponseResult
from honeytrap.ai.cache import ResponseCache

pytestmark = pytest.mark.benchmark


def _result(text: str = "ok") -> ResponseResult:
    """Return a representative :class:`ResponseResult` for cache writes."""
    return ResponseResult(content=text, latency_ms=1.0, backend_name="bench")


def _populate(cache: ResponseCache, count: int) -> list[str]:
    """Pre-populate ``cache`` with ``count`` synthetic entries.

    Returns the canonical key list so tests can target exact keys.
    """
    keys: list[str] = []
    for i in range(count):
        key = cache.key(protocol="ssh", inbound=f"ls -la /var/{i}")
        cache.set(key, _result(f"r{i}"))
        keys.append(key)
    return keys


def test_bench_response_cache_hit(benchmark) -> None:
    """Steady-state hit benchmark: every lookup finds an entry."""
    cache = ResponseCache(capacity=10_000, ttl_seconds=3600)
    keys = _populate(cache, 1000)
    target = keys[500]

    def _hit() -> None:
        cache.get(target)

    benchmark(_hit)
    assert cache.stats.hits >= 1


def test_bench_response_cache_miss(benchmark) -> None:
    """Pure miss benchmark: lookups never find an entry."""
    cache = ResponseCache(capacity=10_000, ttl_seconds=3600)
    _populate(cache, 1000)
    miss_key = cache.key(protocol="ssh", inbound="missing-payload-xyz")

    def _miss() -> None:
        cache.get(miss_key)

    benchmark(_miss)
    assert cache.stats.misses >= 1


def test_bench_response_cache_insert(benchmark) -> None:
    """Insert benchmark with eviction pressure (small capacity)."""
    cache = ResponseCache(capacity=128, ttl_seconds=3600)
    counter = {"i": 0}

    def _insert() -> None:
        counter["i"] += 1
        i = counter["i"]
        key = cache.key(protocol="http", inbound=f"GET /probe/{i} HTTP/1.1")
        cache.set(key, _result(f"r{i}"))

    benchmark(_insert)
    assert len(cache) <= cache.capacity


def test_bench_response_cache_key_compute(benchmark) -> None:
    """Key derivation benchmark: hashing + normalisation cost."""
    cache = ResponseCache()

    def _build() -> str:
        return cache.key(
            protocol="http",
            inbound="GET /admin/login.php HTTP/1.1\r\nHost: example",
            memory_snapshot="snap-12345",
        )

    key = benchmark(_build)
    assert isinstance(key, str)
