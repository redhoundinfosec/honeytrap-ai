"""Tests for the response cache."""

from __future__ import annotations

import time

from honeytrap.ai.backends.base import ResponseResult
from honeytrap.ai.cache import ResponseCache


def _result(content: str = "ok") -> ResponseResult:
    return ResponseResult(
        content=content,
        latency_ms=1.0,
        tokens_used=0,
        backend_name="template",
        cached=False,
        shape_ok=True,
    )


def test_hit_miss_accounting() -> None:
    cache = ResponseCache()
    key = cache.key(protocol="http", inbound="GET /")
    assert cache.get(key) is None
    cache.set(key, _result())
    assert cache.get(key) is not None
    assert cache.stats.hits == 1
    assert cache.stats.misses == 1
    assert cache.stats.ratio == 0.5


def test_ttl_expiry() -> None:
    cache = ResponseCache(ttl_seconds=0.01)
    key = cache.key(protocol="ssh", inbound="whoami")
    cache.set(key, _result())
    time.sleep(0.03)
    assert cache.get(key) is None
    assert cache.stats.misses == 1


def test_http_key_normalization_case_and_whitespace() -> None:
    cache = ResponseCache()
    key1 = cache.key(protocol="http", inbound="GET /Index.html\r\n\r\n")
    key2 = cache.key(protocol="HTTP", inbound="get  /index.html")
    # http is case-folded; whitespace normalised
    assert key1 == key2
    cache.set(key1, _result("cached-body"))
    assert cache.get(key2) is not None


def test_ssh_is_case_sensitive() -> None:
    cache = ResponseCache()
    a = cache.key(protocol="ssh", inbound="RM -rf /")
    b = cache.key(protocol="ssh", inbound="rm -rf /")
    assert a != b


def test_memory_hash_distinguishes_snapshots() -> None:
    cache = ResponseCache()
    base_inbound = "whoami"
    a = cache.key(protocol="ssh", inbound=base_inbound, memory_snapshot="{turn:1}")
    b = cache.key(protocol="ssh", inbound=base_inbound, memory_snapshot="{turn:2}")
    assert a != b


def test_capacity_eviction() -> None:
    cache = ResponseCache(capacity=2)
    for i in range(3):
        cache.set(f"k{i}", _result(f"v{i}"))
    assert len(cache) == 2
    assert cache.get("k0") is None  # evicted as oldest
