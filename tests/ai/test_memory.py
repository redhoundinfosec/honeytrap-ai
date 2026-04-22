"""Tests for the session-memory store."""

from __future__ import annotations

import time

from honeytrap.ai.memory import (
    InMemoryStore,
    SessionMemory,
    SqliteMemoryStore,
    build_store,
)


def test_get_or_create_returns_same_object() -> None:
    store = InMemoryStore()
    a = store.get_or_create("s1", "1.2.3.4")
    b = store.get_or_create("s1", "1.2.3.4")
    assert a is b
    a.record_command("whoami", protocol="ssh")
    assert b.turn_count == 1


def test_lru_eviction_under_cap() -> None:
    store = InMemoryStore(cap_ips=2, cap_sessions_per_ip=1)
    store.get_or_create("s1", "10.0.0.1")
    store.get_or_create("s2", "10.0.0.2")
    store.get_or_create("s3", "10.0.0.3")
    # oldest IP (10.0.0.1) should be gone
    assert store.find_by_ip("10.0.0.1") == []
    assert store.find_by_ip("10.0.0.3")
    assert store.evictions() >= 1


def test_find_by_ip_aggregates_sessions() -> None:
    store = InMemoryStore(cap_sessions_per_ip=5)
    store.get_or_create("s1", "1.1.1.1")
    store.get_or_create("s2", "1.1.1.1")
    store.get_or_create("sX", "9.9.9.9")
    matches = store.find_by_ip("1.1.1.1")
    assert {m.session_id for m in matches} == {"s1", "s2"}


def test_sqlite_store_roundtrips_and_survives_reopen(tmp_path) -> None:
    db = tmp_path / "mem.sqlite3"
    store = SqliteMemoryStore(db)
    mem = store.get_or_create("s1", "8.8.8.8")
    mem.record_command("whoami", protocol="ssh")
    mem.add_ioc("ip", "8.8.8.8")
    store.update(mem)
    store.close()

    reopened = SqliteMemoryStore(db)
    found = reopened.get_or_create("s1", "8.8.8.8")
    assert found.turn_count == 1
    assert "whoami" in found.command_history
    assert found.iocs["ip"] == ["8.8.8.8"]
    reopened.close()


def test_build_store_factory_dispatch(tmp_path) -> None:
    sqlite_store = build_store("sqlite", state_dir=tmp_path)
    assert isinstance(sqlite_store, SqliteMemoryStore)
    mem_store = build_store("memory", state_dir=tmp_path, cap_ips=3)
    assert isinstance(mem_store, InMemoryStore)
    assert mem_store.cap_ips == 3
    sqlite_store.close()


def test_session_memory_serialises_sets() -> None:
    mem = SessionMemory(session_id="s1", source_ip="1.2.3.4")
    mem.user_agents.add("curl/8.1")
    mem.sni_domains.add("victim.example")
    data = mem.to_dict()
    assert data["user_agents"] == ["curl/8.1"]
    assert data["sni_domains"] == ["victim.example"]
    assert data["intent"] is None
    rebuilt = SessionMemory.from_dict(data)
    assert rebuilt.user_agents == {"curl/8.1"}


def test_eviction_counter_increments() -> None:
    store = InMemoryStore(cap_ips=1, cap_sessions_per_ip=1)
    store.get_or_create("s1", "10.0.0.1")
    store.get_or_create("s2", "10.0.0.2")
    # first IP evicted
    assert store.evictions() == 1
    # session evicted within same IP
    store.get_or_create("s3", "10.0.0.2")
    assert store.evictions() == 2


def test_record_backend_updates_timestamps() -> None:
    mem = SessionMemory(session_id="s1", source_ip="1.2.3.4")
    before = mem.last_seen_ts
    time.sleep(0.01)
    mem.record_backend("template", 12.3)
    assert mem.backend_usage["template"] == 1
    assert mem.last_backend_latency_ms == 12.3
    assert mem.last_seen_ts >= before
