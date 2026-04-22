"""SQLite store coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from honeytrap.forensics.recorder import (
    Direction,
    SessionFrame,
    SessionMetadata,
    SqliteSessionStore,
)


def _meta(sid: str = "s1", ip: str = "1.1.1.1") -> SessionMetadata:
    return SessionMetadata(
        session_id=sid,
        protocol="ssh",
        remote_ip=ip,
        remote_port=2222,
        local_ip="10.0.0.1",
        local_port=22,
    )


def _frame(sid: str, ts: int, payload: bytes, direction: Direction) -> SessionFrame:
    return SessionFrame(
        session_id=sid,
        timestamp_ns=ts,
        direction=direction,
        payload=payload,
        source_ip="1.1.1.1",
        source_port=2222,
        dest_ip="10.0.0.1",
        dest_port=22,
        protocol="ssh",
    )


def test_wal_mode_enabled(tmp_path: Path) -> None:
    store = SqliteSessionStore(tmp_path / "f.db")
    assert store.journal_mode().lower() == "wal"
    store.close()


def test_open_append_close_round_trip(tmp_path: Path) -> None:
    store = SqliteSessionStore(tmp_path / "f.db")
    meta = _meta()
    store.open_session(meta)
    store.append_frame(_frame("s1", 100, b"abcd", Direction.INBOUND))
    store.append_frame(_frame("s1", 200, b"reply", Direction.OUTBOUND))
    meta.ended_at = datetime.now(timezone.utc)
    store.close_session(meta)
    sessions = store.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].frame_count == 2
    assert sessions[0].bytes_in == 4
    assert sessions[0].bytes_out == 5
    frames = store.load_frames("s1")
    assert [f.payload for f in frames] == [b"abcd", b"reply"]
    store.close()


def test_list_filters_by_ip_and_window(tmp_path: Path) -> None:
    store = SqliteSessionStore(tmp_path / "f.db")
    a = _meta("a", "1.1.1.1")
    b = _meta("b", "2.2.2.2")
    store.open_session(a)
    store.open_session(b)
    a.ended_at = datetime.now(timezone.utc)
    b.ended_at = datetime.now(timezone.utc)
    store.close_session(a)
    store.close_session(b)
    only_a = store.list_sessions(ip="1.1.1.1")
    assert [m.session_id for m in only_a] == ["a"]
    future = datetime.now(timezone.utc) + timedelta(days=1)
    none = store.list_sessions(since=future)
    assert none == []
    store.close()


def test_get_metadata_returns_none_for_unknown(tmp_path: Path) -> None:
    store = SqliteSessionStore(tmp_path / "f.db")
    assert store.get_metadata("nope") is None
    store.close()


def test_sweep_retention_removes_old_sessions(tmp_path: Path) -> None:
    store = SqliteSessionStore(tmp_path / "f.db")
    old = _meta("old", "1.1.1.1")
    old.started_at = datetime.now(timezone.utc) - timedelta(days=10)
    store.open_session(old)
    store.append_frame(_frame("old", 1, b"xx", Direction.INBOUND))
    store.close_session(old)
    new = _meta("new", "2.2.2.2")
    store.open_session(new)
    store.close_session(new)
    removed = store.sweep_retention(1)
    assert removed == 1
    assert {m.session_id for m in store.list_sessions()} == {"new"}
    store.close()
