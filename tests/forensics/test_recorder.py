"""Recorder + JSONL store coverage."""

from __future__ import annotations

from pathlib import Path

from honeytrap.forensics.recorder import (
    Direction,
    ForensicsConfig,
    JsonlSessionStore,
    SessionRecorder,
    _MetricSink,
    load_session_from_jsonl,
    serialize_jsonl,
)


def _open_recorder(tmp_path: Path, **cfg: object) -> tuple[SessionRecorder, JsonlSessionStore]:
    store = JsonlSessionStore(tmp_path)
    recorder = SessionRecorder(store, ForensicsConfig(path=str(tmp_path), **cfg))
    return recorder, store


def test_record_frame_monotonic_ordering(tmp_path: Path) -> None:
    rec, store = _open_recorder(tmp_path)
    rec.open_session(session_id="s1", protocol="ssh", remote_ip="1.2.3.4", remote_port=2222)
    times = []
    for i in range(5):
        f = rec.record_frame(
            session_id="s1",
            direction=Direction.INBOUND,
            payload=b"hello %d" % i,
            source_ip="1.2.3.4",
            source_port=2222,
            dest_ip="10.0.0.1",
            dest_port=22,
        )
        assert f is not None
        times.append(f.timestamp_ns)
    rec.close_session("s1")
    store.close()
    assert times == sorted(times)


def test_jsonl_store_writes_one_file_per_session(tmp_path: Path) -> None:
    rec, store = _open_recorder(tmp_path)
    rec.open_session(session_id="alpha", protocol="ssh", remote_ip="1.1.1.1", remote_port=22)
    rec.record_frame(
        session_id="alpha",
        direction=Direction.INBOUND,
        payload=b"data",
        source_ip="1.1.1.1",
        source_port=22,
        dest_ip="10.0.0.1",
        dest_port=22,
    )
    rec.close_session("alpha")
    store.close()
    files = list(tmp_path.rglob("*.jsonl.gz"))
    assert len(files) == 1
    assert files[0].name == "alpha.jsonl.gz"


def test_session_size_cap_triggers_truncation(tmp_path: Path) -> None:
    rec, store = _open_recorder(tmp_path, max_session_bytes=100)
    rec.open_session(session_id="big", protocol="x", remote_ip="2.2.2.2", remote_port=80)
    payload = b"x" * 60
    f1 = rec.record_frame(
        session_id="big",
        direction=Direction.INBOUND,
        payload=payload,
        source_ip="2.2.2.2",
        source_port=80,
        dest_ip="10.0.0.1",
        dest_port=80,
    )
    assert f1 is not None
    # second frame would exceed cap -> truncate path
    f2 = rec.record_frame(
        session_id="big",
        direction=Direction.INBOUND,
        payload=payload,
        source_ip="2.2.2.2",
        source_port=80,
        dest_ip="10.0.0.1",
        dest_port=80,
    )
    assert f2 is None
    meta = rec.metadata("big")
    assert meta is not None and meta.truncated is True
    assert meta.truncation_reason == "session_cap"
    rec.close_session("big")
    store.close()


def test_daily_cap_triggers_truncation(tmp_path: Path) -> None:
    rec, store = _open_recorder(tmp_path, max_daily_bytes=10)
    rec.open_session(session_id="d1", protocol="x", remote_ip="9.9.9.9", remote_port=80)
    f1 = rec.record_frame(
        session_id="d1",
        direction=Direction.INBOUND,
        payload=b"abc",
        source_ip="9.9.9.9",
        source_port=80,
        dest_ip="10.0.0.1",
        dest_port=80,
    )
    assert f1 is not None
    f2 = rec.record_frame(
        session_id="d1",
        direction=Direction.INBOUND,
        payload=b"x" * 20,
        source_ip="9.9.9.9",
        source_port=80,
        dest_ip="10.0.0.1",
        dest_port=80,
    )
    assert f2 is None
    assert rec.metadata("d1") is not None
    assert rec.metadata("d1").truncation_reason == "daily_cap"  # type: ignore[union-attr]
    rec.close_session("d1")
    store.close()


def test_guardian_pressure_disables_recording(tmp_path: Path) -> None:
    class Stats:
        should_refuse = True

    class Guardian:
        _stats = Stats()

    store = JsonlSessionStore(tmp_path)
    rec = SessionRecorder(store, ForensicsConfig(), guardian=Guardian())
    assert (
        rec.open_session(session_id="g1", protocol="x", remote_ip="1.1.1.1", remote_port=80) is None
    )
    assert (
        rec.record_frame(
            session_id="g1",
            direction=Direction.INBOUND,
            payload=b"x",
            source_ip="1.1.1.1",
            source_port=80,
            dest_ip="10.0.0.1",
            dest_port=80,
        )
        is None
    )
    store.close()


def test_restart_recovery_reads_back_frames(tmp_path: Path) -> None:
    rec, store = _open_recorder(tmp_path)
    rec.open_session(session_id="r1", protocol="ftp", remote_ip="3.3.3.3", remote_port=21)
    rec.record_frame(
        session_id="r1",
        direction=Direction.INBOUND,
        payload=b"USER admin\r\n",
        source_ip="3.3.3.3",
        source_port=21,
        dest_ip="10.0.0.1",
        dest_port=21,
    )
    rec.record_frame(
        session_id="r1",
        direction=Direction.OUTBOUND,
        payload=b"331 ok\r\n",
        source_ip="10.0.0.1",
        source_port=21,
        dest_ip="3.3.3.3",
        dest_port=21,
    )
    rec.close_session("r1")
    store.close()

    # Reopen and read
    store2 = JsonlSessionStore(tmp_path)
    sessions = store2.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].session_id == "r1"
    frames = store2.load_frames("r1")
    assert len(frames) == 2
    assert frames[0].payload == b"USER admin\r\n"
    assert frames[1].direction is Direction.OUTBOUND
    store2.close()


def test_serialize_jsonl_round_trip(tmp_path: Path) -> None:
    rec, store = _open_recorder(tmp_path)
    rec.open_session(session_id="rt", protocol="x", remote_ip="1.1.1.1", remote_port=80)
    rec.record_frame(
        session_id="rt",
        direction=Direction.INBOUND,
        payload=b"abcd",
        source_ip="1.1.1.1",
        source_port=80,
        dest_ip="10.0.0.1",
        dest_port=80,
    )
    rec.close_session("rt")
    store.close()
    paths = list(tmp_path.rglob("rt.jsonl.gz"))
    assert paths
    meta, frames = load_session_from_jsonl(paths[0])
    assert meta is not None and meta.session_id == "rt"
    assert frames and frames[0].payload == b"abcd"
    blob = serialize_jsonl(meta, frames)
    assert blob.startswith(b"\x1f\x8b")  # gzip magic


def test_metric_sink_fires_on_record_and_truncate(tmp_path: Path) -> None:
    counts = {"recorded": 0, "truncated": 0, "bytes": 0}

    def on_recorded(_proto: str) -> None:
        counts["recorded"] += 1

    def on_truncated(_reason: str) -> None:
        counts["truncated"] += 1

    def on_bytes(_proto: str, _dir: str, n: int) -> None:
        counts["bytes"] += n

    sink = _MetricSink(on_recorded=on_recorded, on_truncated=on_truncated, on_bytes=on_bytes)
    store = JsonlSessionStore(tmp_path)
    rec = SessionRecorder(store, ForensicsConfig(max_session_bytes=10), metrics=sink)
    rec.open_session(session_id="m1", protocol="x", remote_ip="1.1.1.1", remote_port=80)
    rec.record_frame(
        session_id="m1",
        direction=Direction.INBOUND,
        payload=b"abcd",
        source_ip="1.1.1.1",
        source_port=80,
        dest_ip="10.0.0.1",
        dest_port=80,
    )
    rec.record_frame(
        session_id="m1",
        direction=Direction.INBOUND,
        payload=b"x" * 100,
        source_ip="1.1.1.1",
        source_port=80,
        dest_ip="10.0.0.1",
        dest_port=80,
    )
    rec.close_session("m1")
    store.close()
    assert counts["recorded"] >= 1
    assert counts["truncated"] == 1
    assert counts["bytes"] >= 4


def test_disabled_recorder_records_nothing(tmp_path: Path) -> None:
    rec, store = _open_recorder(tmp_path)
    rec.disable()
    assert (
        rec.open_session(session_id="d", protocol="x", remote_ip="1.1.1.1", remote_port=22) is None
    )
    rec.enable()
    assert (
        rec.open_session(session_id="d", protocol="x", remote_ip="1.1.1.1", remote_port=22)
        is not None
    )
    rec.close_session("d")
    store.close()


def test_retention_sweep_removes_expired(tmp_path: Path) -> None:
    rec, store = _open_recorder(tmp_path, retention_days=1)
    rec.open_session(session_id="rs", protocol="x", remote_ip="1.1.1.1", remote_port=22)
    rec.close_session("rs")
    store.close()
    # Set the file mtime far in the past to look expired.
    paths = list(tmp_path.rglob("*.jsonl.gz"))
    assert paths
    import os

    very_old = 0
    os.utime(paths[0], (very_old, very_old))
    store2 = JsonlSessionStore(tmp_path)
    removed = store2.sweep_retention(1)
    assert removed == 1
    store2.close()
