"""Tests for ``honeytrap.cluster.controller_fleet``."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from honeytrap.cluster.controller_fleet import (
    Fleet,
    NodeRecord,
    _redact_snapshot,
)
from tests.cluster.conftest import event


def _build_fleet(tmp_path: Path) -> Fleet:
    return Fleet(tmp_path / "fleet.db", heartbeat_interval=10.0)


def test_register_node_returns_record(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    rec = f.register_node(name="edge-01", role="node", version="1.0.0", profile="web_server")
    assert isinstance(rec, NodeRecord)
    assert rec.status == "online"
    assert rec.profile == "web_server"


def test_register_node_assigns_uuid_when_missing(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    rec = f.register_node(name="x", role="node", version="1")
    assert rec.node_id


def test_register_idempotent_preserves_registered_at(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    first = f.register_node(name="x", role="node", version="1", node_id="alpha")
    second = f.register_node(name="x2", role="node", version="2", node_id="alpha")
    assert first.node_id == "alpha"
    assert second.registered_at == first.registered_at
    assert second.version == "2"


def test_deregister_returns_false_for_unknown(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    assert f.deregister_node("ghost") is False


def test_deregister_removes_node(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    rec = f.register_node(name="x", role="node", version="1", node_id="alpha")
    assert f.deregister_node(rec.node_id) is True
    assert f.get_node(rec.node_id) is None


def test_record_heartbeat_returns_false_for_unknown(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    assert f.record_heartbeat("ghost", {"uptime": 1}) is False


def test_record_heartbeat_redacts_secrets(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    rec = f.register_node(name="x", role="node", version="1", node_id="alpha")
    assert f.record_heartbeat(rec.node_id, {"uptime": 1, "api_key": "leaked"})
    found = f.get_node(rec.node_id)
    assert found is not None
    assert found.health.get("api_key") == "<redacted>"
    assert found.health.get("uptime") == 1


def test_mark_offline_if_stale(tmp_path: Path) -> None:
    f = Fleet(tmp_path / "fleet.db", heartbeat_interval=0.001)
    rec = f.register_node(name="x", role="node", version="1", node_id="alpha")
    f.record_heartbeat(rec.node_id, {"uptime": 1})
    # Force last_heartbeat well into the past so the second-resolution
    # timestamp comparison reliably trips.
    long_ago = (
        (datetime.now(tz=timezone.utc) - timedelta(minutes=5)).replace(microsecond=0).isoformat()
    )
    f._conn.execute(  # noqa: SLF001
        "UPDATE nodes SET last_heartbeat = ? WHERE node_id = ?",
        (long_ago, rec.node_id),
    )
    flipped = f.mark_offline_if_stale(multiplier=1.0)
    assert flipped == 1
    found = f.get_node(rec.node_id)
    assert found is not None
    assert found.status == "offline"


def test_ingest_rejects_missing_required_keys(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="x", role="node", version="1", node_id="n")
    accepted, rejected = f.ingest_events_batch(
        "n", [{"ts": "2026-04-27T00:00:00Z", "protocol": "ssh"}]
    )
    assert accepted == 0 and rejected == 1


def test_ingest_rejects_non_dicts(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="x", role="node", version="1", node_id="n")
    accepted, rejected = f.ingest_events_batch("n", ["bad", 123, None])  # type: ignore[list-item]
    assert accepted == 0 and rejected == 3


def test_ingest_rejects_oversized_payload(tmp_path: Path) -> None:
    f = Fleet(tmp_path / "fleet.db", max_event_payload_bytes=200)
    f.register_node(name="x", role="node", version="1", node_id="n")
    big = event(extra={"blob": "A" * 1024})
    accepted, rejected = f.ingest_events_batch("n", [big])
    assert accepted == 0 and rejected == 1


def test_ingest_caps_max_events_per_batch(tmp_path: Path) -> None:
    f = Fleet(tmp_path / "fleet.db", max_events_per_batch=3)
    f.register_node(name="x", role="node", version="1", node_id="n")
    events = [event(session_id=f"s{i}") for i in range(10)]
    accepted, rejected = f.ingest_events_batch("n", events)
    assert accepted == 3
    assert rejected == 0


def test_ingest_handles_non_list(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="x", role="node", version="1", node_id="n")
    accepted, rejected = f.ingest_events_batch("n", {"not": "list"})  # type: ignore[arg-type]
    assert accepted == 0 and rejected == 0


def test_query_filters_by_protocol_and_ip(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="x", role="node", version="1", node_id="n")
    events = [
        event(protocol="ssh", src_ip="1.1.1.1", session_id="s1"),
        event(protocol="http", src_ip="2.2.2.2", session_id="s2"),
        event(protocol="ssh", src_ip="2.2.2.2", session_id="s3"),
    ]
    f.ingest_events_batch("n", events)
    by_proto = f.query_events(protocol="ssh", limit=10)
    assert len(by_proto) == 2
    by_ip = f.query_events(src_ip="2.2.2.2", limit=10)
    assert len(by_ip) == 2


def test_query_filters_by_node_id_and_time(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="a", role="node", version="1", node_id="n1")
    f.register_node(name="b", role="node", version="1", node_id="n2")
    f.ingest_events_batch("n1", [event(ts="2026-01-01T00:00:00Z")])
    f.ingest_events_batch("n2", [event(ts="2026-12-31T00:00:00Z")])
    one = f.query_events(node_id="n1", limit=10)
    assert len(one) == 1
    after = f.query_events(since="2026-06-01T00:00:00Z", limit=10)
    assert len(after) == 1
    before = f.query_events(until="2026-06-01T00:00:00Z", limit=10)
    assert len(before) == 1


def test_query_limit_cap_clamps(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="x", role="node", version="1", node_id="n")
    f.ingest_events_batch("n", [event(session_id=f"s{i}") for i in range(20)])
    rows = f.query_events(limit=5000)
    assert len(rows) == 20
    rows = f.query_events(limit=0)
    assert len(rows) >= 1


def test_aggregate_top_attackers_orders_correctly(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="x", role="node", version="1", node_id="n")
    seq = (
        [event(src_ip="9.9.9.9")] * 5
        + [event(src_ip="8.8.8.8")] * 3
        + [event(src_ip="7.7.7.7")] * 1
    )
    f.ingest_events_batch("n", seq)
    top = f.aggregate_top_attackers(limit=5)
    assert top[0]["src_ip"] == "9.9.9.9"
    assert top[0]["count"] == 5
    assert top[-1]["src_ip"] == "7.7.7.7"


def test_aggregate_mitre_heatmap(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="x", role="node", version="1", node_id="n")
    f.ingest_events_batch(
        "n",
        [
            event(technique="T1110"),
            event(technique="T1110"),
            event(technique="T1059"),
        ],
    )
    rows = f.aggregate_mitre_heatmap()
    counts = {r["technique"]: r["count"] for r in rows}
    assert counts == {"T1110": 2, "T1059": 1}


def test_aggregate_sessions_per_node(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="a", role="node", version="1", node_id="n1")
    f.register_node(name="b", role="node", version="1", node_id="n2")
    f.ingest_events_batch(
        "n1",
        [
            event(session_id="x", protocol="ssh"),
            event(session_id="x", protocol="ssh"),
            event(session_id="y", protocol="ssh"),
        ],
    )
    f.ingest_events_batch(
        "n2",
        [event(session_id="z", protocol="http")],
    )
    rows = f.aggregate_sessions_per_node()
    by_pair = {(r["node_id"], r["protocol"]): r for r in rows}
    assert by_pair[("n1", "ssh")]["sessions"] == 2
    assert by_pair[("n2", "http")]["sessions"] == 1


def test_generation_counter_increments(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    g0 = f.generation
    f.register_node(name="x", role="node", version="1", node_id="alpha")
    g1 = f.generation
    f.deregister_node("alpha")
    g2 = f.generation
    assert g2 > g1 > g0


def test_redact_snapshot_handles_lists_and_nested() -> None:
    out = _redact_snapshot(
        {
            "items": [{"password": "x"}, {"safe": 1}],
            "token": "secret",
        }
    )
    assert out["token"] == "<redacted>"
    assert out["items"][0]["password"] == "<redacted>"
    assert out["items"][1]["safe"] == 1


def test_redact_snapshot_passthrough_for_scalars() -> None:
    assert _redact_snapshot(7) == 7
    assert _redact_snapshot("hello") == "hello"


def test_close_is_safe_to_call_twice(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.close()
    f.close()


def test_health_falls_back_to_empty_when_corrupt(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    rec = f.register_node(name="x", role="node", version="1", node_id="alpha")
    # Corrupt the snapshot row directly via the connection.
    f._conn.execute(  # noqa: SLF001
        "INSERT INTO node_health(node_id, ts, snapshot) VALUES(?,?,?)",
        (
            rec.node_id,
            datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat(),
            "{not json",
        ),
    )
    found = f.get_node(rec.node_id)
    assert found is not None
    assert found.health == {}


def test_list_nodes_returns_records_sorted(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="a", role="node", version="1", node_id="alpha")
    # Backdate the first registration so newest-first ordering is unambiguous
    # at the second-resolution timestamps used by the schema.
    earlier = (
        (datetime.now(tz=timezone.utc) - timedelta(seconds=5)).replace(microsecond=0).isoformat()
    )
    f._conn.execute(  # noqa: SLF001
        "UPDATE nodes SET registered_at = ? WHERE node_id = ?",
        (earlier, "alpha"),
    )
    f.register_node(name="b", role="node", version="1", node_id="beta")
    rows = f.list_nodes()
    assert [r.node_id for r in rows][0] == "beta"


def test_query_events_metadata_present(tmp_path: Path) -> None:
    f = _build_fleet(tmp_path)
    f.register_node(name="x", role="node", version="1", node_id="n")
    f.ingest_events_batch("n", [event(extra={"username": "root"})])
    rows = f.query_events(limit=1)
    assert rows[0]["node_id"] == "n"
    assert rows[0]["username"] == "root"


def test_stale_with_no_heartbeat_marks_offline(tmp_path: Path) -> None:
    f = Fleet(tmp_path / "fleet.db", heartbeat_interval=0.001)
    f.register_node(name="x", role="node", version="1", node_id="alpha")
    # Force last_heartbeat well into the past via direct update.
    long_ago = (
        (datetime.now(tz=timezone.utc) - timedelta(hours=1)).replace(microsecond=0).isoformat()
    )
    f._conn.execute(  # noqa: SLF001
        "UPDATE nodes SET last_heartbeat = ? WHERE node_id = ?",
        (long_ago, "alpha"),
    )
    flipped = f.mark_offline_if_stale(multiplier=1.0)
    assert flipped == 1
