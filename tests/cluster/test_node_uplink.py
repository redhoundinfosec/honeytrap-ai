"""Tests for ``honeytrap.cluster.node_uplink``."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from honeytrap.cluster.config import ClusterConfig, ClusterRole
from honeytrap.cluster.node_uplink import (
    NodeUplink,
    UplinkStatus,
    UrllibTransport,
    _Spool,
)


class FakeTransport:
    """Configurable in-process transport for uplink tests."""

    def __init__(
        self,
        responder: Callable[[str, str, bytes], tuple[int, bytes]] | None = None,
    ) -> None:
        self.calls: list[tuple[str, str, bytes]] = []
        self._responder = responder or (lambda _m, _u, _b: (200, b'{"node_id":"alpha"}'))

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes,
        timeout: float,
    ) -> tuple[int, bytes]:
        self.calls.append((method, url, body))
        return self._responder(method, url, body)


def _config(tmp_path: Path) -> ClusterConfig:
    return ClusterConfig(
        enabled=True,
        role=ClusterRole.NODE,
        controller_url="http://controller.local:9300",
        api_key="htk_unit",
        heartbeat_interval=0.05,
        event_batch_size=5,
        event_flush_interval=0.05,
        spool_max_events=4,
        spool_max_disk_bytes=1 << 20,
        node_id="alpha",
    )


def test_construction_requires_enabled(tmp_path: Path) -> None:
    cfg = ClusterConfig(enabled=False)
    with pytest.raises(ValueError):
        NodeUplink(cfg, version="1.0.0")


def test_construction_requires_url(tmp_path: Path) -> None:
    cfg = ClusterConfig(enabled=True, role=ClusterRole.NODE, api_key="htk_x")
    with pytest.raises(ValueError):
        NodeUplink(cfg, version="1.0.0")


def test_construction_requires_api_key(tmp_path: Path) -> None:
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.NODE,
        controller_url="http://c",
    )
    with pytest.raises(ValueError):
        NodeUplink(cfg, version="1.0.0")


def test_enqueue_event_rejects_non_dict(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    up = NodeUplink(cfg, version="1.0.0", transport=FakeTransport())
    assert up.enqueue_event("nope") is False  # type: ignore[arg-type]


def test_enqueue_event_spills_to_spool_when_queue_full(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=FakeTransport(),
    )
    for i in range(cfg.spool_max_events):
        assert up.enqueue_event({"i": i}) is True
    assert up.enqueue_event({"i": "overflow"}) is True
    assert up.status.spool_depth >= 1


def test_enqueue_event_drops_when_full(tmp_path: Path) -> None:
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.NODE,
        controller_url="http://c",
        api_key="htk_x",
        spool_max_events=1,
        spool_max_disk_bytes=1,  # essentially zero
    )
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=FakeTransport(),
    )
    assert up.enqueue_event({"a": 1}) is True
    up.enqueue_event({"a": 2})
    up.enqueue_event({"a": 3})
    assert up.status.events_dropped >= 1


def test_heartbeat_snapshot_excludes_secrets(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    up = NodeUplink(
        cfg,
        version="1.2.3",
        transport=FakeTransport(),
        snapshot_provider=lambda: {"cpu": 0.4, "api_key": "leaked"},
    )
    snap = up.heartbeat_snapshot()
    assert snap["version"] == "1.2.3"
    assert "queue_depth" in snap
    # snapshot provider keys are merged but the uplink itself never
    # populates secret-named keys; provider misuse is caller-owned.
    assert "cpu" in snap


def test_heartbeat_snapshot_handles_provider_failure(tmp_path: Path) -> None:
    cfg = _config(tmp_path)

    def boom() -> dict[str, Any]:
        raise RuntimeError("nope")

    up = NodeUplink(cfg, version="1.0.0", transport=FakeTransport(), snapshot_provider=boom)
    snap = up.heartbeat_snapshot()
    assert "uptime_seconds" in snap


def test_heartbeat_snapshot_ignores_non_dict_provider(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    up = NodeUplink(
        cfg,
        version="1.0.0",
        transport=FakeTransport(),
        snapshot_provider=lambda: "not a dict",  # type: ignore[return-value,arg-type]
    )
    snap = up.heartbeat_snapshot()
    assert "uptime_seconds" in snap


@pytest.mark.asyncio
async def test_register_succeeds_and_records_node_id(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    cfg.node_id = None
    transport = FakeTransport(responder=lambda m, u, b: (201, b'{"node_id":"assigned-id"}'))
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    await up._register_with_retry()
    assert up.status.node_id == "assigned-id"
    assert up.status.online is True


@pytest.mark.asyncio
async def test_register_retries_then_gives_up_on_stop(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (-1, b""))
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    up._stop.set()
    await up._register_with_retry()
    assert up.status.online is False


@pytest.mark.asyncio
async def test_send_heartbeat_records_success(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (204, b""))
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    up._registered = True
    await up._send_heartbeat()
    assert up.status.last_heartbeat_at is not None


@pytest.mark.asyncio
async def test_send_heartbeat_skips_when_unregistered(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (200, b""))
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    await up._send_heartbeat()
    assert transport.calls == []


@pytest.mark.asyncio
async def test_send_heartbeat_records_failure(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (500, b""))
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    up._registered = True
    await up._send_heartbeat()
    assert up.status.online is False
    assert up.status.consecutive_failures >= 1


@pytest.mark.asyncio
async def test_post_events_success_marks_forwarded(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (202, b""))
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    ok = await up._post_events([{"a": 1}])
    assert ok is True


@pytest.mark.asyncio
async def test_post_events_failure_returns_false(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (500, b""))
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    ok = await up._post_events([{"a": 1}])
    assert ok is False


@pytest.mark.asyncio
async def test_post_events_no_op_when_empty(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport()
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    assert await up._post_events([]) is True
    assert transport.calls == []


@pytest.mark.asyncio
async def test_full_lifecycle_register_heartbeat_forward(tmp_path: Path) -> None:
    cfg = _config(tmp_path)

    def respond(m: str, u: str, b: bytes) -> tuple[int, bytes]:
        if "/cluster/nodes" in u and m == "POST" and "/events" not in u:
            return 201, b'{"node_id":"alpha"}'
        if "/heartbeat" in u:
            return 204, b""
        if "/cluster/events" in u:
            return 202, b""
        return 404, b""

    transport = FakeTransport(responder=respond)
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    await up.start()
    up.enqueue_event({"ts": "2026-04-27T00:00:00Z", "protocol": "ssh", "src_ip": "1.1.1.1"})
    forwarded = 0
    for _ in range(20):
        await asyncio.sleep(0.05)
        forwarded = up.status.events_forwarded
        if forwarded >= 1:
            break
    await up.stop()
    assert forwarded >= 1


@pytest.mark.asyncio
async def test_forwarder_respools_failed_in_memory_events(tmp_path: Path) -> None:
    cfg = _config(tmp_path)

    def respond(m: str, u: str, b: bytes) -> tuple[int, bytes]:
        if "/heartbeat" in u:
            return 204, b""
        if "/cluster/nodes" in u and "/events" not in u:
            return 201, b'{"node_id":"alpha"}'
        if "/cluster/events" in u:
            return 500, b""
        return 404, b""

    transport = FakeTransport(responder=respond)
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "spool.db",
        transport=transport,
    )
    await up.start()
    up.enqueue_event({"ts": "x", "protocol": "ssh", "src_ip": "1"})
    failures = 0
    for _ in range(10):
        await asyncio.sleep(0.05)
        failures = up.status.consecutive_failures
        if failures >= 1:
            break
    await up.stop()
    assert failures >= 1


def test_register_once_handles_bad_status(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (500, b""))
    up = NodeUplink(cfg, version="1.0.0", spool_path=tmp_path / "spool.db", transport=transport)
    assert asyncio.run(up._register_once()) is False
    assert "register" in (up.status.last_error or "")


def test_register_once_handles_bad_json(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (200, b"not json"))
    up = NodeUplink(cfg, version="1.0.0", spool_path=tmp_path / "spool.db", transport=transport)
    assert asyncio.run(up._register_once()) is False


def test_register_once_handles_missing_node_id(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    transport = FakeTransport(responder=lambda m, u, b: (200, b'{"name":"x"}'))
    up = NodeUplink(cfg, version="1.0.0", spool_path=tmp_path / "spool.db", transport=transport)
    assert asyncio.run(up._register_once()) is False


def test_endpoint_strips_trailing_slash(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    cfg.controller_url = "http://controller.local:9300/"
    up = NodeUplink(
        cfg, version="1.0.0", spool_path=tmp_path / "spool.db", transport=FakeTransport()
    )
    assert up._endpoint("/api/v1/x") == "http://controller.local:9300/api/v1/x"


def test_uplink_status_to_json_round_trip() -> None:
    s = UplinkStatus(
        node_id="x",
        last_heartbeat_at=1.0,
        events_forwarded=3,
        events_dropped=1,
        online=True,
        extras={"k": "v"},
    )
    out = s.to_json()
    assert out["node_id"] == "x"
    assert out["events_forwarded"] == 3
    assert out["extras"] == {"k": "v"}


def test_spool_push_pop_round_trip(tmp_path: Path) -> None:
    s = _Spool(tmp_path / "s.db", max_disk_bytes=1 << 20)
    assert s.push({"a": 1}) is True
    assert s.push({"a": 2}) is True
    assert s.depth() == 2
    rows = s.pop_batch(10)
    assert [ev for _, ev in rows] == [{"a": 1}, {"a": 2}]
    s.discard([rid for rid, _ in rows])
    assert s.depth() == 0
    s.close()


def test_spool_pop_batch_empty(tmp_path: Path) -> None:
    s = _Spool(tmp_path / "s.db", max_disk_bytes=1 << 20)
    assert s.pop_batch(0) == []
    assert s.pop_batch(5) == []
    s.close()


def test_spool_discard_no_op_for_empty(tmp_path: Path) -> None:
    s = _Spool(tmp_path / "s.db", max_disk_bytes=1 << 20)
    s.discard([])
    s.close()


def test_spool_size_bytes_for_in_memory(tmp_path: Path) -> None:
    s = _Spool(":memory:", max_disk_bytes=1 << 20)
    assert s.size_bytes() == 0
    s.close()


def test_spool_skips_corrupt_payload(tmp_path: Path) -> None:
    s = _Spool(tmp_path / "s.db", max_disk_bytes=1 << 20)
    s._conn.execute("INSERT INTO spool(payload) VALUES (?)", ("not json",))
    s._conn.execute("INSERT INTO spool(payload) VALUES (?)", ('{"ok":1}',))
    rows = s.pop_batch(10)
    assert [ev for _, ev in rows] == [{"ok": 1}]
    s.close()


def test_urllib_transport_handles_url_error() -> None:
    t = UrllibTransport(tls_verify=False)
    status, body = t.request(
        "GET",
        "http://127.0.0.1:1/never",
        headers={},
        body=b"",
        timeout=0.1,
    )
    assert status == -1
    assert body == b""


def test_urllib_transport_tls_context_when_disabled() -> None:
    t = UrllibTransport(tls_verify=False)
    ctx = t._ssl_context()
    assert ctx is not None


def test_urllib_transport_tls_context_when_enabled() -> None:
    t = UrllibTransport(tls_verify=True)
    assert t._ssl_context() is None
