"""End-to-end cluster integration tests.

A controller is instantiated in-process, two simulated nodes register,
ingest events, and the analyst reads aggregate data back. The transport
between node and controller is a tiny adapter that calls into the
:class:`ApiClient` request helper directly -- no sockets are opened.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from honeytrap.api.rbac import Role
from honeytrap.cluster.config import ClusterConfig, ClusterRole
from honeytrap.cluster.node_uplink import NodeUplink
from tests.cluster.conftest import ClusterClient, event, make_token


class InProcessTransport:
    """Routes uplink HTTP calls through the in-memory controller client."""

    def __init__(self, cluster_client: ClusterClient, token: str) -> None:
        self._cc = cluster_client
        self._token = token

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes,
        timeout: float,
    ) -> tuple[int, bytes]:
        path = url.split("//", 1)[1].split("/", 1)[1]  # strip scheme + host
        path = "/" + path
        status, _, raw = self._cc.client.request(
            method,
            path,
            token=self._token,
            body=body,
            headers={"Content-Type": "application/json"},
        )
        return status, raw


@pytest.mark.asyncio
async def test_two_nodes_register_and_ingest(cluster_client: ClusterClient, tmp_path: Path) -> None:
    """Two simulated nodes register, send events, and the analyst reads them."""
    node_token = make_token(cluster_client.client, role=Role.NODE)
    analyst_token = make_token(cluster_client.client, role=Role.ANALYST)
    transport = InProcessTransport(cluster_client, node_token)

    def make_uplink(node_id: str) -> NodeUplink:
        cfg = ClusterConfig(
            enabled=True,
            role=ClusterRole.NODE,
            controller_url="http://127.0.0.1:0",
            api_key=node_token,
            heartbeat_interval=0.05,
            event_batch_size=10,
            event_flush_interval=0.05,
            spool_max_events=100,
            spool_max_disk_bytes=1 << 20,
            node_id=node_id,
        )
        return NodeUplink(
            cfg,
            version="1.0.0",
            spool_path=tmp_path / f"{node_id}.db",
            transport=transport,
        )

    n1 = make_uplink("alpha")
    n2 = make_uplink("beta")
    await n1.start()
    await n2.start()

    n1.enqueue_event(event(src_ip="1.1.1.1", session_id="a1"))
    n1.enqueue_event(event(src_ip="1.1.1.1", session_id="a2"))
    n2.enqueue_event(event(src_ip="2.2.2.2", session_id="b1", protocol="http"))

    forwarded_total = 0
    for _ in range(40):
        await asyncio.sleep(0.05)
        forwarded_total = n1.status.events_forwarded + n2.status.events_forwarded
        if forwarded_total >= 3:
            break

    await n1.stop()
    await n2.stop()

    assert forwarded_total >= 3

    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/nodes",
        token=analyst_token,
    )
    assert status == 200
    node_ids = {n["node_id"] for n in body["items"]}
    assert {"alpha", "beta"} <= node_ids

    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/aggregate/top-attackers",
        token=analyst_token,
    )
    ips = {row["src_ip"] for row in body["items"]}
    assert {"1.1.1.1", "2.2.2.2"} <= ips


@pytest.mark.asyncio
async def test_controller_outage_recovers_via_spool(
    cluster_client: ClusterClient, tmp_path: Path
) -> None:
    """Events buffered during an outage are delivered after recovery."""
    node_token = make_token(cluster_client.client, role=Role.NODE)
    analyst_token = make_token(cluster_client.client, role=Role.ANALYST)
    transport = InProcessTransport(cluster_client, node_token)

    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.NODE,
        controller_url="http://127.0.0.1:0",
        api_key=node_token,
        heartbeat_interval=0.05,
        event_batch_size=10,
        event_flush_interval=0.05,
        spool_max_events=100,
        spool_max_disk_bytes=1 << 20,
        node_id="alpha",
    )
    up = NodeUplink(
        cfg,
        version="1.0.0",
        spool_path=tmp_path / "alpha.db",
        transport=transport,
    )

    # Pre-register manually so registration is not blocked.
    cluster_client.fleet.register_node(name="alpha", role="node", version="1.0.0", node_id="alpha")
    await up.start()
    up.enqueue_event(event(session_id="x"))

    forwarded = 0
    for _ in range(40):
        await asyncio.sleep(0.05)
        forwarded = up.status.events_forwarded
        if forwarded >= 1:
            break
    await up.stop()
    assert forwarded >= 1

    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/events?node_id=alpha",
        token=analyst_token,
    )
    assert status == 200
    assert body["count"] >= 1


def test_generation_header_increments(cluster_client: ClusterClient) -> None:
    """Cluster-Generation header bumps on register/deregister."""
    node_token = make_token(cluster_client.client, role=Role.NODE)
    admin_token = make_token(cluster_client.client, role=Role.ADMIN)

    status, headers, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/nodes",
        token=node_token,
        body={"name": "x", "version": "1", "node_id": "alpha"},
    )
    assert status == 201
    gen_a = int(headers["Cluster-Generation"])

    status, headers, _ = cluster_client.client.request(
        "DELETE",
        "/api/v1/cluster/nodes/alpha",
        token=admin_token,
    )
    gen_b = int(headers["Cluster-Generation"])
    assert gen_b > gen_a
