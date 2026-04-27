"""Tests for ``honeytrap.cluster.api_endpoints``."""

from __future__ import annotations

import json

from honeytrap.api.rbac import Role
from tests.cluster.conftest import ClusterClient, event, make_token


def _node_token(cc: ClusterClient) -> str:
    return make_token(cc.client, role=Role.NODE)


def _admin_token(cc: ClusterClient) -> str:
    return make_token(cc.client, role=Role.ADMIN)


def _analyst_token(cc: ClusterClient) -> str:
    return make_token(cc.client, role=Role.ANALYST)


def _viewer_token(cc: ClusterClient) -> str:
    return make_token(cc.client, role=Role.VIEWER)


def test_register_node_requires_node_role(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/nodes",
        token=_admin_token(cluster_client),
        body={"name": "edge", "version": "1"},
    )
    assert status == 403


def test_register_node_succeeds_with_node_role(cluster_client: ClusterClient) -> None:
    status, body = cluster_client.client.json(
        "POST",
        "/api/v1/cluster/nodes",
        token=_node_token(cluster_client),
        body={"name": "edge", "version": "1.0", "role": "node"},
    )
    assert status == 201
    assert body["name"] == "edge"


def test_register_node_with_explicit_id_round_trips(cluster_client: ClusterClient) -> None:
    status, body = cluster_client.client.json(
        "POST",
        "/api/v1/cluster/nodes",
        token=_node_token(cluster_client),
        body={"name": "edge", "version": "1.0", "node_id": "alpha", "tags": ["a", 1]},
    )
    assert status == 201
    assert body["node_id"] == "alpha"
    assert "a" in body["tags"]


def test_register_node_rejects_non_object_body(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/nodes",
        token=_node_token(cluster_client),
        body=b"[1,2,3]",
        headers={"Content-Type": "application/json"},
    )
    assert status == 400


def test_register_node_rejects_invalid_json(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/nodes",
        token=_node_token(cluster_client),
        body=b"{broken",
        headers={"Content-Type": "application/json"},
    )
    assert status == 400


def test_response_has_cluster_generation_header(cluster_client: ClusterClient) -> None:
    status, headers, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/nodes",
        token=_node_token(cluster_client),
        body={"name": "x", "version": "1.0"},
    )
    assert status == 201
    assert "Cluster-Generation" in headers


def test_heartbeat_requires_node_role(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    status, _, _ = cluster_client.client.request(
        "PUT",
        "/api/v1/cluster/nodes/alpha/heartbeat",
        token=_analyst_token(cluster_client),
        body={"uptime": 1},
    )
    assert status == 403


def test_heartbeat_unknown_node_returns_404(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "PUT",
        "/api/v1/cluster/nodes/missing/heartbeat",
        token=_node_token(cluster_client),
        body={"uptime": 1},
    )
    assert status == 404


def test_heartbeat_records_snapshot(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    status, body = cluster_client.client.json(
        "PUT",
        "/api/v1/cluster/nodes/alpha/heartbeat",
        token=_node_token(cluster_client),
        body={"uptime": 42, "queue_depth": 0},
    )
    assert status == 200
    assert body["recorded"] is True


def test_ingest_events_requires_node_role(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/events",
        token=_analyst_token(cluster_client),
        body={"node_id": "alpha", "events": []},
    )
    assert status == 403


def test_ingest_events_requires_node_id(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/events",
        token=_node_token(cluster_client),
        body={"events": []},
    )
    assert status == 400


def test_ingest_events_requires_events_list(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/events",
        token=_node_token(cluster_client),
        body={"node_id": "alpha", "events": "nope"},
    )
    assert status == 400


def test_ingest_events_unknown_node(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/events",
        token=_node_token(cluster_client),
        body={"node_id": "ghost", "events": [event()]},
    )
    assert status == 404


def test_ingest_events_happy_path(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    status, body = cluster_client.client.json(
        "POST",
        "/api/v1/cluster/events",
        token=_node_token(cluster_client),
        body={"node_id": "alpha", "events": [event(), event(session_id="s2")]},
    )
    assert status == 202
    assert body["accepted"] == 2
    assert body["rejected"] == 0


def test_list_nodes_requires_analyst_or_higher(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "GET",
        "/api/v1/cluster/nodes",
        token=_viewer_token(cluster_client),
    )
    assert status == 403


def test_list_nodes_returns_records(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/nodes",
        token=_analyst_token(cluster_client),
    )
    assert status == 200
    assert body["count"] == 1


def test_get_node_404_for_unknown(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "GET",
        "/api/v1/cluster/nodes/ghost",
        token=_analyst_token(cluster_client),
    )
    assert status == 404


def test_get_node_returns_record(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/nodes/alpha",
        token=_analyst_token(cluster_client),
    )
    assert status == 200
    assert body["node_id"] == "alpha"


def test_deregister_requires_admin(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    status, _, _ = cluster_client.client.request(
        "DELETE",
        "/api/v1/cluster/nodes/alpha",
        token=_analyst_token(cluster_client),
    )
    assert status == 403


def test_deregister_succeeds_for_admin(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    status, body = cluster_client.client.json(
        "DELETE",
        "/api/v1/cluster/nodes/alpha",
        token=_admin_token(cluster_client),
    )
    assert status == 200
    assert body["deregistered"] is True


def test_deregister_404_for_missing(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "DELETE",
        "/api/v1/cluster/nodes/ghost",
        token=_admin_token(cluster_client),
    )
    assert status == 404


def test_query_events_with_filters(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    cluster_client.fleet.ingest_events_batch(
        "alpha",
        [event(protocol="ssh"), event(protocol="http", session_id="s2")],
    )
    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/events?protocol=ssh&limit=10",
        token=_analyst_token(cluster_client),
    )
    assert status == 200
    assert body["count"] == 1


def test_query_events_invalid_limit_returns_400(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "GET",
        "/api/v1/cluster/events?limit=not-a-number",
        token=_analyst_token(cluster_client),
    )
    assert status == 400


def test_top_attackers_endpoint(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    cluster_client.fleet.ingest_events_batch(
        "alpha",
        [event(src_ip="9.9.9.9"), event(src_ip="9.9.9.9", session_id="s2")],
    )
    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/aggregate/top-attackers",
        token=_analyst_token(cluster_client),
    )
    assert status == 200
    assert body["items"][0]["src_ip"] == "9.9.9.9"


def test_top_attackers_invalid_limit(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "GET",
        "/api/v1/cluster/aggregate/top-attackers?limit=bogus",
        token=_analyst_token(cluster_client),
    )
    assert status == 400


def test_mitre_endpoint_returns_counts(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    cluster_client.fleet.ingest_events_batch(
        "alpha", [event(technique="T1110"), event(technique="T1059", session_id="s2")]
    )
    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/aggregate/mitre",
        token=_analyst_token(cluster_client),
    )
    assert status == 200
    assert {row["technique"] for row in body["items"]} == {"T1110", "T1059"}


def test_sessions_endpoint(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    cluster_client.fleet.ingest_events_batch("alpha", [event()])
    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/cluster/aggregate/sessions",
        token=_analyst_token(cluster_client),
    )
    assert status == 200
    assert body["items"]


def test_anonymous_request_rejected(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "GET",
        "/api/v1/cluster/nodes",
    )
    assert status == 401


def test_node_role_cannot_read_aggregate(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "GET",
        "/api/v1/cluster/aggregate/mitre",
        token=_node_token(cluster_client),
    )
    assert status == 403


def test_admin_can_read_aggregate(cluster_client: ClusterClient) -> None:
    status, _, _ = cluster_client.client.request(
        "GET",
        "/api/v1/cluster/aggregate/mitre",
        token=_admin_token(cluster_client),
    )
    assert status == 200


def test_openapi_includes_cluster_routes(cluster_client: ClusterClient) -> None:
    status, body = cluster_client.client.json(
        "GET",
        "/api/v1/openapi.json",
        token=_admin_token(cluster_client),
    )
    assert status == 200
    paths = body.get("paths", {})
    assert any("/cluster/" in p for p in paths)


def test_event_body_too_large_rejected(cluster_client: ClusterClient) -> None:
    cluster_client.fleet.register_node(name="x", role="node", version="1", node_id="alpha")
    huge = json.dumps({"node_id": "alpha", "events": [{"blob": "A" * (6 * 1024 * 1024)}]}).encode(
        "utf-8"
    )
    status, _, _ = cluster_client.client.request(
        "POST",
        "/api/v1/cluster/events",
        token=_node_token(cluster_client),
        body=huge,
        headers={"Content-Type": "application/json"},
    )
    # Either the API server's max_body_bytes (8 MiB) accepts the request and
    # the cluster route's 5 MiB cap rejects it, or the API rejects it first.
    assert status in (400, 413, 422)
