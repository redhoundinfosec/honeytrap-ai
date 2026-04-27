"""Cluster routes registered onto the management API server.

The :func:`register_cluster_routes` helper attaches eight endpoints to a
:class:`~honeytrap.api.server.APIServer`. RBAC is split:

* ``role=node``    -- registration, heartbeat, event ingest.
* ``role=analyst`` -- read endpoints (also satisfied by ``admin``).

Every response carries a ``Cluster-Generation`` header sourced from the
:class:`~honeytrap.cluster.controller_fleet.Fleet`. Clients use this to
invalidate cached node lists when nodes come and go.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from honeytrap.api.errors import bad_request, not_found
from honeytrap.api.rbac import Role
from honeytrap.cluster.controller_fleet import Fleet

if TYPE_CHECKING:  # pragma: no cover -- import-only typing
    from honeytrap.api.server import APIServer

API_PREFIX = "/api/v1/cluster"
_MAX_EVENT_BODY = 5 * 1024 * 1024  # 5 MiB


def register_cluster_routes(server: APIServer, fleet: Fleet) -> None:
    """Attach the cluster routes to ``server`` using ``fleet`` for state.

    The function is idempotent in spirit (calling twice would re-register
    the same routes; the router does not deduplicate, so callers must
    invoke this exactly once during server initialisation).
    """
    from honeytrap.api.server import _RequestContext, _Response  # noqa: PLC0415

    router = server.router

    def _gen_headers() -> dict[str, str]:
        return {"Cluster-Generation": str(fleet.generation)}

    def _json(status: int, payload: Any) -> _Response:
        body = json.dumps(payload, default=_default_json).encode("utf-8")
        headers = _gen_headers()
        return _Response(status, body, "application/json; charset=utf-8", headers)

    def _ensure_dict(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise bad_request("body must be valid JSON") from exc
        if not isinstance(decoded, dict):
            raise bad_request("body must be a JSON object")
        return decoded

    @router.route(
        f"{API_PREFIX}/nodes",
        methods=["POST"],
        role=Role.NODE,
        tags=["cluster"],
    )
    def _register(ctx: _RequestContext) -> _Response:
        """Register or refresh a node and return its assigned id."""
        payload = _ensure_dict(ctx.body)
        name = str(payload.get("name") or "node").strip() or "node"
        role = str(payload.get("role") or "node").strip() or "node"
        version = str(payload.get("version") or "unknown").strip()
        profile = _opt_str(payload.get("profile"))
        address = ctx.remote_addr
        tags_raw = payload.get("tags") or []
        if isinstance(tags_raw, list):
            tags = [str(t) for t in tags_raw if isinstance(t, (str, int, float))]
        else:
            tags = []
        node_id = _opt_str(payload.get("node_id"))
        record = fleet.register_node(
            name=name,
            role=role,
            version=version,
            profile=profile,
            address=address,
            tags=tags,
            node_id=node_id,
        )
        return _json(201, record.to_json())

    @router.route(
        f"{API_PREFIX}/nodes/{{node_id}}",
        methods=["DELETE"],
        role=Role.ADMIN,
        tags=["cluster"],
    )
    def _deregister(ctx: _RequestContext, node_id: str) -> _Response:
        """Remove a node and its history (admin only)."""
        if not fleet.deregister_node(node_id):
            raise not_found(f"node {node_id!r} not found")
        return _json(200, {"deregistered": True, "node_id": node_id})

    @router.route(
        f"{API_PREFIX}/nodes/{{node_id}}/heartbeat",
        methods=["PUT"],
        role=Role.NODE,
        tags=["cluster"],
    )
    def _heartbeat(ctx: _RequestContext, node_id: str) -> _Response:
        """Record a heartbeat snapshot for a registered node."""
        snapshot = _ensure_dict(ctx.body)
        ok = fleet.record_heartbeat(node_id, snapshot)
        if not ok:
            raise not_found(f"node {node_id!r} not registered")
        return _json(200, {"recorded": True})

    @router.route(
        f"{API_PREFIX}/events",
        methods=["POST"],
        role=Role.NODE,
        tags=["cluster"],
    )
    def _ingest(ctx: _RequestContext) -> _Response:
        """Ingest an event batch from a node."""
        if len(ctx.body) > _MAX_EVENT_BODY:
            raise bad_request("event batch exceeds 5 MiB limit")
        payload = _ensure_dict(ctx.body)
        node_id = _opt_str(payload.get("node_id"))
        if not node_id:
            raise bad_request("node_id is required")
        events = payload.get("events")
        if not isinstance(events, list):
            raise bad_request("events must be a list")
        if not fleet.get_node(node_id):
            raise not_found(f"node {node_id!r} not registered")
        accepted, rejected = fleet.ingest_events_batch(node_id, events)
        return _json(202, {"accepted": accepted, "rejected": rejected})

    @router.route(
        f"{API_PREFIX}/nodes",
        methods=["GET"],
        role=Role.ANALYST,
        tags=["cluster"],
    )
    def _list_nodes(ctx: _RequestContext) -> _Response:
        """Return every registered node with its latest health snapshot."""
        items = [n.to_json() for n in fleet.list_nodes()]
        return _json(200, {"items": items, "count": len(items)})

    @router.route(
        f"{API_PREFIX}/nodes/{{node_id}}",
        methods=["GET"],
        role=Role.ANALYST,
        tags=["cluster"],
    )
    def _get_node(ctx: _RequestContext, node_id: str) -> _Response:
        """Return a single node's record."""
        rec = fleet.get_node(node_id)
        if rec is None:
            raise not_found(f"node {node_id!r} not found")
        return _json(200, rec.to_json())

    @router.route(
        f"{API_PREFIX}/events",
        methods=["GET"],
        role=Role.ANALYST,
        tags=["cluster"],
    )
    def _query_events(ctx: _RequestContext) -> _Response:
        """Return the latest events filtered by node/protocol/ip/time."""
        limit_raw = _qp(ctx.query, "limit") or "100"
        try:
            limit = int(limit_raw)
        except ValueError as exc:
            raise bad_request("limit must be an integer") from exc
        items = fleet.query_events(
            since=_qp(ctx.query, "since"),
            until=_qp(ctx.query, "until"),
            src_ip=_qp(ctx.query, "src_ip"),
            protocol=_qp(ctx.query, "protocol"),
            node_id=_qp(ctx.query, "node_id"),
            limit=limit,
        )
        return _json(200, {"items": items, "count": len(items)})

    @router.route(
        f"{API_PREFIX}/aggregate/top-attackers",
        methods=["GET"],
        role=Role.ANALYST,
        tags=["cluster"],
    )
    def _top_attackers(ctx: _RequestContext) -> _Response:
        """Return the top-N attacker IPs across the cluster."""
        limit_raw = _qp(ctx.query, "limit") or "20"
        try:
            limit = int(limit_raw)
        except ValueError as exc:
            raise bad_request("limit must be an integer") from exc
        return _json(200, {"items": fleet.aggregate_top_attackers(limit=limit)})

    @router.route(
        f"{API_PREFIX}/aggregate/mitre",
        methods=["GET"],
        role=Role.ANALYST,
        tags=["cluster"],
    )
    def _mitre(ctx: _RequestContext) -> _Response:
        """Return cluster-wide MITRE ATT&CK technique counts."""
        return _json(200, {"items": fleet.aggregate_mitre_heatmap()})

    @router.route(
        f"{API_PREFIX}/aggregate/sessions",
        methods=["GET"],
        role=Role.ANALYST,
        tags=["cluster"],
    )
    def _sessions(ctx: _RequestContext) -> _Response:
        """Return per-node session counts grouped by protocol."""
        return _json(200, {"items": fleet.aggregate_sessions_per_node()})


def _qp(query: dict[str, list[str]], name: str) -> str | None:
    """Return the first value for a query param or ``None``."""
    values = query.get(name)
    if not values:
        return None
    return values[0]


def _opt_str(value: Any) -> str | None:
    """Coerce a value to ``str`` or ``None`` if empty."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _default_json(obj: Any) -> Any:
    """Fallback JSON encoder mirroring the API server's helper."""
    if hasattr(obj, "to_json"):
        return obj.to_json()
    raise TypeError(f"Cannot serialise {type(obj).__name__}")
