"""Textual screen for the cluster console.

Provides :class:`ClusterScreen`, a standalone Textual screen rendering
fleet status by polling the local management API. The screen is wired
to an injectable HTTP fetcher so it can be tested without a real
controller. It is used by the main TUI when the operator presses the
``c`` key binding (when cluster mode is enabled in config).

The screen renders three tables side-by-side:

* Nodes -- node_id, role, version, status, last heartbeat.
* Top attackers -- src_ip, count.
* MITRE techniques -- technique, count.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

HttpFn = Callable[[str, str, dict[str, str], bytes], tuple[int, bytes]]


@dataclass
class ClusterSnapshot:
    """Plain-data view fetched from the controller."""

    nodes: list[dict[str, Any]]
    attackers: list[dict[str, Any]]
    mitre: list[dict[str, Any]]


def fetch_cluster_snapshot(base_url: str, api_key: str, http: HttpFn) -> ClusterSnapshot:
    """Pull nodes / top-attackers / mitre from a controller.

    Returns an empty snapshot if any request fails. The HTTP callable
    signature mirrors :func:`honeytrap.cluster.cli._default_http` so
    tests can pass a tiny in-memory adapter.
    """
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    base = base_url.rstrip("/")

    def _get(path: str) -> list[dict[str, Any]]:
        status, body = http("GET", base + path, headers, b"")
        if status != 200:
            return []
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return []
        items = data.get("items") if isinstance(data, dict) else None
        return items if isinstance(items, list) else []

    return ClusterSnapshot(
        nodes=_get("/api/v1/cluster/nodes"),
        attackers=_get("/api/v1/cluster/aggregate/top-attackers"),
        mitre=_get("/api/v1/cluster/aggregate/mitre"),
    )


class ClusterScreen(Screen[None]):
    """Textual screen showing fleet status, attackers, and MITRE counts."""

    BINDINGS = [("escape", "app.pop_screen", "Back"), ("r", "refresh", "Refresh")]

    def __init__(
        self,
        *,
        controller_url: str,
        api_key: str,
        http: HttpFn,
        title: str = "HoneyTrap cluster",
    ) -> None:
        """Build the screen pointed at ``controller_url`` with ``api_key``."""
        super().__init__()
        self._controller_url = controller_url
        self._api_key = api_key
        self._http = http
        self._title = title

    def compose(self) -> ComposeResult:
        """Build the visual layout."""
        yield Header()
        with Vertical():
            yield Static(self._title, id="cluster-title")
            with Horizontal():
                yield DataTable(id="cluster-nodes", zebra_stripes=True)
                yield DataTable(id="cluster-attackers", zebra_stripes=True)
                yield DataTable(id="cluster-mitre", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:  # pragma: no cover -- depends on Textual loop
        """Initialise tables and trigger the first refresh."""
        nodes: DataTable[Any] = self.query_one("#cluster-nodes", DataTable)
        nodes.add_columns("node_id", "role", "version", "status", "last_heartbeat")
        attackers: DataTable[Any] = self.query_one("#cluster-attackers", DataTable)
        attackers.add_columns("src_ip", "count")
        mitre: DataTable[Any] = self.query_one("#cluster-mitre", DataTable)
        mitre.add_columns("technique", "count")
        self.action_refresh()

    def action_refresh(self) -> None:  # pragma: no cover -- depends on Textual loop
        """Pull a fresh snapshot from the controller and repopulate."""
        snap = fetch_cluster_snapshot(self._controller_url, self._api_key, self._http)
        nodes: DataTable[Any] = self.query_one("#cluster-nodes", DataTable)
        nodes.clear()
        for node in snap.nodes:
            nodes.add_row(
                str(node.get("node_id", "")),
                str(node.get("role", "")),
                str(node.get("version", "")),
                str(node.get("status", "")),
                str(node.get("last_heartbeat") or "-"),
            )
        attackers: DataTable[Any] = self.query_one("#cluster-attackers", DataTable)
        attackers.clear()
        for row in snap.attackers:
            attackers.add_row(str(row.get("src_ip", "")), str(row.get("count", 0)))
        mitre: DataTable[Any] = self.query_one("#cluster-mitre", DataTable)
        mitre.clear()
        for row in snap.mitre:
            mitre.add_row(str(row.get("technique", "")), str(row.get("count", 0)))
