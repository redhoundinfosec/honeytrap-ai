"""Tests for ``honeytrap.ui.cluster_tui`` (snapshot fetcher)."""

from __future__ import annotations

import json

from honeytrap.ui.cluster_tui import (
    ClusterScreen,
    ClusterSnapshot,
    fetch_cluster_snapshot,
)


def test_fetch_cluster_snapshot_happy_path() -> None:
    payloads = {
        "/api/v1/cluster/nodes": {"items": [{"node_id": "alpha"}]},
        "/api/v1/cluster/aggregate/top-attackers": {"items": [{"src_ip": "1.2.3.4", "count": 5}]},
        "/api/v1/cluster/aggregate/mitre": {"items": [{"technique": "T1110", "count": 7}]},
    }

    def http(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        for path, payload in payloads.items():
            if path in url:
                return 200, json.dumps(payload).encode()
        return 404, b""

    snap = fetch_cluster_snapshot("http://controller", "htk_x", http)
    assert isinstance(snap, ClusterSnapshot)
    assert snap.nodes[0]["node_id"] == "alpha"
    assert snap.attackers[0]["src_ip"] == "1.2.3.4"
    assert snap.mitre[0]["technique"] == "T1110"


def test_fetch_cluster_snapshot_empty_on_failure() -> None:
    def http(*_args: object, **_kwargs: object) -> tuple[int, bytes]:
        return 500, b""

    snap = fetch_cluster_snapshot("http://controller", "htk_x", http)
    assert snap.nodes == [] and snap.attackers == [] and snap.mitre == []


def test_fetch_cluster_snapshot_invalid_json() -> None:
    def http(*_args: object, **_kwargs: object) -> tuple[int, bytes]:
        return 200, b"not json"

    snap = fetch_cluster_snapshot("http://controller", "htk_x", http)
    assert snap.nodes == [] and snap.attackers == [] and snap.mitre == []


def test_fetch_cluster_snapshot_non_object_response() -> None:
    def http(*_args: object, **_kwargs: object) -> tuple[int, bytes]:
        return 200, b"[1,2,3]"

    snap = fetch_cluster_snapshot("http://controller", "htk_x", http)
    assert snap.nodes == []


def test_fetch_cluster_snapshot_missing_items_key() -> None:
    def http(*_args: object, **_kwargs: object) -> tuple[int, bytes]:
        return 200, b'{"other": []}'

    snap = fetch_cluster_snapshot("http://controller", "htk_x", http)
    assert snap.nodes == []


def test_cluster_screen_constructs() -> None:
    """Constructing the screen should not require a Textual runtime."""
    screen = ClusterScreen(
        controller_url="http://x",
        api_key="htk_x",
        http=lambda *a, **k: (200, b'{"items": []}'),
    )
    assert screen._controller_url == "http://x"  # noqa: SLF001
