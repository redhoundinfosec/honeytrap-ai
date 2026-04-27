"""Shared fixtures for cluster tests.

Builds a pre-configured :class:`APIClient` with the cluster routes wired
in, plus helpers for crafting node/admin/analyst keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from honeytrap.api import APIConfig, APIServer
from honeytrap.api.auth import APIKeyStore
from honeytrap.api.rbac import Role
from honeytrap.api.service import InMemoryService
from honeytrap.cluster.controller_fleet import Fleet
from tests.api.conftest import ApiClient


@dataclass
class ClusterClient:
    """Bundle of API client plus the fleet used by the routes."""

    client: ApiClient
    fleet: Fleet


@pytest.fixture
def cluster_state(tmp_path: Path) -> Path:
    """Return a temp state directory."""
    target = tmp_path / "state"
    target.mkdir()
    return target


@pytest.fixture
def cluster_client(cluster_state: Path) -> ClusterClient:
    """Build a server with cluster routes registered against a fresh fleet."""
    config = APIConfig(
        state_dir=cluster_state,
        port=0,
        rate_limits={
            "node": 6000,
            "viewer": 600,
            "analyst": 600,
            "admin": 600,
        },
        max_body_bytes=8 * 1024 * 1024,
    )
    service = InMemoryService()
    store = APIKeyStore(config.state_path(config.api_keys_name))
    server = APIServer(service, store, config)
    fleet = Fleet(cluster_state / "fleet.db", heartbeat_interval=10.0)
    server.enable_cluster(fleet)
    api = ApiClient(server=server, service=service, store=store)
    return ClusterClient(client=api, fleet=fleet)


def make_token(client: ApiClient, *, role: Role, name: str | None = None) -> str:
    """Create an API key of the given role and return the plaintext token."""
    _, token = client.store.create(name=name or role.value, role=role)
    return token


def event(
    *,
    ts: str = "2026-04-27T00:00:00Z",
    protocol: str = "ssh",
    src_ip: str = "10.0.0.1",
    technique: str = "T1110",
    session_id: str = "sess-1",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a synthetic event dict for fleet/test ingest paths."""
    payload: dict[str, Any] = {
        "ts": ts,
        "protocol": protocol,
        "src_ip": src_ip,
        "technique": technique,
        "session_id": session_id,
    }
    if extra:
        payload.update(extra)
    return payload
