"""Rate-limiting behaviour tests."""

from __future__ import annotations

from pathlib import Path

from honeytrap.api import APIConfig, APIServer
from honeytrap.api.auth import APIKeyStore
from honeytrap.api.rbac import Role
from honeytrap.api.service import InMemoryService
from tests.api.conftest import ApiClient


def test_exceeding_budget_returns_429_with_retry_after(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cfg = APIConfig(state_dir=state, port=0, rate_limits={"viewer": 2, "analyst": 5, "admin": 10})
    service = InMemoryService()
    store = APIKeyStore(cfg.state_path(cfg.api_keys_name))
    server = APIServer(service, store, cfg)
    client = ApiClient(server=server, service=service, store=store)
    _, token = store.create(name="v", role=Role.VIEWER)

    statuses = []
    for _ in range(4):
        status, _, _ = client.request("GET", "/api/v1/sessions", token=token)
        statuses.append(status)
    assert 429 in statuses
    # Find the first 429 and check Retry-After
    status, headers, _ = client.request("GET", "/api/v1/sessions", token=token)
    if status == 429:
        assert int(headers.get("Retry-After", "0")) >= 1
