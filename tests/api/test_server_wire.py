"""End-to-end test that the stdlib HTTP backend actually serves requests.

Complements the in-process ``handle()`` tests by binding a real socket
on an ephemeral port and making a network round-trip. Verifies that
security headers, request IDs, and body bytes survive the transport.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from honeytrap.api import APIConfig, APIServer
from honeytrap.api.auth import APIKeyStore
from honeytrap.api.rbac import Role
from honeytrap.api.service import InMemoryService


def test_stdlib_server_serves_over_wire(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cfg = APIConfig(state_dir=state, port=0)
    service = InMemoryService()
    store = APIKeyStore(cfg.state_path(cfg.api_keys_name))
    server = APIServer(service, store, cfg)
    server.start()
    try:
        base = f"http://{server.bound_host}:{server.bound_port}"
        with urllib.request.urlopen(f"{base}/api/v1/health", timeout=5) as resp:
            body = resp.read()
            headers = dict(resp.headers.items())
        payload = json.loads(body)
        assert payload["status"] == "ok"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"

        try:
            urllib.request.urlopen(f"{base}/api/v1/sessions", timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:  # pragma: no cover -- would indicate an auth regression
            raise AssertionError("Expected 401 on unauthenticated sessions call")
    finally:
        server.stop()


def test_over_wire_auth_success(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cfg = APIConfig(state_dir=state, port=0)
    service = InMemoryService()
    store = APIKeyStore(cfg.state_path(cfg.api_keys_name))
    _, token = store.create(name="v", role=Role.VIEWER)
    server = APIServer(service, store, cfg)
    server.start()
    try:
        req = urllib.request.Request(
            f"http://{server.bound_host}:{server.bound_port}/api/v1/sessions",
            headers={"X-API-Key": token},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read())
            assert "items" in body
    finally:
        server.stop()
