"""Tests for the AI-related API endpoints."""

from __future__ import annotations

from honeytrap.api.rbac import Role
from tests.api.conftest import ApiClient, make_key


def test_session_memory_returns_snapshot(client: ApiClient) -> None:
    client.service.set_ai_memory(
        "sess-1",
        {
            "session_id": "sess-1",
            "source_ip": "203.0.113.5",
            "command_history": ["whoami", "id"],
            "intent": "RECON",
            "intent_confidence": 0.8,
        },
    )
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json(
        "GET", "/api/v1/sessions/sess-1/memory", token=token
    )
    assert status == 200
    assert payload["session_id"] == "sess-1"
    assert payload["intent"] == "RECON"
    assert payload["command_history"] == ["whoami", "id"]


def test_session_memory_missing_returns_404(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, _payload = client.json(
        "GET", "/api/v1/sessions/unknown-session/memory", token=token
    )
    assert status == 404


def test_session_memory_requires_auth(client: ApiClient) -> None:
    status, _hdrs, _body = client.request(
        "GET", "/api/v1/sessions/sess-1/memory"
    )
    assert status == 401


def test_intent_counts_endpoint(client: ApiClient) -> None:
    client.service.set_ai_intents({"RECON": 4, "EXPLOIT_ATTEMPT": 1})
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/intel/intents", token=token)
    assert status == 200
    assert payload["counts"]["RECON"] == 4
    assert payload["counts"]["EXPLOIT_ATTEMPT"] == 1


def test_ai_backends_health_endpoint(client: ApiClient) -> None:
    client.service.set_ai_backend_health(
        [
            {"name": "template", "healthy": True, "calls": 12, "failures": 0},
            {"name": "openai", "healthy": False, "calls": 3, "failures": 3},
        ]
    )
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/ai/backends", token=token)
    assert status == 200
    names = [row["name"] for row in payload["backends"]]
    assert "template" in names
    assert "openai" in names
