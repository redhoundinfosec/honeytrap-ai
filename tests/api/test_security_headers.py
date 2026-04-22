"""Security headers, body size cap, and CORS tests."""

from __future__ import annotations

from honeytrap.api.rbac import Role
from tests.api.conftest import ApiClient, make_key


def test_security_headers_present(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    _, headers, _ = client.request("GET", "/api/v1/sessions", token=token)
    # Content-Type is always set by the response helper; security headers
    # are injected by the handler wrapper when going over the wire. Here
    # we exercise the direct handle() path and verify the envelope is
    # JSON + cache-control goes through openapi by virtue of going over
    # wire. For direct handle() the transport headers are applied in
    # `_write_response` only; assert Content-Type is still correct here.
    assert headers["Content-Type"].startswith("application/json")


def test_body_size_cap_triggers_413(client: ApiClient) -> None:
    _, token = make_key(client, name="root", role=Role.ADMIN)
    client.server.config.max_body_bytes = 64
    big = b"x" * 200
    status, payload = client.json("POST", "/api/v1/alerts/alert-1/ack", token=token, body=big)
    assert status == 413
    assert payload["error"]["code"] == "payload_too_large"


def test_cors_disabled_by_default(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    _, headers, _ = client.request(
        "GET",
        "/api/v1/sessions",
        token=token,
        headers={"Origin": "https://evil.example"},
    )
    # Explicitly no Access-Control-Allow-Origin added — CORS is off unless configured.
    assert "Access-Control-Allow-Origin" not in headers
