"""Tests for the ``/api/v1/sinks`` endpoints."""

from __future__ import annotations

from honeytrap.api.rbac import Role

from .conftest import ApiClient, make_key


def test_sinks_list_returns_health(client: ApiClient) -> None:
    client.service.set_sinks_health(
        [
            {"name": "es-prod", "state": "closed", "queue_depth": 0, "last_error": None},
            {"name": "splunk", "state": "open", "queue_depth": 12, "last_error": "boom"},
        ]
    )
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    status, body = client.json("GET", "/api/v1/sinks", token=viewer_token)
    assert status == 200
    names = {row["name"] for row in body["items"]}
    assert names == {"es-prod", "splunk"}


def test_sinks_list_requires_auth(client: ApiClient) -> None:
    status, _, _ = client.request("GET", "/api/v1/sinks")
    assert status == 401


def test_sinks_flush_requires_admin(client: ApiClient) -> None:
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    status, _, _ = client.request(
        "POST", "/api/v1/sinks/es-prod/flush", token=viewer_token, body=b""
    )
    assert status == 403


def test_sinks_flush_returns_count(client: ApiClient) -> None:
    client.service.set_sinks_flush_result("es-prod", {"flushed": 7, "sink": "es-prod"})
    _, admin_token = make_key(client, name="a", role=Role.ADMIN)
    status, body = client.json("POST", "/api/v1/sinks/es-prod/flush", token=admin_token, body={})
    assert status == 200
    assert body["flushed"] == 7
    assert body["sink"] == "es-prod"
