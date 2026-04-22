"""API-key management endpoint tests."""

from __future__ import annotations

from honeytrap.api.rbac import Role
from tests.api.conftest import ApiClient, make_key


def test_create_key_returns_plaintext_once(client: ApiClient) -> None:
    _, admin_token = make_key(client, name="root", role=Role.ADMIN)
    status, payload = client.json(
        "POST",
        "/api/v1/apikeys",
        token=admin_token,
        body={"name": "bot", "role": "analyst"},
    )
    assert status == 201
    new_id = payload["key"]["id"]
    assert payload["token"].startswith("htk_")

    status, listing = client.json("GET", "/api/v1/apikeys", token=admin_token)
    entry = next(k for k in listing["items"] if k["id"] == new_id)
    assert "token" not in entry
    assert "hashed" not in entry
    assert entry["prefix"].startswith("htk_")


def test_delete_revokes_key(client: ApiClient) -> None:
    _, admin_token = make_key(client, name="root", role=Role.ADMIN)
    status, create_payload = client.json(
        "POST",
        "/api/v1/apikeys",
        token=admin_token,
        body={"name": "tmp", "role": "viewer"},
    )
    new_id = create_payload["key"]["id"]
    victim_token = create_payload["token"]

    status, _ = client.json("DELETE", f"/api/v1/apikeys/{new_id}", token=admin_token)
    assert status == 200

    status, _ = client.json("GET", "/api/v1/sessions", token=victim_token)
    assert status == 401
