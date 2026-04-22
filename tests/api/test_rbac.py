"""Role-based access control tests."""

from __future__ import annotations

from honeytrap.api.rbac import Role, check_role
from tests.api.conftest import ApiClient, make_key


def test_analyst_can_ack_alert(client: ApiClient) -> None:
    _, token = make_key(client, name="a", role=Role.ANALYST)
    status, payload = client.json(
        "POST", "/api/v1/alerts/alert-1/ack", token=token, body={"note": "triaged"}
    )
    assert status == 200
    assert payload["acknowledged"] is True
    assert payload["note"] == "triaged"


def test_analyst_cannot_delete_apikey(client: ApiClient) -> None:
    _, analyst_token = make_key(client, name="a", role=Role.ANALYST)
    victim, _ = make_key(client, name="v", role=Role.VIEWER)
    status, _ = client.json("DELETE", f"/api/v1/apikeys/{victim.id}", token=analyst_token)
    assert status == 403


def test_admin_can_crud_apikeys(client: ApiClient) -> None:
    _, admin_token = make_key(client, name="root", role=Role.ADMIN)
    status, payload = client.json(
        "POST",
        "/api/v1/apikeys",
        token=admin_token,
        body={"name": "bot", "role": "viewer"},
    )
    assert status == 201
    new_id = payload["key"]["id"]
    assert payload["token"].startswith("htk_")

    status, listing = client.json("GET", "/api/v1/apikeys", token=admin_token)
    assert status == 200
    assert any(k["id"] == new_id for k in listing["items"])

    status, payload = client.json("DELETE", f"/api/v1/apikeys/{new_id}", token=admin_token)
    assert status == 200
    assert payload["revoked"] is True


def test_admin_satisfies_viewer_check() -> None:
    assert check_role(Role.ADMIN, Role.VIEWER) is True
    assert check_role(Role.ADMIN, Role.ANALYST) is True
    assert check_role(Role.VIEWER, Role.ADMIN) is False
