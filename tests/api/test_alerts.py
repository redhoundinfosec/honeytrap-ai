"""Alert listing and acknowledgement tests."""

from __future__ import annotations

from honeytrap.api.rbac import Role
from tests.api.conftest import ApiClient, make_key


def test_list_alerts_by_severity(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/alerts?severity=HIGH", token=token)
    assert status == 200
    assert len(payload["items"]) == 1
    assert payload["items"][0]["id"] == "alert-1"


def test_ack_flips_flag_and_stores_note(client: ApiClient) -> None:
    _, token = make_key(client, name="a", role=Role.ANALYST)
    status, payload = client.json(
        "POST",
        "/api/v1/alerts/alert-1/ack",
        token=token,
        body={"note": "false positive"},
    )
    assert status == 200
    assert payload["acknowledged"] is True
    assert payload["note"] == "false positive"

    status, listing = client.json("GET", "/api/v1/alerts?acknowledged=true", token=token)
    assert status == 200
    assert len(listing["items"]) == 1
    assert listing["items"][0]["id"] == "alert-1"
