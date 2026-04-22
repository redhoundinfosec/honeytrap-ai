"""Server-control endpoint tests."""

from __future__ import annotations

from honeytrap.api.rbac import Role
from tests.api.conftest import ApiClient, make_key


def test_pause_sets_state(client: ApiClient) -> None:
    _, token = make_key(client, name="root", role=Role.ADMIN)
    status, payload = client.json("POST", "/api/v1/control/pause", token=token, body={})
    assert status == 200
    assert payload["paused"] is True
    assert client.service.control.paused is True


def test_resume_clears_state(client: ApiClient) -> None:
    _, token = make_key(client, name="root", role=Role.ADMIN)
    client.service.control.paused = True
    status, payload = client.json("POST", "/api/v1/control/resume", token=token, body={})
    assert status == 200
    assert payload["paused"] is False
    assert client.service.control.paused is False


def test_shutdown_marks_flag(client: ApiClient) -> None:
    _, token = make_key(client, name="root", role=Role.ADMIN)
    status, payload = client.json("POST", "/api/v1/control/shutdown", token=token, body={})
    assert status == 202
    assert payload["shutdown_requested"] is True
    assert client.service.control.shutdown_requested is True
