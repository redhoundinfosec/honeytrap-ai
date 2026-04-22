"""Intel (ATT&CK, IOC, TLS) endpoint tests."""

from __future__ import annotations

from honeytrap.api.rbac import Role
from tests.api.conftest import ApiClient, make_key


def test_attck_returns_counts(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/intel/attck", token=token)
    assert status == 200
    assert payload["counts"]["T1110"] == 5


def test_iocs_filter_by_type(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/intel/iocs?type=domain", token=token)
    assert status == 200
    assert len(payload["items"]) == 1
    assert payload["items"][0]["value"] == "evil.example"


def test_tls_top_capped(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/intel/tls?top=1", token=token)
    assert status == 200
    assert len(payload["items"]) == 1
