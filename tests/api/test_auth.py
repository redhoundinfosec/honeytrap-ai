"""Authentication and HMAC signing tests."""

from __future__ import annotations

import time

from honeytrap.api.auth import compute_hmac
from honeytrap.api.rbac import Role
from tests.api.conftest import ApiClient, make_key, now_ts


def test_missing_api_key_returns_401(client: ApiClient) -> None:
    status, payload = client.json("GET", "/api/v1/sessions")
    assert status == 401
    assert payload["error"]["code"] == "unauthorized"


def test_invalid_api_key_records_audit_failure(client: ApiClient) -> None:
    status, _ = client.json("GET", "/api/v1/sessions", token="htk_bogus_token_xxxxxxxxxxxxxxxxxxxx")
    assert status == 401
    records = client.server.audit.read_all()
    assert any(
        r.get("status") == 401 and r.get("auth_reason") == "invalid_credentials" for r in records
    )


def test_valid_viewer_can_get_sessions(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/sessions", token=token)
    assert status == 200
    assert isinstance(payload["items"], list)


def test_viewer_cannot_ack_alert(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json(
        "POST", "/api/v1/alerts/alert-1/ack", token=token, body={"note": "nope"}
    )
    assert status == 403
    assert payload["error"]["code"] == "forbidden"


def test_revoked_key_is_rejected(client: ApiClient) -> None:
    record, token = make_key(client, name="v", role=Role.VIEWER)
    client.store.revoke(record.id)
    status, _ = client.json("GET", "/api/v1/sessions", token=token)
    assert status == 401


def test_hmac_correct_signature_accepted(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    ts = str(now_ts())
    sig = compute_hmac(token, "GET", "/api/v1/sessions", ts, b"")
    headers = {"X-API-Key": token, "X-HT-Timestamp": ts, "X-HT-Signature": sig}
    status, _ = client.json("GET", "/api/v1/sessions", headers=headers)
    assert status == 200


def test_hmac_expired_timestamp_rejected(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    ts = str(int(time.time()) - 3600)
    sig = compute_hmac(token, "GET", "/api/v1/sessions", ts, b"")
    headers = {"X-API-Key": token, "X-HT-Timestamp": ts, "X-HT-Signature": sig}
    status, payload = client.json("GET", "/api/v1/sessions", headers=headers)
    assert status == 401
    assert "skew" in payload["error"]["message"].lower()


def test_hmac_replay_rejected(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    ts = str(now_ts())
    sig = compute_hmac(token, "GET", "/api/v1/sessions", ts, b"")
    headers = {"X-API-Key": token, "X-HT-Timestamp": ts, "X-HT-Signature": sig}
    first, _ = client.json("GET", "/api/v1/sessions", headers=headers)
    second, payload = client.json("GET", "/api/v1/sessions", headers=headers)
    assert first == 200
    assert second == 401
    assert "replay" in payload["error"]["message"].lower()
