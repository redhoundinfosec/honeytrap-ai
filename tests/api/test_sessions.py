"""Sessions endpoints: listing, filters, pagination, streaming exports."""

from __future__ import annotations

import gzip

from honeytrap.api.rbac import Role
from tests.api.conftest import ApiClient, make_key


def test_list_sessions_paginates_with_cursor(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/sessions?limit=1", token=token)
    assert status == 200
    assert len(payload["items"]) == 1
    assert payload["next_cursor"] is not None
    cursor = payload["next_cursor"]
    status, payload = client.json("GET", f"/api/v1/sessions?limit=1&cursor={cursor}", token=token)
    assert status == 200
    assert len(payload["items"]) == 1
    assert payload["next_cursor"] is None


def test_filter_by_ip_and_protocol(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json(
        "GET", "/api/v1/sessions?ip=203.0.113.5&protocol=ssh", token=token
    )
    assert status == 200
    assert len(payload["items"]) == 1
    assert payload["items"][0]["session_id"] == "sess-1"


def test_unknown_session_returns_404(client: ApiClient) -> None:
    _, token = make_key(client, name="v", role=Role.VIEWER)
    status, payload = client.json("GET", "/api/v1/sessions/nope", token=token)
    assert status == 404
    assert payload["error"]["code"] == "not_found"


def test_pcap_stream_starts_with_magic(client: ApiClient) -> None:
    _, token = make_key(client, name="a", role=Role.ANALYST)
    status, _, body = client.request("GET", "/api/v1/sessions/sess-1/pcap", token=token)
    assert status == 200
    assert body[:4] == b"\xd4\xc3\xb2\xa1"


def test_jsonl_stream_is_valid_gzip(client: ApiClient) -> None:
    _, token = make_key(client, name="a", role=Role.ANALYST)
    status, _, body = client.request("GET", "/api/v1/sessions/sess-1/jsonl.gz", token=token)
    assert status == 200
    decoded = gzip.decompress(body)
    assert b"sess-1" in decoded


def test_timeline_json_matches_service(client: ApiClient) -> None:
    _, token = make_key(client, name="a", role=Role.ANALYST)
    status, payload = client.json(
        "GET", "/api/v1/sessions/sess-1/timeline?format=json", token=token
    )
    assert status == 200
    assert payload["entries"][0]["kind"] == "connect"
