"""Tests for the ``/api/v1/intel/stix`` and TAXII 2.1 endpoints."""

from __future__ import annotations

import json

from honeytrap.api.rbac import Role
from honeytrap.api.taxii import COLLECTION_IDS, TAXII_CONTENT_TYPE, TAXII_PREFIX

from .conftest import ApiClient, make_key


def _seed(client: ApiClient) -> None:
    """Populate the in-memory service with a session, IOCs, technique, and TLS match."""
    client.service.set_stix_techniques(
        [
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        ]
    )
    client.service.set_stix_tls([{"ja3": "a" * 32, "ja4": "t13d", "label": "nmap"}])


# ---------------------------------------------------------------------------
# /api/v1/intel/stix
# ---------------------------------------------------------------------------


def test_stix_endpoint_requires_analyst_role(client: ApiClient) -> None:
    _seed(client)
    _, viewer_token = make_key(client, name="viewer", role=Role.VIEWER)
    status, _, _ = client.request("GET", "/api/v1/intel/stix", token=viewer_token)
    assert status == 403


def test_stix_endpoint_returns_bundle(client: ApiClient) -> None:
    _seed(client)
    _, analyst_token = make_key(client, name="a", role=Role.ANALYST)
    status, body = client.json("GET", "/api/v1/intel/stix", token=analyst_token)
    assert status == 200
    assert body["type"] == "bundle"
    assert body["id"].startswith("bundle--")
    types = {obj["type"] for obj in body["objects"]}
    assert "identity" in types
    assert "indicator" in types  # session sess-1 has IOCs
    assert "attack-pattern" in types


def test_stix_endpoint_filters_by_session(client: ApiClient) -> None:
    _seed(client)
    _, analyst_token = make_key(client, name="a", role=Role.ANALYST)
    status, body = client.json("GET", "/api/v1/intel/stix?session_id=sess-1", token=analyst_token)
    assert status == 200
    types = {o["type"] for o in body["objects"]}
    assert "infrastructure" in types
    campaigns = [o for o in body["objects"] if o["type"] == "campaign"]
    assert any("203.0.113.5" in (c.get("name") or "") for c in campaigns)


def test_stix_endpoint_filters_by_ip(client: ApiClient) -> None:
    _seed(client)
    client.service.set_iocs([{"type": "ip", "value": "203.0.113.5", "session_id": "sess-1"}])
    _, analyst_token = make_key(client, name="a", role=Role.ANALYST)
    status, body = client.json("GET", "/api/v1/intel/stix?ip=203.0.113.5", token=analyst_token)
    assert status == 200
    indicators = [o for o in body["objects"] if o["type"] == "indicator"]
    assert any("203.0.113.5" in i.get("pattern", "") for i in indicators)


# ---------------------------------------------------------------------------
# TAXII 2.1
# ---------------------------------------------------------------------------


def test_taxii_discovery_returns_taxii_content_type(client: ApiClient) -> None:
    _seed(client)
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    status, headers, body = client.request("GET", f"{TAXII_PREFIX}/", token=viewer_token)
    assert status == 200
    assert headers["Content-Type"] == TAXII_CONTENT_TYPE
    payload = json.loads(body.decode("utf-8"))
    assert payload["api_roots"] == [f"{TAXII_PREFIX}/honeytrap/"]


def test_taxii_root_and_collections(client: ApiClient) -> None:
    _seed(client)
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    status, body = client.json("GET", f"{TAXII_PREFIX}/honeytrap/", token=viewer_token)
    assert status == 200
    assert body["versions"] == [TAXII_CONTENT_TYPE]
    status, body = client.json("GET", f"{TAXII_PREFIX}/honeytrap/collections/", token=viewer_token)
    assert status == 200
    ids = {c["id"] for c in body["collections"]}
    assert COLLECTION_IDS["indicators"] in ids
    assert COLLECTION_IDS["attack-patterns"] in ids


def test_taxii_objects_returns_only_collection_types(client: ApiClient) -> None:
    _seed(client)
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    cid = COLLECTION_IDS["attack-patterns"]
    status, body = client.json(
        "GET",
        f"{TAXII_PREFIX}/honeytrap/collections/{cid}/objects/",
        token=viewer_token,
    )
    assert status == 200
    assert all(o["type"] == "attack-pattern" for o in body["objects"])
    assert any(o["external_references"][0]["external_id"] == "T1110" for o in body["objects"])


def test_taxii_objects_paginates_with_limit(client: ApiClient) -> None:
    _seed(client)
    # Add many techniques so pagination has something to chew on.
    client.service.set_stix_techniques(
        [{"id": f"T{1000 + i}", "name": f"tech{i}"} for i in range(5)]
    )
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    cid = COLLECTION_IDS["attack-patterns"]
    status, body = client.json(
        "GET",
        f"{TAXII_PREFIX}/honeytrap/collections/{cid}/objects/?limit=2",
        token=viewer_token,
    )
    assert status == 200
    assert len(body["objects"]) == 2
    assert body["more"] is True
    assert "next" in body
    next_token = body["next"]
    status, body2 = client.json(
        "GET",
        f"{TAXII_PREFIX}/honeytrap/collections/{cid}/objects/?limit=2&next={next_token}",
        token=viewer_token,
    )
    assert status == 200
    assert len(body2["objects"]) >= 1


def test_taxii_unknown_collection_returns_404(client: ApiClient) -> None:
    _seed(client)
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    status, _, _ = client.request(
        "GET",
        f"{TAXII_PREFIX}/honeytrap/collections/00000000-0000-0000-0000-000000000000/",
        token=viewer_token,
    )
    assert status == 404


def test_taxii_manifest_returns_metadata_entries(client: ApiClient) -> None:
    _seed(client)
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    cid = COLLECTION_IDS["indicators"]
    status, body = client.json(
        "GET",
        f"{TAXII_PREFIX}/honeytrap/collections/{cid}/manifest/",
        token=viewer_token,
    )
    assert status == 200
    if body["objects"]:
        entry = body["objects"][0]
        assert "id" in entry
        assert entry["media_type"] == "application/stix+json;version=2.1"


def test_taxii_status_endpoint(client: ApiClient) -> None:
    _, viewer_token = make_key(client, name="v", role=Role.VIEWER)
    status, body = client.json(
        "GET", f"{TAXII_PREFIX}/honeytrap/status/abcd-1234/", token=viewer_token
    )
    assert status == 200
    assert body["status"] == "complete"


def test_taxii_requires_authentication(client: ApiClient) -> None:
    status, _, _ = client.request("GET", f"{TAXII_PREFIX}/")
    assert status == 401
