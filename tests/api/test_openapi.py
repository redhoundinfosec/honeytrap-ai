"""OpenAPI schema generation tests."""

from __future__ import annotations

import json

from honeytrap.api.openapi import validate_openapi_document
from tests.api.conftest import ApiClient


def test_openapi_is_valid(client: ApiClient) -> None:
    status, _, raw = client.request("GET", "/api/v1/openapi.json")
    assert status == 200
    doc = json.loads(raw.decode("utf-8"))
    problems = validate_openapi_document(doc)
    assert problems == []
    assert doc["openapi"].startswith("3.")
    assert doc["components"]["securitySchemes"]["ApiKeyAuth"]["in"] == "header"


def test_all_routes_appear_with_roles(client: ApiClient) -> None:
    status, _, raw = client.request("GET", "/api/v1/openapi.json")
    assert status == 200
    doc = json.loads(raw.decode("utf-8"))
    paths = doc["paths"]
    for route in client.server.router.iter_routes():
        assert route.path in paths, f"Missing path: {route.path}"
        for method in route.methods:
            operation = paths[route.path][method.lower()]
            if not route.public:
                assert "security" in operation
                if route.required_role is not None:
                    assert operation["x-required-role"] == route.required_role.value
