"""Generate an OpenAPI 3.1 schema from the :class:`~honeytrap.api.router.Router`.

The output is intentionally lightweight: we enumerate registered routes,
describe their path params, summaries, and role requirements, and emit
a security scheme for both the ``X-API-Key`` header and the optional
HMAC signing variant. A trimmed Rapidoc-based HTML UI is served at
``/api/v1/docs`` with an inline CDN URL; no frontend build pipeline is
required.
"""

from __future__ import annotations

from typing import Any

from honeytrap.api.router import Router

OPENAPI_VERSION = "3.1.0"


def build_openapi(
    router: Router, *, version: str, title: str = "HoneyTrap Management API"
) -> dict[str, Any]:
    """Return an OpenAPI 3.1 document describing every route in ``router``."""
    paths: dict[str, dict[str, Any]] = {}
    for route in router.iter_routes():
        path_item = paths.setdefault(route.path, {})
        for method in route.methods:
            operation: dict[str, Any] = {
                "summary": route.summary,
                "tags": list(route.tags) if route.tags else ["default"],
                "responses": {
                    "200": {"description": "Successful response"},
                    "401": {"description": "Missing or invalid API key"},
                    "403": {"description": "Role does not satisfy the requirement"},
                    "429": {"description": "Rate limit exceeded"},
                    "500": {"description": "Internal error"},
                },
            }
            if not route.public:
                security_schemes = [{"ApiKeyAuth": []}]
                security_schemes.append({"HmacAuth": []})
                operation["security"] = security_schemes
                if route.required_role is not None:
                    operation["x-required-role"] = route.required_role.value
            parameters: list[dict[str, Any]] = []
            for name in route.param_names:
                parameters.append(
                    {
                        "name": name,
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                )
            if parameters:
                operation["parameters"] = parameters
            path_item[method.lower()] = operation
    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": title,
            "version": version,
            "description": (
                "HoneyTrap AI management REST API. Authenticate with an "
                "API key using either the X-API-Key header or HMAC-signed "
                "requests (X-API-Key + X-HT-Timestamp + X-HT-Signature)."
            ),
        },
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                },
                "HmacAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-HT-Signature",
                    "description": ("Hex HMAC-SHA256 of 'METHOD|path|timestamp|sha256(body)'."),
                },
            }
        },
        "paths": paths,
    }


RAPIDOC_HTML = """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>HoneyTrap API Docs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <script
      type="module"
      src="https://unpkg.com/rapidoc@9.3.4/dist/rapidoc-min.js"
      integrity="sha384-J9PdESuqL7jI2m8SmWV1BiN8ZfnCM8QKy4IEe2YwzLGGZ8GwdTJrq8mV7VgIFEF5"
      crossorigin="anonymous"
    ></script>
    <style>
      body {{
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }}
    </style>
  </head>
  <body>
    <rapi-doc
      spec-url="{spec_url}"
      theme="dark"
      render-style="read"
      show-header="false"
      allow-try="true"
      regular-font="-apple-system, Segoe UI, sans-serif"
      mono-font="SFMono-Regular, Menlo, monospace"
      nav-bg-color="#1f2937"
      primary-color="#38bdf8"
    ></rapi-doc>
  </body>
</html>
"""


def build_docs_html(*, spec_url: str) -> str:
    """Return the self-contained HTML page that mounts Rapidoc."""
    return RAPIDOC_HTML.format(spec_url=spec_url)


def validate_openapi_document(doc: dict[str, Any]) -> list[str]:
    """Return a list of structural problems in ``doc``.

    This is a minimal sanity check: full OpenAPI 3.1 validation requires
    a JSON-schema engine we don't want to add as a dep. The checks are
    enough to fail loudly when a developer breaks the schema while
    editing routes.
    """
    problems: list[str] = []
    if str(doc.get("openapi", "")).split(".")[0] not in {"3"}:
        problems.append("openapi version must be 3.x")
    info = doc.get("info")
    if not isinstance(info, dict) or not info.get("title") or not info.get("version"):
        problems.append("info.title and info.version are required")
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        problems.append("paths must be a non-empty object")
    components = doc.get("components", {})
    if "securitySchemes" not in components:
        problems.append("components.securitySchemes is required")
    return problems
