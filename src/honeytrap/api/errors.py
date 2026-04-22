"""Standardised HTTP error envelopes for the management API.

Every error response shares the shape::

    {"error": {"code": "STR", "message": "STR", "request_id": "UUID"}}

Handlers raise :class:`APIError` (or one of its helpers) and the
middleware converts it to the envelope plus the correct HTTP status.
The request id is either the value of ``X-Request-ID`` from the caller
(when supplied and sane) or a server-generated UUID4.
"""

from __future__ import annotations

import json
from typing import Any


class APIError(Exception):
    """Structured error raised by handlers to produce a JSON envelope."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        extra: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Create an error with HTTP ``status`` and machine-readable ``code``."""
        super().__init__(message)
        self.status = int(status)
        self.code = code
        self.message = message
        self.extra: dict[str, Any] = dict(extra or {})
        self.headers: dict[str, str] = dict(headers or {})

    def envelope(self, request_id: str) -> dict[str, Any]:
        """Build the canonical JSON envelope for this error."""
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "request_id": request_id,
        }
        if self.extra:
            payload.update(self.extra)
        return {"error": payload}

    def to_bytes(self, request_id: str) -> bytes:
        """Return the JSON-encoded envelope as UTF-8 bytes."""
        return json.dumps(self.envelope(request_id)).encode("utf-8")


def bad_request(message: str, *, code: str = "bad_request") -> APIError:
    """400 helper."""
    return APIError(400, code, message)


def unauthorized(message: str = "Authentication required") -> APIError:
    """401 helper. Emits a ``WWW-Authenticate`` hint for API keys."""
    return APIError(
        401,
        "unauthorized",
        message,
        headers={"WWW-Authenticate": 'Bearer realm="honeytrap-api"'},
    )


def forbidden(message: str = "Insufficient role") -> APIError:
    """403 helper."""
    return APIError(403, "forbidden", message)


def not_found(message: str = "Resource not found") -> APIError:
    """404 helper."""
    return APIError(404, "not_found", message)


def payload_too_large(limit: int) -> APIError:
    """413 helper referencing the configured limit in bytes."""
    return APIError(
        413,
        "payload_too_large",
        f"Request body exceeds the {limit}-byte limit",
    )


def rate_limited(retry_after: int) -> APIError:
    """429 helper that sets ``Retry-After`` to the seconds until reset."""
    return APIError(
        429,
        "rate_limited",
        "Rate limit exceeded",
        headers={"Retry-After": str(int(max(1, retry_after)))},
    )
