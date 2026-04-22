"""Tiny stdlib-only HTTP JSON helper used by the LLM backends.

We intentionally avoid httpx/requests so this feature adds zero runtime
deps. All network IO is pushed off the event loop with
:func:`asyncio.to_thread`; timeouts are enforced per-call so a hung
backend cannot stall the honeypot.
"""

from __future__ import annotations

import asyncio
import json as _json
from dataclasses import dataclass
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request


@dataclass
class HTTPResponse:
    """Minimal HTTP response envelope used by the LLM backends."""

    status: int
    body: bytes
    error: str | None = None

    def json(self) -> Any:
        """Parse ``body`` as JSON, returning ``{}`` on failure."""
        if not self.body:
            return {}
        try:
            return _json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}


async def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    connect_timeout: float = 3.0,
    read_timeout: float = 10.0,
) -> HTTPResponse:
    """POST ``payload`` as JSON and return the response envelope.

    The call is wrapped in ``asyncio.to_thread`` so blocking ``urlopen``
    doesn't stall the protocol handler's event loop. ``connect_timeout``
    is advisory — stdlib collapses both timeouts into one, so we use the
    larger of the two as the overall deadline and surface the distinction
    only in the docstring.
    """
    body = _json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib_request.Request(url, data=body, headers=req_headers, method="POST")
    timeout = max(connect_timeout, read_timeout)

    def _call() -> HTTPResponse:
        try:
            with urllib_request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return HTTPResponse(status=resp.status, body=resp.read())
        except urllib_error.HTTPError as exc:
            try:
                data = exc.read()
            except Exception:  # noqa: BLE001
                data = b""
            return HTTPResponse(status=exc.code, body=data, error=str(exc))
        except urllib_error.URLError as exc:
            return HTTPResponse(status=0, body=b"", error=str(exc))
        except TimeoutError as exc:
            return HTTPResponse(status=0, body=b"", error=f"timeout: {exc}")
        except Exception as exc:  # noqa: BLE001
            return HTTPResponse(status=0, body=b"", error=str(exc))

    return await asyncio.to_thread(_call)
