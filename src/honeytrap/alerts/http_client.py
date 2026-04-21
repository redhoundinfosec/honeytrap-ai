"""Async HTTP client helpers used by webhook-based alert channels.

Prefers :mod:`aiohttp` when available (it already is in this project's
base deps). The stdlib fallback path is kept for completeness — if
``aiohttp`` is ever removed no channel suddenly breaks.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any

try:
    import aiohttp

    _HAS_AIOHTTP = True
except ImportError:  # pragma: no cover — exercised only when aiohttp is missing
    _HAS_AIOHTTP = False

logger = logging.getLogger(__name__)

_DEFAULT_CONNECT_TIMEOUT = 5.0
_DEFAULT_READ_TIMEOUT = 10.0
_RETRY_BACKOFF = (0.5, 1.0, 2.0)


@dataclass
class HttpResponse:
    """Minimal response container returned by :func:`post_json`."""

    status: int
    body: str
    headers: dict[str, str]


class HttpClientError(RuntimeError):
    """Raised when the HTTP client gives up after retries."""


async def post_json(
    url: str,
    payload: dict[str, Any] | list[Any],
    *,
    headers: dict[str, str] | None = None,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
    retries: int = 3,
    sleeper: Any = None,
) -> HttpResponse:
    """POST JSON to ``url`` with retries on 5xx / network errors.

    4xx responses are returned directly and do not trigger a retry.
    ``Retry-After`` headers are respected (integer seconds only).
    """
    body = json.dumps(payload).encode("utf-8")
    merged_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        merged_headers.update(headers)
    sleep = sleeper or asyncio.sleep

    last_exc: Exception | None = None
    backoff = list(_RETRY_BACKOFF)
    attempts = max(1, int(retries))

    for attempt in range(attempts):
        try:
            response = await _do_post(
                url,
                body,
                merged_headers,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
            )
        except Exception as exc:  # noqa: BLE001 — any network error triggers retry
            last_exc = exc
            if attempt + 1 >= attempts:
                raise HttpClientError(f"POST {url} failed: {exc}") from exc
            delay = backoff[min(attempt, len(backoff) - 1)]
            await sleep(delay)
            continue

        if 400 <= response.status < 500:
            # Don't retry 4xx — caller can inspect.
            return response

        if response.status >= 500:
            if attempt + 1 >= attempts:
                return response
            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
            delay = (
                retry_after if retry_after is not None else backoff[min(attempt, len(backoff) - 1)]
            )
            await sleep(delay)
            continue

        return response

    # Should be unreachable; kept to satisfy type checkers.
    if last_exc is not None:
        raise HttpClientError(str(last_exc)) from last_exc
    raise HttpClientError(f"POST {url} failed with no response")


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After value. Only integer-seconds form is supported."""
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


async def _do_post(
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    connect_timeout: float,
    read_timeout: float,
) -> HttpResponse:
    if _HAS_AIOHTTP:
        timeout = aiohttp.ClientTimeout(
            total=connect_timeout + read_timeout,
            connect=connect_timeout,
            sock_read=read_timeout,
        )
        async with aiohttp.ClientSession(timeout=timeout) as session:  # noqa: SIM117
            async with session.post(url, data=body, headers=headers) as resp:
                text = await resp.text()
                return HttpResponse(
                    status=resp.status,
                    body=text,
                    headers=dict(resp.headers.items()),
                )
    return await _do_post_stdlib(
        url, body, headers, connect_timeout=connect_timeout, read_timeout=read_timeout
    )


async def _do_post_stdlib(  # pragma: no cover — aiohttp is a runtime dep
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    connect_timeout: float,
    read_timeout: float,
) -> HttpResponse:
    import urllib.error
    import urllib.request

    def _sync() -> HttpResponse:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=connect_timeout + read_timeout) as resp:
                return HttpResponse(
                    status=resp.status,
                    body=resp.read().decode("utf-8", errors="replace"),
                    headers=dict(resp.headers.items()),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                status=exc.code,
                body=exc.read().decode("utf-8", errors="replace"),
                headers=dict(exc.headers.items()),
            )

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync)
