"""Tiny async HTTP helper used by network sinks.

Sinks must not pull in ``aiohttp``; we only need POST with optional
auth, a timeout, and a 429 ``Retry-After`` honoring path. We wrap
:mod:`urllib.request` calls in ``asyncio.to_thread`` so the event
loop is not blocked.

Authorization headers are intentionally never logged. URLs are
validated to be ``http`` / ``https`` so a config typo cannot cause a
``file://`` read.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MiB cap on captured response bodies


class HttpError(RuntimeError):
    """Raised by :func:`post_json` for non-2xx responses or transport faults."""

    def __init__(self, status: int, message: str, *, retry_after: float | None = None) -> None:
        """Capture the status code, message, and optional Retry-After hint."""
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.retry_after = retry_after


@dataclass
class HttpResponse:
    """The bits of an HTTP response sinks actually look at."""

    status: int
    body: bytes
    headers: dict[str, str]


def _validate_url(url: str) -> None:
    """Reject URLs we won't talk to, to neutralise SSRF / typo footguns."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError(f"URL missing host: {url!r}")


def _build_ssl_context(verify: bool, ca_cert: str | None) -> ssl.SSLContext | None:
    """Return an SSL context honoring verify + optional CA bundle."""
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_cert:
        return ssl.create_default_context(cafile=ca_cert)
    return None


async def post_json(
    url: str,
    body: bytes,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    verify_tls: bool = True,
    ca_cert: str | None = None,
    expected_2xx: bool = True,
) -> HttpResponse:
    """POST ``body`` to ``url`` and return the response.

    Raises:
        HttpError: when ``expected_2xx`` is True and status is >= 300.
    """
    _validate_url(url)
    final_headers = {"Content-Type": "application/json"}
    if headers:
        final_headers.update(headers)

    def _do() -> HttpResponse:
        request = urllib.request.Request(url, data=body, headers=final_headers, method="POST")
        ctx = _build_ssl_context(verify_tls, ca_cert)
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=ctx) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raw = raw[:MAX_RESPONSE_BYTES]
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return HttpResponse(status=resp.status, body=raw, headers=hdrs)
        except urllib.error.HTTPError as exc:
            raw = b""
            with contextlib.suppress(Exception):
                raw = exc.read(MAX_RESPONSE_BYTES + 1)
            retry_after_header = exc.headers.get("Retry-After") if exc.headers else None
            retry_after: float | None = None
            if retry_after_header:
                try:
                    retry_after = float(retry_after_header)
                except ValueError:
                    retry_after = None
            raise HttpError(
                exc.code,
                _safe_message(raw),
                retry_after=retry_after,
            ) from exc
        except urllib.error.URLError as exc:
            raise HttpError(0, f"transport error: {exc.reason}") from exc

    response = await asyncio.to_thread(_do)
    if expected_2xx and not (200 <= response.status < 300):
        raise HttpError(response.status, _safe_message(response.body))
    return response


def _safe_message(raw: bytes) -> str:
    """Trim and decode an error body for logging without leaking secrets."""
    try:
        text = raw[:512].decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 -- defensive
        text = "<undecodable>"
    return text.strip() or "<empty body>"


async def sleep_for_retry_after(retry_after: float | None, *, default: float) -> None:
    """Sleep for ``retry_after`` if set, else for ``default`` seconds."""
    delay = retry_after if (retry_after and retry_after > 0) else default
    delay = min(60.0, max(0.0, delay))
    await asyncio.sleep(delay)


def now_monotonic() -> float:
    """Monotonic clock indirection for tests."""
    return time.monotonic()
