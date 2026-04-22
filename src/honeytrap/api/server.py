"""HTTP transport for the HoneyTrap management API.

The server is built on :mod:`http.server` and served from a background
thread (or threads) so health/metrics semantics match the existing
pattern in :mod:`honeytrap.ops.health`. The same pattern also keeps the
server responsive even when the honeypot asyncio loop is busy or
wedged.

Design notes
------------

* **Backend choice.** Stdlib ``http.server`` was chosen over ``aiohttp``
  because the management API is low-QPS, the feature set is tiny, and
  we want zero new hard dependencies. ``aiohttp`` remains available for
  callers but is never required here.
* **Threading model.** The server uses :class:`ThreadingHTTPServer` so
  long reads (streamed PCAP) do not head-of-line other requests.
* **Security headers.** Every response sets ``X-Content-Type-Options``,
  ``X-Frame-Options``, ``Referrer-Policy``, and (for authenticated
  endpoints) ``Cache-Control: no-store``. HSTS is sent when TLS is in
  use.
* **Request IDs.** Every request carries an ``X-Request-ID`` which is
  either echoed from the client (when safe) or freshly generated.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import re
import socket
import ssl
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from honeytrap.api.audit import AuditLog, AuditRecord, now_iso
from honeytrap.api.auth import (
    APIKey,
    APIKeyStore,
    ReplayCache,
    build_hmac_string,
    hash_key,
)
from honeytrap.api.config import APIConfig
from honeytrap.api.errors import (
    APIError,
    bad_request,
    forbidden,
    not_found,
    payload_too_large,
    rate_limited,
    unauthorized,
)
from honeytrap.api.openapi import build_docs_html, build_openapi
from honeytrap.api.rate_limit import RateLimiter
from honeytrap.api.rbac import Role, check_role
from honeytrap.api.router import Router
from honeytrap.api.service import HoneytrapService, public_api_key
from honeytrap.ops.health import MetricsRegistry

logger = logging.getLogger(__name__)

API_PREFIX = "/api/v1"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_ROLE_VIEWER = Role.VIEWER
_ROLE_ANALYST = Role.ANALYST
_ROLE_ADMIN = Role.ADMIN


@dataclass
class _RequestContext:
    """Per-request context threaded into every handler."""

    method: str
    path: str
    query: dict[str, list[str]]
    headers: Mapping[str, str]
    body: bytes
    remote_addr: str
    request_id: str
    api_key: APIKey | None = None
    role: Role | None = None
    hmac_used: bool = False

    def path_with_query(self) -> str:
        """Return the path plus original query string (for HMAC)."""
        if not self.query:
            return self.path
        parts: list[str] = []
        for k, values in self.query.items():
            for v in values:
                parts.append(f"{k}={v}")
        return f"{self.path}?{'&'.join(parts)}"


@dataclass
class _Response:
    """Return value of every handler."""

    status: int
    body: bytes
    content_type: str
    headers: dict[str, str]


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class APIServer:
    """Threaded HTTP server exposing ``/api/v1`` endpoints."""

    def __init__(
        self,
        service: HoneytrapService,
        key_store: APIKeyStore,
        config: APIConfig | None = None,
        *,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        """Create the server bound to ``service`` and ``key_store``."""
        self.service = service
        self.key_store = key_store
        self.config = config or APIConfig()
        self.metrics = metrics
        self._register_metrics()
        self.router = Router()
        self.rate_limiter = RateLimiter(self.config.rate_limits)
        self.replay_cache = ReplayCache()
        self.audit = AuditLog(self.config.state_path(self.config.audit_log_name))
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._started_at = time.time()
        self._openapi_cache: dict[str, Any] | None = None
        self._register_routes()

    # -- lifecycle -----------------------------------------------------
    @property
    def bound_host(self) -> str:
        """Return the host actually bound (may differ from config)."""
        if self._httpd is None:
            return self.config.host
        return self._httpd.server_address[0]

    @property
    def bound_port(self) -> int:
        """Return the port the server is listening on (0 when stopped)."""
        if self._httpd is None:
            return 0
        return self._httpd.server_address[1]

    @property
    def tls_enabled(self) -> bool:
        """True when both a cert and key were configured."""
        return bool(self.config.tls_cert and self.config.tls_key)

    def start(self) -> None:
        """Bind the socket and begin serving in a background thread."""
        if self._httpd is not None:
            return
        if self.config.host == "0.0.0.0" and not self.config.allow_external:
            raise RuntimeError("Refusing to bind 0.0.0.0 without allow_external=True in APIConfig")
        if self.tls_enabled is False:
            logger.warning(
                "API server starting without TLS; traffic is plaintext on %s:%s",
                self.config.host,
                self.config.port,
            )
        handler_cls = self._build_handler_class()
        self._httpd = ThreadingHTTPServer((self.config.host, self.config.port), handler_cls)
        if self.tls_enabled:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(
                certfile=str(self.config.tls_cert),
                keyfile=str(self.config.tls_key),
            )
            self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        self._started_at = time.time()
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="honeytrap-api",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "API server listening on %s://%s:%s",
            "https" if self.tls_enabled else "http",
            self.bound_host,
            self.bound_port,
        )

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the background server. Safe to call more than once."""
        if self._httpd is None:
            return
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("API server shutdown error: %s", exc)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._httpd = None
        self._thread = None

    def uptime_seconds(self) -> float:
        """Return wall-clock seconds since :meth:`start` completed."""
        return time.time() - self._started_at

    # -- internals -----------------------------------------------------
    def _register_metrics(self) -> None:
        if self.metrics is None:
            return
        self.metrics.register(
            "honeytrap_api_requests_total",
            "Total management-API requests, labelled by method, path, status, role.",
            "counter",
        )
        self.metrics.register(
            "honeytrap_api_request_duration_seconds",
            "Management-API request duration in seconds.",
            "histogram",
        )
        self.metrics.register(
            "honeytrap_api_auth_failures_total",
            "Management-API authentication failures, by reason.",
            "counter",
        )
        self.metrics.register(
            "honeytrap_api_rate_limited_total",
            "Management-API requests rejected by the rate limiter, by role.",
            "counter",
        )
        self.metrics.register(
            "honeytrap_api_keys_active",
            "Number of non-revoked management-API keys.",
            "gauge",
        )

    def _metric_inc(self, name: str, labels: dict[str, str] | None = None) -> None:
        if self.metrics is None:
            return
        self.metrics.inc_counter(name, labels=labels)

    def _metric_gauge(self, name: str, value: float) -> None:
        if self.metrics is None:
            return
        self.metrics.set_gauge(name, value)

    def _metric_observe(self, name: str, value: float) -> None:
        if self.metrics is None:
            return
        self.metrics.observe_histogram(name, value)

    # -- route registration -------------------------------------------
    def _register_routes(self) -> None:
        r = self.router

        @r.route(f"{API_PREFIX}/health", methods=["GET"], public=True, tags=["meta"])
        def _health(ctx: _RequestContext) -> _Response:
            """Liveness plus a tiny identity payload."""
            payload = {
                "status": "ok",
                "version": self.service.version(),
                "uptime_seconds": round(self.uptime_seconds(), 3),
                "build": "stdlib",
            }
            return _json_response(200, payload)

        @r.route(
            f"{API_PREFIX}/openapi.json",
            methods=["GET"],
            public=True,
            tags=["meta"],
        )
        def _openapi(ctx: _RequestContext) -> _Response:
            """Serve the OpenAPI 3.1 schema document."""
            return _json_response(200, self.openapi_document())

        @r.route(
            f"{API_PREFIX}/docs",
            methods=["GET"],
            public=True,
            tags=["meta"],
        )
        def _docs(ctx: _RequestContext) -> _Response:
            """Return the self-hosted Rapidoc UI HTML."""
            html = build_docs_html(spec_url=f"{API_PREFIX}/openapi.json")
            return _Response(200, html.encode("utf-8"), "text/html; charset=utf-8", {})

        # --- Sessions ---------------------------------------------------
        @r.route(f"{API_PREFIX}/sessions", methods=["GET"], role=_ROLE_VIEWER, tags=["sessions"])
        def _sessions(ctx: _RequestContext) -> _Response:
            """Paginated list of recorded sessions."""
            limit = _parse_limit(ctx.query)
            result = self.service.list_sessions(
                ip=_qp(ctx.query, "ip"),
                protocol=_qp(ctx.query, "protocol"),
                since=_qp(ctx.query, "since"),
                until=_qp(ctx.query, "until"),
                limit=limit,
                cursor=_qp(ctx.query, "cursor"),
            )
            return _json_response(200, {"items": result.items, "next_cursor": result.next_cursor})

        @r.route(
            f"{API_PREFIX}/sessions/{{session_id}}",
            methods=["GET"],
            role=_ROLE_VIEWER,
            tags=["sessions"],
        )
        def _session_get(ctx: _RequestContext, session_id: str) -> _Response:
            """Return a full session object including recorded events."""
            sess = self.service.get_session(session_id)
            if sess is None:
                raise not_found(f"session {session_id!r} not found")
            return _json_response(200, sess)

        @r.route(
            f"{API_PREFIX}/sessions/{{session_id}}/events",
            methods=["GET"],
            role=_ROLE_VIEWER,
            tags=["sessions"],
        )
        def _session_events(ctx: _RequestContext, session_id: str) -> _Response:
            """Paginate events for a single session."""
            if self.service.get_session(session_id) is None:
                raise not_found(f"session {session_id!r} not found")
            result = self.service.list_session_events(
                session_id,
                limit=_parse_limit(ctx.query),
                cursor=_qp(ctx.query, "cursor"),
            )
            return _json_response(200, {"items": result.items, "next_cursor": result.next_cursor})

        @r.route(
            f"{API_PREFIX}/sessions/{{session_id}}/timeline",
            methods=["GET"],
            role=_ROLE_ANALYST,
            tags=["sessions"],
        )
        def _session_timeline(ctx: _RequestContext, session_id: str) -> _Response:
            """Timeline reconstruction either as text or a JSON list."""
            if self.service.get_session(session_id) is None:
                raise not_found(f"session {session_id!r} not found")
            fmt = (_qp(ctx.query, "format") or "json").lower()
            if fmt not in {"json", "text"}:
                raise bad_request("format must be 'json' or 'text'")
            if fmt == "text":
                text = self.service.session_timeline(session_id, as_text=True)
                assert isinstance(text, str)
                return _Response(200, text.encode("utf-8"), "text/plain; charset=utf-8", {})
            data = self.service.session_timeline(session_id, as_text=False)
            assert isinstance(data, list)
            return _json_response(200, {"entries": data})

        @r.route(
            f"{API_PREFIX}/sessions/{{session_id}}/pcap",
            methods=["GET"],
            role=_ROLE_ANALYST,
            tags=["sessions"],
        )
        def _session_pcap(ctx: _RequestContext, session_id: str) -> _Response:
            """Stream the PCAP export for a session."""
            if self.service.get_session(session_id) is None:
                raise not_found(f"session {session_id!r} not found")
            data = self.service.session_pcap(session_id)
            return _Response(
                200,
                data,
                "application/vnd.tcpdump.pcap",
                {"Content-Disposition": f'attachment; filename="{session_id}.pcap"'},
            )

        @r.route(
            f"{API_PREFIX}/sessions/{{session_id}}/jsonl.gz",
            methods=["GET"],
            role=_ROLE_ANALYST,
            tags=["sessions"],
        )
        def _session_jsonl(ctx: _RequestContext, session_id: str) -> _Response:
            """Stream gzipped JSONL frames for a session."""
            if self.service.get_session(session_id) is None:
                raise not_found(f"session {session_id!r} not found")
            data = self.service.session_jsonl(session_id)
            return _Response(
                200,
                data,
                "application/gzip",
                {
                    "Content-Disposition": f'attachment; filename="{session_id}.jsonl.gz"',
                    "Content-Encoding": "gzip",
                },
            )

        # --- Alerts -----------------------------------------------------
        @r.route(f"{API_PREFIX}/alerts", methods=["GET"], role=_ROLE_VIEWER, tags=["alerts"])
        def _alerts(ctx: _RequestContext) -> _Response:
            """Paginated list of alerts with filters."""
            ack_raw = _qp(ctx.query, "acknowledged")
            ack_filter: bool | None = None
            if ack_raw is not None:
                ack_filter = ack_raw.lower() in {"true", "1", "yes"}
            result = self.service.list_alerts(
                severity=_qp(ctx.query, "severity"),
                since=_qp(ctx.query, "since"),
                acknowledged=ack_filter,
                limit=_parse_limit(ctx.query),
                cursor=_qp(ctx.query, "cursor"),
            )
            return _json_response(200, {"items": result.items, "next_cursor": result.next_cursor})

        @r.route(
            f"{API_PREFIX}/alerts/{{alert_id}}/ack",
            methods=["POST"],
            role=_ROLE_ANALYST,
            tags=["alerts"],
        )
        def _alert_ack(ctx: _RequestContext, alert_id: str) -> _Response:
            """Acknowledge an alert, optionally recording a note."""
            payload = _parse_json_body(ctx.body)
            note = payload.get("note") if isinstance(payload, dict) else None
            assert ctx.api_key is not None
            record = self.service.ack_alert(
                alert_id, actor=ctx.api_key.id, note=str(note) if note else None
            )
            if record is None:
                raise not_found(f"alert {alert_id!r} not found")
            return _json_response(200, record.to_json())

        # --- Intel ------------------------------------------------------
        @r.route(f"{API_PREFIX}/intel/attck", methods=["GET"], role=_ROLE_VIEWER, tags=["intel"])
        def _attck(ctx: _RequestContext) -> _Response:
            """Return ATT&CK technique counts."""
            return _json_response(200, {"counts": self.service.attck_counts()})

        @r.route(f"{API_PREFIX}/intel/iocs", methods=["GET"], role=_ROLE_VIEWER, tags=["intel"])
        def _iocs(ctx: _RequestContext) -> _Response:
            """Return IOCs filtered by type."""
            ioc_type = _qp(ctx.query, "type")
            return _json_response(200, {"items": self.service.iocs(ioc_type=ioc_type)})

        @r.route(f"{API_PREFIX}/intel/tls", methods=["GET"], role=_ROLE_VIEWER, tags=["intel"])
        def _tls(ctx: _RequestContext) -> _Response:
            """Return the top-N TLS fingerprints."""
            top_raw = _qp(ctx.query, "top") or "100"
            try:
                top = max(1, min(500, int(top_raw)))
            except ValueError as exc:
                raise bad_request("top must be an integer") from exc
            return _json_response(200, {"items": self.service.tls_top(top=top)})

        # --- AI / adaptive responder ------------------------------------
        @r.route(
            f"{API_PREFIX}/sessions/{{session_id}}/memory",
            methods=["GET"],
            role=_ROLE_VIEWER,
            tags=["ai"],
        )
        def _session_memory(ctx: _RequestContext, session_id: str) -> _Response:
            """Return the adaptive AI memory snapshot for a session."""
            memory = self.service.ai_session_memory(session_id)
            if memory is None:
                raise not_found(f"memory for session {session_id!r} not found")
            return _json_response(200, memory)

        @r.route(
            f"{API_PREFIX}/intel/intents",
            methods=["GET"],
            role=_ROLE_VIEWER,
            tags=["ai"],
        )
        def _intent_counts(ctx: _RequestContext) -> _Response:
            """Return the histogram of classified attacker intents."""
            return _json_response(200, {"counts": self.service.ai_intent_counts()})

        @r.route(
            f"{API_PREFIX}/ai/backends",
            methods=["GET"],
            role=_ROLE_VIEWER,
            tags=["ai"],
        )
        def _ai_backends(ctx: _RequestContext) -> _Response:
            """Return health of configured AI response backends."""
            return _json_response(200, {"backends": self.service.ai_backend_health()})

        # --- Metrics ----------------------------------------------------
        @r.route(
            f"{API_PREFIX}/metrics/prometheus",
            methods=["GET"],
            role=_ROLE_VIEWER,
            tags=["metrics"],
        )
        def _metrics_prom(ctx: _RequestContext) -> _Response:
            """Authenticated passthrough of the Prometheus exposition."""
            text = self.service.prometheus_text()
            return _Response(200, text.encode("utf-8"), "text/plain; version=0.0.4", {})

        @r.route(
            f"{API_PREFIX}/metrics/summary",
            methods=["GET"],
            role=_ROLE_VIEWER,
            tags=["metrics"],
        )
        def _metrics_summary(ctx: _RequestContext) -> _Response:
            """Return a small JSON metrics summary."""
            return _json_response(200, self.service.metrics_summary().to_json())

        # --- Profiles / config -----------------------------------------
        @r.route(f"{API_PREFIX}/profiles", methods=["GET"], role=_ROLE_VIEWER, tags=["config"])
        def _profiles(ctx: _RequestContext) -> _Response:
            """List known device profiles."""
            items = [p.to_json() for p in self.service.list_profiles()]
            return _json_response(200, {"items": items})

        @r.route(
            f"{API_PREFIX}/profiles/{{name}}",
            methods=["GET"],
            role=_ROLE_VIEWER,
            tags=["config"],
        )
        def _profile_get(ctx: _RequestContext, name: str) -> _Response:
            """Return a single profile by name."""
            prof = self.service.get_profile(name)
            if prof is None:
                raise not_found(f"profile {name!r} not found")
            return _json_response(200, prof.to_json())

        @r.route(
            f"{API_PREFIX}/profiles/reload",
            methods=["POST"],
            role=_ROLE_ADMIN,
            tags=["config"],
        )
        def _profile_reload(ctx: _RequestContext) -> _Response:
            """Trigger a graceful reload of the active profile."""
            return _json_response(200, self.service.reload_profile())

        @r.route(f"{API_PREFIX}/config", methods=["GET"], role=_ROLE_VIEWER, tags=["config"])
        def _config_get(ctx: _RequestContext) -> _Response:
            """Return the effective configuration with secrets redacted."""
            return _json_response(200, self.service.redacted_config())

        # --- API keys ---------------------------------------------------
        @r.route(f"{API_PREFIX}/apikeys", methods=["GET"], role=_ROLE_ADMIN, tags=["apikeys"])
        def _apikeys_list(ctx: _RequestContext) -> _Response:
            """List all API keys with secrets omitted."""
            items = [public_api_key(k).to_json() for k in self.key_store.list()]
            return _json_response(200, {"items": items})

        @r.route(f"{API_PREFIX}/apikeys", methods=["POST"], role=_ROLE_ADMIN, tags=["apikeys"])
        def _apikeys_create(ctx: _RequestContext) -> _Response:
            """Create a new API key, returning the plaintext token once."""
            payload = _parse_json_body(ctx.body)
            if not isinstance(payload, dict):
                raise bad_request("body must be a JSON object")
            name = str(payload.get("name") or "").strip()
            role_raw = str(payload.get("role") or "").strip()
            if not name:
                raise bad_request("name is required")
            try:
                role = Role.from_str(role_raw)
            except ValueError as exc:
                raise bad_request(str(exc)) from exc
            record, plaintext = self.key_store.create(name=name, role=role)
            self._metric_gauge("honeytrap_api_keys_active", self.key_store.count_active())
            return _json_response(
                201,
                {
                    "key": public_api_key(record).to_json(),
                    "token": plaintext,
                },
            )

        @r.route(
            f"{API_PREFIX}/apikeys/{{key_id}}",
            methods=["DELETE"],
            role=_ROLE_ADMIN,
            tags=["apikeys"],
        )
        def _apikeys_delete(ctx: _RequestContext, key_id: str) -> _Response:
            """Revoke an API key by id."""
            ok = self.key_store.revoke(key_id)
            if not ok:
                raise not_found(f"api key {key_id!r} not found")
            self._metric_gauge("honeytrap_api_keys_active", self.key_store.count_active())
            return _json_response(200, {"revoked": True, "id": key_id})

        # --- Control ----------------------------------------------------
        @r.route(
            f"{API_PREFIX}/control/pause",
            methods=["POST"],
            role=_ROLE_ADMIN,
            tags=["control"],
        )
        def _control_pause(ctx: _RequestContext) -> _Response:
            """Request the honeypot to pause accepting new sessions."""
            self.service.pause()
            return _json_response(200, {"paused": True})

        @r.route(
            f"{API_PREFIX}/control/resume",
            methods=["POST"],
            role=_ROLE_ADMIN,
            tags=["control"],
        )
        def _control_resume(ctx: _RequestContext) -> _Response:
            """Request the honeypot to resume accepting sessions."""
            self.service.resume()
            return _json_response(200, {"paused": False})

        @r.route(
            f"{API_PREFIX}/control/shutdown",
            methods=["POST"],
            role=_ROLE_ADMIN,
            tags=["control"],
        )
        def _control_shutdown(ctx: _RequestContext) -> _Response:
            """Trigger a graceful shutdown of the honeypot process."""
            self.service.shutdown()
            return _json_response(202, {"shutdown_requested": True})

    def openapi_document(self) -> dict[str, Any]:
        """Return (and cache) the OpenAPI 3.1 document for this server."""
        if self._openapi_cache is None:
            self._openapi_cache = build_openapi(self.router, version=self.service.version())
        return self._openapi_cache

    # -- request lifecycle --------------------------------------------
    def handle(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        remote_addr: str,
    ) -> _Response:
        """Core request dispatcher, exposed directly for unit testing."""
        started = time.monotonic()
        split = urlsplit(path)
        request_id = _derive_request_id(headers)
        ctx = _RequestContext(
            method=method.upper(),
            path=split.path,
            query=parse_qs(split.query, keep_blank_values=True),
            headers={k.lower(): v for k, v in headers.items()},
            body=body or b"",
            remote_addr=_resolve_remote_addr(remote_addr, headers, self.config.trusted_proxies),
            request_id=request_id,
        )
        response: _Response | None = None
        auth_reason: str | None = None
        try:
            self._enforce_body_cap(ctx)
            match = self.router.match(ctx.method, ctx.path)
            if match is None:
                raise not_found(f"no route for {ctx.method} {ctx.path}")
            route, params = match
            if ctx.method not in route.methods:
                raise APIError(
                    405,
                    "method_not_allowed",
                    f"{ctx.method} not allowed on {ctx.path}",
                    headers={"Allow": ",".join(sorted(route.methods))},
                )
            if not route.public:
                key, role, hmac_used = self._authenticate(ctx)
                ctx.api_key = key
                ctx.role = role
                ctx.hmac_used = hmac_used
                if route.required_role is not None and not check_role(role, route.required_role):
                    raise forbidden(f"role {role.value} cannot access {route.path}")
                self._enforce_rate_limit(ctx)
            response = route.handler(ctx, **params)
            if not isinstance(response, _Response):  # pragma: no cover -- defensive
                response = _json_response(
                    500,
                    {
                        "error": {
                            "code": "bad_handler",
                            "message": "handler did not return a response",
                        }
                    },
                )
        except APIError as exc:
            if exc.code == "unauthorized":
                auth_reason = "invalid_credentials"
                self._metric_inc(
                    "honeytrap_api_auth_failures_total",
                    labels={"reason": "invalid_credentials"},
                )
            response = _Response(
                exc.status,
                exc.to_bytes(request_id),
                "application/json; charset=utf-8",
                dict(exc.headers),
            )
        except Exception as exc:  # noqa: BLE001 -- contain and never leak
            logger.exception("Unhandled API error: %s", exc)
            response = _Response(
                500,
                APIError(500, "internal_error", "Internal server error").to_bytes(request_id),
                "application/json; charset=utf-8",
                {},
            )
        finally:
            duration = time.monotonic() - started
            self._post_response(ctx, response, duration, auth_reason)
        assert response is not None
        return response

    def _enforce_body_cap(self, ctx: _RequestContext) -> None:
        if len(ctx.body) > self.config.max_body_bytes:
            raise payload_too_large(self.config.max_body_bytes)

    def _authenticate(self, ctx: _RequestContext) -> tuple[APIKey, Role, bool]:
        token = _extract_token(ctx.headers)
        if not token:
            raise unauthorized("API key is required")
        key = self.key_store.lookup_by_token(token)
        if key is None:
            raise unauthorized("Invalid API key")
        hmac_used = False
        if self.config.require_hmac or "x-ht-signature" in ctx.headers:
            self._verify_hmac(ctx, token)
            hmac_used = True
        self.key_store.touch(key.id)
        return key, key.role, hmac_used

    def _verify_hmac(self, ctx: _RequestContext, token: str) -> None:
        sig = ctx.headers.get("x-ht-signature")
        ts = ctx.headers.get("x-ht-timestamp")
        if not sig or not ts:
            raise unauthorized("HMAC signing required but headers missing")
        try:
            ts_int = int(ts)
        except ValueError as exc:
            raise unauthorized("X-HT-Timestamp must be a unix timestamp") from exc
        now = int(time.time())
        if abs(now - ts_int) > self.config.hmac_skew_seconds:
            raise unauthorized("HMAC timestamp outside permitted skew")
        expected = _expected_hmac(token, ctx.method, ctx.path_with_query(), ts, ctx.body)
        if not hmac.compare_digest(expected.lower(), sig.lower()):
            raise unauthorized("HMAC signature mismatch")
        fingerprint = f"{hash_key(token)}:{sig}"
        if self.replay_cache.seen(fingerprint):
            raise unauthorized("HMAC signature replayed")
        self.replay_cache.remember(fingerprint)

    def _enforce_rate_limit(self, ctx: _RequestContext) -> None:
        assert ctx.api_key is not None and ctx.role is not None
        allowed, retry = self.rate_limiter.check(key_id=ctx.api_key.id, role=ctx.role.value)
        if not allowed:
            self._metric_inc(
                "honeytrap_api_rate_limited_total",
                labels={"role": ctx.role.value},
            )
            raise rate_limited(int(retry) + 1)

    def _post_response(
        self,
        ctx: _RequestContext,
        response: _Response | None,
        duration: float,
        auth_reason: str | None,
    ) -> None:
        if response is None:
            return
        body_digest = hashlib.sha256(ctx.body).hexdigest() if ctx.body else ""
        role = ctx.role.value if ctx.role else None
        record = AuditRecord(
            timestamp=now_iso(),
            method=ctx.method,
            path=ctx.path,
            status=response.status,
            api_key_id=ctx.api_key.id if ctx.api_key else None,
            role=role,
            remote_addr=ctx.remote_addr,
            user_agent=ctx.headers.get("user-agent", ""),
            body_sha256=body_digest,
            request_id=ctx.request_id,
            duration_ms=round(duration * 1000.0, 3),
            auth_reason=auth_reason,
        )
        if ctx.path not in (f"{API_PREFIX}/health",):
            self.audit.record(record)
        self._metric_inc(
            "honeytrap_api_requests_total",
            labels={
                "method": ctx.method,
                "path": ctx.path,
                "status": str(response.status),
                "role": role or "anonymous",
            },
        )
        self._metric_observe("honeytrap_api_request_duration_seconds", duration)
        if self.metrics is not None:
            self._metric_gauge("honeytrap_api_keys_active", self.key_store.count_active())

    # ------------------------------------------------------------------
    def _build_handler_class(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _fmt: str, *_args: Any) -> None:
                return

            def _handle(self) -> None:
                try:
                    length = int(self.headers.get("Content-Length") or "0")
                except ValueError:
                    length = 0
                if length > server.config.max_body_bytes:
                    _send_error_envelope(
                        self,
                        payload_too_large(server.config.max_body_bytes),
                        _derive_request_id(self.headers),
                        tls=server.tls_enabled,
                    )
                    return
                body = b""
                if length:
                    try:
                        body = self.rfile.read(length)
                    except OSError:
                        body = b""
                headers = dict(self.headers.items())
                response = server.handle(
                    method=self.command,
                    path=self.path,
                    headers=headers,
                    body=body,
                    remote_addr=self.client_address[0] if self.client_address else "",
                )
                _write_response(
                    self,
                    response,
                    headers.get("x-request-id") or _derive_request_id(self.headers),
                    tls=server.tls_enabled,
                )

            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def do_DELETE(self) -> None:  # noqa: N802
                self._handle()

            def do_PUT(self) -> None:  # noqa: N802
                self._handle()

        return _Handler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _qp(query: dict[str, list[str]], name: str) -> str | None:
    """Return the first value for a query param, or None."""
    values = query.get(name)
    if not values:
        return None
    return values[0]


def _parse_limit(query: dict[str, list[str]]) -> int:
    """Parse ``?limit=`` clamped to the server's default range."""
    raw = _qp(query, "limit")
    if raw is None:
        return 50
    try:
        value = int(raw)
    except ValueError as exc:
        raise bad_request("limit must be an integer") from exc
    return max(1, min(500, value))


def _json_response(status: int, payload: Any) -> _Response:
    """Return a :class:`_Response` carrying a JSON body."""
    body = json.dumps(payload, default=_default_json).encode("utf-8")
    return _Response(status, body, "application/json; charset=utf-8", {})


def _default_json(obj: Any) -> Any:
    """Fallback encoder for dataclasses and Path objects."""
    if hasattr(obj, "to_json"):
        return obj.to_json()
    if isinstance(obj, Path):
        return str(obj)
    raise TypeError(f"Cannot serialise {type(obj).__name__}")


def _parse_json_body(body: bytes) -> Any:
    """Decode a JSON body; empty body returns ``{}``."""
    if not body:
        return {}
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise bad_request("body must be valid JSON") from exc


def _extract_token(headers: Mapping[str, str]) -> str | None:
    """Pull the API token from ``X-API-Key`` or ``Authorization: Bearer``."""
    token = headers.get("x-api-key")
    if token:
        return token.strip()
    auth = headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _derive_request_id(headers: Mapping[str, str]) -> str:
    """Echo a sane ``X-Request-ID`` or generate a fresh UUID4."""
    headers_lc = {k.lower(): v for k, v in headers.items()}
    rid = headers_lc.get("x-request-id")
    if rid and _REQUEST_ID_RE.match(rid):
        return rid
    return str(uuid.uuid4())


def _resolve_remote_addr(remote_addr: str, headers: Mapping[str, str], trusted: list[str]) -> str:
    """Resolve the effective client IP.

    When the immediate peer is in ``trusted`` we honour ``X-Forwarded-For``;
    otherwise we keep the raw peer address to avoid header spoofing.
    """
    if remote_addr in trusted:
        xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return remote_addr


def _expected_hmac(token: str, method: str, path: str, timestamp: str, body: bytes) -> str:
    """Compute the expected hex HMAC-SHA-256 for a request."""
    canonical = build_hmac_string(method, path, timestamp, body).encode("utf-8")
    return hmac.new(token.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def _security_headers(*, tls: bool, public: bool) -> dict[str, str]:
    """Return the default security header set for every response."""
    base: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    if tls:
        base["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not public:
        base["Cache-Control"] = "no-store"
    return base


def _write_response(
    handler: BaseHTTPRequestHandler,
    response: _Response,
    request_id: str,
    *,
    tls: bool,
) -> None:
    """Serialise a :class:`_Response` onto the wire."""
    handler.send_response(response.status)
    for name, value in _security_headers(tls=tls, public=False).items():
        handler.send_header(name, value)
    for name, value in response.headers.items():
        handler.send_header(name, value)
    handler.send_header("Content-Type", response.content_type)
    handler.send_header("Content-Length", str(len(response.body)))
    handler.send_header("X-Request-ID", request_id)
    handler.end_headers()
    with contextlib.suppress(OSError, BrokenPipeError, ConnectionResetError, socket.error):
        handler.wfile.write(response.body)


def _send_error_envelope(
    handler: BaseHTTPRequestHandler,
    exc: APIError,
    request_id: str,
    *,
    tls: bool,
) -> None:
    """Write an :class:`APIError` envelope directly from a handler path."""
    body = exc.to_bytes(request_id)
    handler.send_response(exc.status)
    for name, value in _security_headers(tls=tls, public=False).items():
        handler.send_header(name, value)
    for name, value in exc.headers.items():
        handler.send_header(name, value)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Request-ID", request_id)
    handler.end_headers()
    with contextlib.suppress(OSError, BrokenPipeError, ConnectionResetError, socket.error):
        handler.wfile.write(body)


# Re-export small helpers used by tests via the package root.
__all__ = ["APIServer", "API_PREFIX"]
