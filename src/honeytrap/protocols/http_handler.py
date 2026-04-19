"""HTTP honeypot built on aiohttp.

Simulates an Apache 2.4.49 server with:

* Exposed admin panels (wp-login, phpMyAdmin, /admin, Tomcat manager, cPanel)
* Path traversal (CVE-2021-41773) returning a fake ``/etc/passwd``
* Exposed ``.env``, ``.git`` and ``phpinfo.php`` responses
* Directory listing for ``/files/``
* Scanner fingerprinting via user-agent
* Geo-aware content — company name, file names, locale hints vary
"""

from __future__ import annotations

import logging
from pathlib import Path

from aiohttp import web
from jinja2 import Environment, FileSystemLoader, select_autoescape

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


_TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "templates" / "http"


class HTTPHandler(ProtocolHandler):
    """aiohttp-backed HTTP honeypot."""

    name = "http"

    def __init__(self, service: ServiceSpec, engine) -> None:  # noqa: ANN001
        """Initialize the HTTP honeypot handler."""
        super().__init__(service, engine)
        self._runner: web.AppRunner | None = None
        self._site: web.BaseSite | None = None
        self._jinja = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        server_header = str(service.data.get("server_header") or service.banner or "Apache/2.4.49 (Ubuntu)")
        self.server_header = server_header

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self, bind_address: str, port: int) -> None:
        """Start the aiohttp web server and begin accepting connections."""
        self.bind_address = bind_address
        self.bound_port = port
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", self._dispatch)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, bind_address, port)
        try:
            await self._site.start()
        except OSError as exc:
            raise PortBindError(f"Could not bind HTTP on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Gracefully shut down the HTTP server."""
        if self._site is not None:
            await self._site.stop()
        if self._runner is not None:
            await self._runner.cleanup()

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    async def _dispatch(self, request: web.Request) -> web.StreamResponse:
        """Primary request handler for every incoming HTTP call."""
        try:
            return await self._handle(request)
        except Exception as exc:  # noqa: BLE001 — never crash a request
            logger.exception("HTTP handler error: %s", exc)
            body = self.engine.rules._apache_404(request.path)  # type: ignore[attr-defined]
            return web.Response(
                text=body,
                status=500,
                headers={"Server": self.server_header, "Content-Type": "text/html"},
            )

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        remote_ip = self._client_ip(request)
        remote_port = (request.transport.get_extra_info("peername") or ("", 0))[1]
        user_agent = request.headers.get("User-Agent", "")
        path = request.path_qs or "/"
        method = request.method

        # Body (for POST detection). Cap read to 16KB.
        body_text = ""
        if method in {"POST", "PUT", "PATCH"}:
            try:
                body_bytes = await request.content.read(16 * 1024)
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                body_text = ""

        geo = await self.resolve_geo(remote_ip)
        personality = self.engine.personalities.for_country(geo["country_code"])
        session = self.engine.sessions.create(remote_ip, remote_port, "http", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")

        match = self.engine.rules.match_http(
            method=method,
            path=request.path,
            user_agent=user_agent,
            remote_ip=remote_ip,
            body=body_text,
        )
        for tag in match.tags:
            session.add_tag(tag)

        # Log a request event
        event_type = "exploit_attempt" if "exploit_attempt" in match.tags else "http_request"
        await self.emit(
            Event(
                protocol="http",
                event_type=event_type,
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                session_id=session.session_id,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                path=request.path,
                method=method,
                user_agent=user_agent,
                message=f"{method} {request.path}",
                data={
                    "query_string": request.query_string,
                    "rule_category": match.category,
                    "tags": match.tags,
                    "body_size": len(body_text),
                    "personality": personality.key,
                },
            )
        )

        # Build response
        try:
            response = await self._render_response(match, path, personality, request)
        finally:
            self.engine.sessions.close(session.session_id)
        return response

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    async def _render_response(
        self, match, path, personality, request
    ) -> web.StreamResponse:
        """Turn a RuleMatch into an aiohttp Response."""
        headers = {"Server": self.server_header}

        if match.category == "path_traversal" or match.category == "sensitive_file":
            headers["Content-Type"] = "text/plain"
            return web.Response(
                text=match.response or "", status=match.status_code, headers=headers
            )

        if match.category == "admin_panel":
            admin_path = match.metadata.get("admin_path", "")
            template = self._admin_template(admin_path)
            body = self._render_template(
                template, path=request.path, personality=personality
            )
            headers["Content-Type"] = "text/html"
            return web.Response(text=body, status=200, headers=headers)

        if match.category == "not_found":
            headers["Content-Type"] = "text/html"
            return web.Response(text=match.response, status=404, headers=headers)

        # Default index page.
        body = self._render_template("index.html", path=request.path, personality=personality)
        headers["Content-Type"] = "text/html"
        return web.Response(text=body, status=200, headers=headers)

    def _admin_template(self, admin_path: str) -> str:
        if "wp-" in admin_path:
            return "wp-login.html"
        if "phpmyadmin" in admin_path or "pma" in admin_path or "dbadmin" in admin_path:
            return "phpmyadmin.html"
        if "manager" in admin_path:
            return "tomcat_manager.html"
        if "cpanel" in admin_path:
            return "cpanel.html"
        return "admin_generic.html"

    def _render_template(self, name: str, **kwargs) -> str:
        try:
            tpl = self._jinja.get_template(name)
        except Exception:  # noqa: BLE001
            return self._fallback_html(name, **kwargs)
        try:
            return tpl.render(**kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Template %s rendering failed: %s", name, exc)
            return self._fallback_html(name, **kwargs)

    def _fallback_html(self, name: str, **kwargs) -> str:
        personality = kwargs.get("personality")
        company = getattr(personality, "company", "Example Corp")
        return (
            f"<!DOCTYPE html><html><head><title>{company}</title></head>"
            f"<body><h1>{company}</h1><p>Internal portal</p></body></html>"
        )

    @staticmethod
    def _client_ip(request: web.Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        peer = request.transport.get_extra_info("peername") if request.transport else None
        if peer:
            return str(peer[0])
        return ""
