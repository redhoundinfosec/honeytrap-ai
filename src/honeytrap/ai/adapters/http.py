"""HTTP adapter — generates wire-correct HTTP/1.1 responses.

The adapter accepts a parsed HTTP request (method/path/headers/body
truncated to 8 KiB) via :class:`AdapterPrompt.extra` and returns a raw
``HTTP/1.1 ...\\r\\n...\\r\\n\\r\\n<body>`` blob. The response is
shaped to look authentic for the active profile:

* ``web_server`` -> nginx-style index page; absent paths -> 404 with
  the same Server header; ``/admin`` -> 302 redirect to ``/login``.
* ``iot_camera`` -> camera-UI shell with a small JS asset.
* Auth-required paths -> 401 with ``WWW-Authenticate: Basic``.
* Form POSTs -> 302 redirect with a CSRF cookie freshly minted from the
  session id.

Realism vs safety: the adapter never echoes back attacker-supplied
secrets (passwords, tokens, JWT-shaped values) or absolute filesystem
paths from the host. Every response carries a deterministic
``Content-Length`` matching the body it actually emits.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from honeytrap.ai.adapters.base import AdapterPrompt, BaseAdapter

_AUTH_REQUIRED_PATHS = (
    "/admin",
    "/manager",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/dashboard",
)
_NOT_FOUND_HINTS = (".env", ".git", "/etc/passwd", ".bak", ".old")
_REDIRECT_PATHS = ("/login", "/auth", "/signin")


@dataclass
class HttpRequestContext:
    """Subset of an HTTP request the adapter cares about."""

    method: str
    path: str
    headers: dict[str, str]
    body: str
    profile: str = "web_server"


class HttpAdapter(BaseAdapter):
    """HTTP/1.1 wire adapter."""

    protocol = "http"

    def template_response(self, prompt: AdapterPrompt) -> str:
        """Build a deterministic HTTP/1.1 response."""
        ctx = self._ctx(prompt)
        status, body, content_type, extra_headers = self._select_response(ctx, prompt)
        return self._format_response(status, body, content_type, ctx, prompt, extra_headers)

    def validate_shape(self, response: str) -> str:
        """Ensure the response has a status line and CRLF separators."""
        if not response:
            return ""
        if not response.startswith("HTTP/1.1 "):
            return ""
        head, sep, body = response.partition("\r\n\r\n")
        if not sep:
            return ""
        try:
            status_line = head.split("\r\n", 1)[0]
            parts = status_line.split(" ", 2)
            int(parts[1])
        except (IndexError, ValueError):
            return ""
        # Repair Content-Length if it disagrees with the body.
        header_lines = head.split("\r\n")
        out_headers: list[str] = []
        seen_cl = False
        for line in header_lines:
            if line.lower().startswith("content-length:"):
                seen_cl = True
                out_headers.append(f"Content-Length: {len(body.encode('utf-8'))}")
            else:
                out_headers.append(line)
        if not seen_cl:
            out_headers.insert(1, f"Content-Length: {len(body.encode('utf-8'))}")
        return "\r\n".join(out_headers) + "\r\n\r\n" + body

    def cache_key(self, prompt: AdapterPrompt) -> str:
        """Cache by method + path + profile only — bodies vary too much."""
        ctx = self._ctx(prompt)
        return f"{ctx.method}|{ctx.path}|{ctx.profile}"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _ctx(self, prompt: AdapterPrompt) -> HttpRequestContext:
        e = prompt.extra
        return HttpRequestContext(
            method=str(e.get("method", "GET")).upper(),
            path=str(e.get("path", "/")),
            headers={k.lower(): str(v) for k, v in (e.get("headers") or {}).items()},
            body=str(e.get("body", ""))[:8192],
            profile=str(prompt.persona.get("profile", "web_server")),
        )

    def _select_response(
        self, ctx: HttpRequestContext, prompt: AdapterPrompt
    ) -> tuple[int, str, str, dict[str, str]]:
        path = ctx.path.split("?", 1)[0]
        method = ctx.method
        # Sensitive-file probes — never reveal real content.
        if any(hint in path for hint in _NOT_FOUND_HINTS):
            return 404, self._not_found_body(path, prompt), "text/html", {}
        # Server-error probe sentinel for tests.
        if "/__error" in path:
            return 500, self._server_error_body(prompt), "text/html", {}
        # Auth gate -> 401 when credentials are absent, 403 when present.
        if any(path.startswith(p) for p in _AUTH_REQUIRED_PATHS):
            authz = ctx.headers.get("authorization", "")
            if not authz:
                return (
                    401,
                    "Unauthorized\r\n",
                    "text/plain",
                    {
                        "WWW-Authenticate": 'Basic realm="Restricted"',
                    },
                )
            return 403, "Forbidden\r\n", "text/plain", {}
        # Form POST handling.
        if method in {"POST", "PUT", "PATCH"} and any(path.startswith(p) for p in _REDIRECT_PATHS):
            csrf = self._csrf_cookie(prompt)
            return 302, "", "text/plain", {"Location": "/", "Set-Cookie": csrf}
        # Authentication landing pages -> 200 with a login form.
        if any(path.startswith(p) for p in _REDIRECT_PATHS):
            return (
                200,
                self._login_body(prompt),
                "text/html",
                {
                    "Set-Cookie": self._csrf_cookie(prompt),
                },
            )
        # Default index.
        return 200, self._index_body(ctx, prompt), "text/html", {}

    def _format_response(
        self,
        status: int,
        body: str,
        content_type: str,
        ctx: HttpRequestContext,
        prompt: AdapterPrompt,
        extra_headers: dict[str, str],
    ) -> str:
        reason = _STATUS_REASONS.get(status, "OK")
        server = str(prompt.persona.get("server_header") or self._infer_server(ctx.profile))
        date = datetime.now(tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        body_bytes = body.encode("utf-8")
        headers = [
            f"HTTP/1.1 {status} {reason}",
            f"Server: {server}",
            f"Date: {date}",
            f"Content-Type: {content_type}; charset=UTF-8",
            f"Content-Length: {len(body_bytes)}",
            f'ETag: "{self._etag(ctx)}"',
            "Connection: close",
        ]
        for name, value in extra_headers.items():
            headers.append(f"{name}: {value}")
        return "\r\n".join(headers) + "\r\n\r\n" + body

    @staticmethod
    def _infer_server(profile: str) -> str:
        if profile == "iot_camera":
            return "Hipcam Real Server/1.0"
        if profile == "iot_industrial":
            return "BoaServer/0.94.14rc21"
        if profile == "windows_workstation":
            return "Microsoft-IIS/10.0"
        return "nginx/1.18.0 (Ubuntu)"

    def _etag(self, ctx: HttpRequestContext) -> str:
        digest = hashlib.md5(f"{ctx.profile}|{ctx.path}".encode()).hexdigest()
        return digest[:16]

    def _csrf_cookie(self, prompt: AdapterPrompt) -> str:
        token = hashlib.sha256(
            (prompt.persona.get("session_id", "anon") or "anon").encode("utf-8")
        ).hexdigest()[:32]
        return f"csrf_token={token}; Path=/; HttpOnly; SameSite=Strict"

    @staticmethod
    def _not_found_body(path: str, prompt: AdapterPrompt) -> str:
        company = str(prompt.persona.get("company", "Acme Corp"))
        safe_path = path.replace("<", "&lt;").replace(">", "&gt;")
        return (
            "<!DOCTYPE html><html><head><title>404 Not Found</title></head>\n"
            f"<body><h1>Not Found</h1><p>{safe_path} was not found on this server.</p>"
            f"<hr><address>{company}</address></body></html>\r\n"
        )

    @staticmethod
    def _server_error_body(prompt: AdapterPrompt) -> str:
        company = str(prompt.persona.get("company", "Acme Corp"))
        return (
            "<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head>\n"
            f"<body><h1>Internal Server Error</h1><p>{company} application encountered "
            "an unexpected condition and could not complete the request.</p>"
            "<pre>Traceback (most recent call last):\n"
            '  File "/var/www/app/main.py", line 142, in handler\n'
            '    raise RuntimeError("upstream timeout")</pre>\n'
            "</body></html>\r\n"
        )

    @staticmethod
    def _login_body(prompt: AdapterPrompt) -> str:
        company = str(prompt.persona.get("company", "Acme Corp"))
        return (
            f"<!DOCTYPE html><html><head><title>{company} Login</title></head>\n"
            '<body><form method="POST" action="/login">'
            '<label>User: <input name="u"></label>'
            '<label>Pass: <input name="p" type="password"></label>'
            '<button type="submit">Sign in</button></form></body></html>\r\n'
        )

    def _index_body(self, ctx: HttpRequestContext, prompt: AdapterPrompt) -> str:
        company = str(prompt.persona.get("company", "Acme Corp"))
        if ctx.profile == "iot_camera":
            return (
                "<!DOCTYPE html><html><head><title>Network Camera</title></head>\n"
                '<body><div id="viewer"></div>'
                '<script src="/cgi-bin/viewer.js"></script></body></html>\r\n'
            )
        if ctx.profile == "iot_industrial":
            return (
                "<!DOCTYPE html><html><head><title>Industrial Gateway</title></head>\n"
                "<body><h1>Modbus / OPC UA Gateway</h1><p>Status: online</p></body></html>\r\n"
            )
        return (
            f"<!DOCTYPE html><html><head><title>Welcome to {company}</title></head>\n"
            f"<body><h1>{company}</h1><p>Internal services portal.</p>"
            '<ul><li><a href="/login">Sign in</a></li>'
            '<li><a href="/docs">API docs</a></li></ul></body></html>\r\n'
        )


_STATUS_REASONS: dict[int, str] = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def build_http_extra(
    *, method: str, path: str, headers: dict[str, str] | None = None, body: str = ""
) -> dict[str, Any]:
    """Helper for protocol handlers — returns a populated ``extra`` dict."""
    return {
        "method": method.upper(),
        "path": path,
        "headers": dict(headers or {}),
        "body": body,
    }
