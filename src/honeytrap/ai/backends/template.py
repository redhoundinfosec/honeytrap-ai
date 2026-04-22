"""Deterministic zero-dep template backend.

The template backend is the always-available safety net for the adapter
chain. It does not reach out to any network service, so it cannot fail in
operational ways; it always returns ``shape_ok=True`` output tailored to
the protocol and the session persona.

Values are derived from a seeded PRNG keyed on the session id so the same
session sees the same hostname / uptime / process list across every turn
— attackers re-running a probe on a live session get consistent output.

Only a tiny ``${var}`` substitution engine is implemented on purpose: we
do not want to pull in Jinja or any other templating library, and this
level of complexity is enough for the per-protocol templates we ship.
"""

from __future__ import annotations

import hashlib
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from honeytrap.ai.backends.base import ResponseBackend, ResponseRequest, ResponseResult

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
_PLACEHOLDER_RE = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _substitute(template: str, context: dict[str, Any]) -> str:
    """Replace ``${var}`` tokens in ``template`` using ``context``.

    Unknown placeholders are left intact so template-authoring mistakes
    surface visibly rather than silently producing empty strings.
    """

    def _resolve(match: re.Match[str]) -> str:
        key = match.group(1)
        value = context.get(key)
        if value is None:
            return match.group(0)
        return str(value)

    return _PLACEHOLDER_RE.sub(_resolve, template)


class TemplateBackend(ResponseBackend):
    """Deterministic per-protocol template generator."""

    name = "template"

    def __init__(self, prompts_dir: str | Path | None = None) -> None:
        """Resolve the prompts directory with a fallback to the bundled copy."""
        self.prompts_dir = Path(prompts_dir) if prompts_dir else _PROMPTS_DIR

    def _load_template(self, protocol: str) -> str:
        path = self.prompts_dir / f"{protocol}.txt"
        if not path.exists():
            path = _PROMPTS_DIR / f"{protocol}.txt"
        if not path.exists():
            return ""
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""

    def _rng(self, session_id: str) -> random.Random:
        seed_bytes = hashlib.sha256(session_id.encode("utf-8") or b"seed").digest()
        seed = int.from_bytes(seed_bytes[:8], "big")
        return random.Random(seed)

    def _build_context(self, request: ResponseRequest) -> dict[str, Any]:
        rng = self._rng(request.session_id or "default")
        persona = request.persona or {}
        hostname = persona.get(
            "hostname",
            f"srv-{rng.choice(['ord', 'iad', 'sfo', 'lhr', 'fra'])}-{rng.randint(1, 99):02d}",
        )
        user = persona.get("user", "root")
        kernel = persona.get("kernel", f"5.{rng.randint(4, 15)}.0-{rng.randint(30, 90)}-generic")
        build_date = persona.get("build_date", "Thu Apr 4 18:22:11 UTC 2026")
        uptime_minutes = persona.get("uptime_minutes", rng.randint(120, 50_000))
        uptime_line = (
            f"{datetime.now(tz=timezone.utc).strftime('%H:%M:%S')} up "
            f"{uptime_minutes // 1440}d, load average: "
            f"{rng.random() * 0.5:.2f}, {rng.random() * 0.5:.2f}, {rng.random() * 0.5:.2f}"
        )
        server_header = persona.get("server_header", "Apache/2.4.41 (Ubuntu)")
        http_date = datetime.now(tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        path = request.inbound.split(" ")[1] if request.inbound.startswith("GET ") else "/"
        body_hint = persona.get("body_hint", hostname)
        content_body = (
            f"<html><head><title>404 Not Found</title></head>\n"
            f"<body><h1>Not Found</h1><p>The requested URL {path} was not found on {body_hint}.</p></body></html>\n"
        )
        ctx = {
            "hostname": hostname,
            "user": user,
            "kernel": kernel,
            "build_date": build_date,
            "uptime_line": uptime_line,
            "server_header": server_header,
            "http_date": http_date,
            "path": path,
            "content_length": len(content_body),
            "remote_ip": request.memory_snapshot.get("source_ip", "0.0.0.0"),
            "last_login": datetime.now(tz=timezone.utc).strftime("%a %b %e %H:%M:%S %Y"),
        }
        # Allow persona keys to override defaults for consistent-over-turns output.
        ctx.update({k: v for k, v in persona.items() if v is not None})
        return ctx

    async def generate(self, request: ResponseRequest) -> ResponseResult:
        """Render the appropriate template for ``request``."""
        start = time.time()
        template_body = self._load_template(request.protocol.lower())
        context = self._build_context(request)
        rendered = _substitute(template_body, context) if template_body else ""
        if not rendered:
            rendered = self._fallback_for(request.protocol.lower(), context)
        return ResponseResult(
            content=rendered,
            latency_ms=self._elapsed_ms(start),
            tokens_used=len(rendered.split()),
            backend_name=self.name,
            cached=False,
            shape_ok=True,
        )

    @staticmethod
    def _fallback_for(protocol: str, context: dict[str, Any]) -> str:
        """Minimal last-ditch response when no template file is found."""
        if protocol in {"http", "https"}:
            return (
                "HTTP/1.1 404 Not Found\r\n"
                f"Server: {context.get('server_header', 'nginx')}\r\n"
                f"Date: {context.get('http_date', '')}\r\n"
                "Content-Length: 9\r\n"
                "Connection: close\r\n\r\nNot Found"
            )
        if protocol == "smtp":
            return f"250 {context.get('hostname', 'localhost')} OK\r\n"
        if protocol in {"ssh", "telnet"}:
            return ""
        return ""
