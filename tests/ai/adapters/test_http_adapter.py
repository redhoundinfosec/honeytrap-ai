"""HTTP adapter tests — Cycle 16."""

from __future__ import annotations

import re

from honeytrap.ai.adapters import AdapterPrompt, HttpAdapter

from .conftest import make_extra, run


def _do(adapter: HttpAdapter, **req: object) -> str:
    extra = make_extra(method=req.get("method", "GET"), path=req.get("path", "/"))
    extra["headers"] = req.get("headers", {})
    extra["body"] = req.get("body", "")
    persona = dict(req.get("persona", {}))
    return run(
        adapter.respond(
            "sess-1",
            AdapterPrompt(
                inbound=f"{extra['method']} {extra['path']}",
                persona=persona,
                extra=extra,
            ),
        )
    ).content


def _status(raw: str) -> int:
    return int(raw.split(" ", 2)[1])


def test_template_only_returns_200_index() -> None:
    raw = _do(HttpAdapter(enabled=False))
    assert raw.startswith("HTTP/1.1 200 OK\r\n")
    assert "Content-Length:" in raw
    assert "Content-Type: text/html" in raw


def test_admin_path_yields_401_when_unauthenticated() -> None:
    raw = _do(HttpAdapter(enabled=False), path="/admin")
    assert _status(raw) == 401
    assert 'WWW-Authenticate: Basic realm="Restricted"' in raw


def test_admin_path_with_authorization_yields_403() -> None:
    raw = _do(
        HttpAdapter(enabled=False),
        path="/admin",
        headers={"Authorization": "Basic Zm9vOmJhcg=="},
    )
    assert _status(raw) == 403


def test_login_post_returns_302_with_csrf_cookie() -> None:
    raw = _do(HttpAdapter(enabled=False), method="POST", path="/login", body="u=a&p=b")
    assert _status(raw) == 302
    assert "Location: /" in raw
    assert "Set-Cookie: csrf_token=" in raw


def test_login_get_returns_login_form_with_cookie() -> None:
    raw = _do(HttpAdapter(enabled=False), path="/login")
    assert _status(raw) == 200
    assert "<form" in raw
    assert "Set-Cookie: csrf_token=" in raw


def test_sensitive_file_returns_404() -> None:
    raw = _do(HttpAdapter(enabled=False), path="/.env")
    assert _status(raw) == 404
    assert "Not Found" in raw


def test_server_error_path_returns_500_traceback() -> None:
    raw = _do(HttpAdapter(enabled=False), path="/__error")
    assert _status(raw) == 500
    assert "Traceback" in raw


def test_iot_camera_profile_uses_camera_server_header() -> None:
    raw = _do(HttpAdapter(enabled=False), persona={"profile": "iot_camera"})
    assert "Server: Hipcam Real Server/1.0" in raw
    assert '<div id="viewer"' in raw


def test_iot_industrial_profile_marks_modbus_landing() -> None:
    raw = _do(HttpAdapter(enabled=False), persona={"profile": "iot_industrial"})
    assert "Server: BoaServer" in raw
    assert "Modbus" in raw


def test_windows_profile_uses_iis_header() -> None:
    raw = _do(HttpAdapter(enabled=False), persona={"profile": "windows_workstation"})
    assert "Server: Microsoft-IIS/10.0" in raw


def test_safety_filter_blocks_password_echo() -> None:
    extra = make_extra(method="POST", path="/login", body="user=root&password=topsekret")
    extra["headers"] = {}
    extra["body"] = "user=root&password=topsekret"

    class _EchoAdapter(HttpAdapter):
        def template_response(self, prompt: AdapterPrompt) -> str:  # noqa: D401
            body = "topsekret was accepted"
            return (
                "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n\r\n{body}"
            )

    e = _EchoAdapter(enabled=False)
    out = run(
        e.respond(
            "sess-leak",
            AdapterPrompt(inbound="POST /login", persona={}, extra=extra),
        )
    )
    assert "topsekret" not in out.content
    assert out.safety_trimmed is True


def test_safety_filter_strips_jwt_pattern() -> None:
    class _LeakAdapter(HttpAdapter):
        def template_response(self, prompt: AdapterPrompt) -> str:  # noqa: D401
            body = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
            return (
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n\r\n{body}"
            )

    a = _LeakAdapter(enabled=False)
    out = run(a.respond("s", AdapterPrompt(inbound="GET /", extra={"method": "GET", "path": "/"})))
    assert "[redacted]" in out.content
    assert any("secret_pattern" in r for r in out.safety_reasons)


def test_validate_shape_repairs_content_length() -> None:
    a = HttpAdapter(enabled=False)
    raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\nhello"
    fixed = a.validate_shape(raw)
    assert "Content-Length: 5" in fixed


def test_validate_shape_rejects_nonsense_status_line() -> None:
    a = HttpAdapter(enabled=False)
    assert a.validate_shape("not a response") == ""
    assert a.validate_shape("HTTP/1.1 NOPE OK\r\n\r\n") == ""


def test_cache_key_stable_per_method_path_profile() -> None:
    a = HttpAdapter(enabled=False)
    p1 = AdapterPrompt(
        inbound="GET /", persona={"profile": "web_server"}, extra={"method": "GET", "path": "/"}
    )
    p2 = AdapterPrompt(
        inbound="GET /", persona={"profile": "web_server"}, extra={"method": "GET", "path": "/"}
    )
    assert a.cache_key(p1) == a.cache_key(p2)


def test_cache_key_changes_with_path() -> None:
    a = HttpAdapter(enabled=False)
    p1 = AdapterPrompt(inbound="GET /", extra={"method": "GET", "path": "/"})
    p2 = AdapterPrompt(inbound="GET /a", extra={"method": "GET", "path": "/a"})
    assert a.cache_key(p1) != a.cache_key(p2)


def test_etag_appears_and_is_deterministic() -> None:
    a = HttpAdapter(enabled=False)
    raw1 = _do(a, path="/")
    raw2 = _do(a, path="/")
    etag_re = re.compile(r"ETag: \"([0-9a-f]+)\"")
    m1 = etag_re.search(raw1)
    m2 = etag_re.search(raw2)
    assert m1 and m2 and m1.group(1) == m2.group(1)


def test_status_line_always_first_and_well_formed() -> None:
    a = HttpAdapter(enabled=False)
    for path in ["/", "/admin", "/login", "/.git/config", "/__error"]:
        raw = _do(a, path=path)
        assert raw.startswith("HTTP/1.1 ")
        head, sep, _ = raw.partition("\r\n\r\n")
        assert sep == "\r\n\r\n"
        # Each header line must contain a colon.
        for line in head.split("\r\n")[1:]:
            assert ":" in line
