"""Tests for the deterministic template backend."""

from __future__ import annotations

import asyncio

from honeytrap.ai.backends import ResponseRequest, TemplateBackend


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_template_output_is_deterministic_by_session_id() -> None:
    backend = TemplateBackend()
    req1 = ResponseRequest(
        protocol="ssh",
        inbound="whoami",
        memory_snapshot={},
        session_id="abc",
    )
    req2 = ResponseRequest(
        protocol="ssh",
        inbound="whoami",
        memory_snapshot={},
        session_id="abc",
    )
    a = _run(backend.generate(req1))
    b = _run(backend.generate(req2))
    assert a.content == b.content
    assert a.shape_ok is True


def test_template_output_differs_across_sessions() -> None:
    backend = TemplateBackend()
    a = _run(backend.generate(ResponseRequest(protocol="ssh", inbound="ls", session_id="AAA")))
    b = _run(backend.generate(ResponseRequest(protocol="ssh", inbound="ls", session_id="BBB")))
    assert a.content != b.content


def test_template_placeholder_substitution() -> None:
    backend = TemplateBackend()
    result = _run(
        backend.generate(
            ResponseRequest(
                protocol="http",
                inbound="GET /admin HTTP/1.1",
                session_id="fixed",
                persona={"server_header": "MyServer/9.9"},
            )
        )
    )
    assert "MyServer/9.9" in result.content
    assert result.content.startswith("HTTP/1.1 404")


def test_template_persona_consistency_across_turns() -> None:
    backend = TemplateBackend()
    req = ResponseRequest(protocol="ssh", inbound="uname", session_id="persona-test")
    one = _run(backend.generate(req))
    two = _run(backend.generate(req))
    # Hostname line is stable for the same session id.
    host_lines_one = [l for l in one.content.splitlines() if "srv-" in l or "logged" in l]
    host_lines_two = [l for l in two.content.splitlines() if "srv-" in l or "logged" in l]
    assert host_lines_one == host_lines_two
