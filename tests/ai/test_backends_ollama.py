"""Tests for the Ollama ``/api/chat`` backend."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from honeytrap.ai.backends import ResponseRequest
from honeytrap.ai.backends import ollama as ollama_mod
from honeytrap.ai.backends._http import HTTPResponse
from honeytrap.ai.backends.ollama import OllamaBackend

ollama_mod._RETRY_BACKOFFS = (0.0, 0.0)


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def test_api_chat_body_shape() -> None:
    backend = OllamaBackend(model="llama3.1:8b")
    seen = {}

    async def fake(url, body, **_kw):  # type: ignore[no-untyped-def]
        seen["url"] = url
        seen["body"] = body
        return HTTPResponse(
            status=200,
            body=b'{"message":{"role":"assistant","content":"ok"}}',
        )

    with patch("honeytrap.ai.backends.ollama.post_json", side_effect=fake):
        result = _run(
            backend.generate(
                ResponseRequest(protocol="ssh", inbound="whoami", session_id="s")
            )
        )
    assert seen["url"].endswith("/api/chat")
    assert seen["body"]["model"] == "llama3.1:8b"
    assert seen["body"]["stream"] is False
    assert result.content == "ok"


def test_empty_response_fails_over() -> None:
    backend = OllamaBackend()

    async def fake(url, body, **_kw):  # type: ignore[no-untyped-def]
        return HTTPResponse(status=200, body=b'{"message":{"content":""}}')

    with patch("honeytrap.ai.backends.ollama.post_json", side_effect=fake):
        result = _run(
            backend.generate(
                ResponseRequest(protocol="ssh", inbound="whoami", session_id="s")
            )
        )
    assert result.content == ""
    assert result.shape_ok is False
