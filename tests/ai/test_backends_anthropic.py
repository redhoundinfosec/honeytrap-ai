"""Tests for the Anthropic Messages backend."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

from honeytrap.ai.backends import ResponseRequest
from honeytrap.ai.backends import anthropic as anthropic_mod
from honeytrap.ai.backends._http import HTTPResponse
from honeytrap.ai.backends.anthropic import AnthropicBackend

anthropic_mod._RETRY_BACKOFFS = (0.0, 0.0)


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def test_messages_envelope_is_parsed() -> None:
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    backend = AnthropicBackend()
    payload = HTTPResponse(
        status=200,
        body=(
            b'{"content":[{"type":"text","text":"root\\n"}],'
            b'"usage":{"input_tokens":4,"output_tokens":2}}'
        ),
    )

    async def fake(url, body, **_kw):  # type: ignore[no-untyped-def]
        assert url.endswith("/v1/messages")
        assert body["model"]
        assert body["messages"][0]["role"] == "user"
        return payload

    with patch("honeytrap.ai.backends.anthropic.post_json", side_effect=fake):
        result = _run(
            backend.generate(ResponseRequest(protocol="ssh", inbound="whoami", session_id="x"))
        )
    assert result.content == "root\n"
    assert result.tokens_used == 6
    assert result.shape_ok is True
