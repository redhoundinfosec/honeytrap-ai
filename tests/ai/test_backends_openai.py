"""Tests for the OpenAI-compatible backend.

All network IO is mocked; no real keys or endpoints are touched.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

from honeytrap.ai.backends._http import HTTPResponse
from honeytrap.ai.backends import ResponseRequest
from honeytrap.ai.backends import openai as openai_mod
from honeytrap.ai.backends.openai import OpenAIBackend

openai_mod._RETRY_BACKOFFS = (0.0, 0.0)


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _req() -> ResponseRequest:
    return ResponseRequest(protocol="ssh", inbound="whoami", session_id="x")


def test_success_parses_response() -> None:
    payload = HTTPResponse(
        status=200,
        body=b'{"choices":[{"message":{"content":"root\\n"}}],"usage":{"total_tokens":7}}',
    )
    os.environ["OPENAI_API_KEY"] = "test-key"
    backend = OpenAIBackend()

    async def fake(*_a, **_kw):  # type: ignore[no-untyped-def]
        return payload

    with patch("honeytrap.ai.backends.openai.post_json", side_effect=fake):
        result = _run(backend.generate(_req()))
    assert result.content == "root\n"
    assert result.tokens_used == 7
    assert result.shape_ok is True


def test_5xx_retried_then_fails_over() -> None:
    os.environ["OPENAI_API_KEY"] = "test-key"
    backend = OpenAIBackend()
    fail = HTTPResponse(status=503, body=b"boom", error="service unavailable")
    call_count = {"n": 0}

    async def fake_post_json(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["n"] += 1
        return fail

    with patch("honeytrap.ai.backends.openai.post_json", side_effect=fake_post_json):
        result = _run(backend.generate(_req()))
    # 1 initial + 2 retries => 3 attempts
    assert call_count["n"] == 3
    assert result.content == ""
    assert result.shape_ok is False


def test_401_fails_immediately() -> None:
    os.environ["OPENAI_API_KEY"] = "test-key"
    backend = OpenAIBackend()
    call_count = {"n": 0}

    async def fake_post_json(*args, **kwargs):  # type: ignore[no-untyped-def]
        call_count["n"] += 1
        return HTTPResponse(status=401, body=b"unauthorized", error="auth")

    with patch("honeytrap.ai.backends.openai.post_json", side_effect=fake_post_json):
        result = _run(backend.generate(_req()))
    assert call_count["n"] == 1
    assert result.shape_ok is False


def test_timeout_triggers_shape_fail() -> None:
    os.environ["OPENAI_API_KEY"] = "test-key"
    backend = OpenAIBackend()
    timeout = HTTPResponse(status=0, body=b"", error="timeout: timed out")

    async def fake(*_a, **_kw):  # type: ignore[no-untyped-def]
        return timeout

    with patch("honeytrap.ai.backends.openai.post_json", side_effect=fake):
        result = _run(backend.generate(_req()))
    assert result.content == ""
    assert result.shape_ok is False


def test_missing_api_key_fails_fast() -> None:
    os.environ.pop("OPENAI_API_KEY", None)
    backend = OpenAIBackend(api_key_env="UNSET_FOR_TEST")
    result = _run(backend.generate(_req()))
    assert result.content == ""
    assert result.shape_ok is False


def _async_return(value):  # type: ignore[no-untyped-def]
    async def _coro(*_a, **_kw):
        return value

    return _coro()
