"""Anthropic Messages API backend.

Speaks the ``/v1/messages`` JSON envelope over stdlib HTTP; no SDK is
required. Extracts the first ``text`` block from the response content
list. Like the other remote backends, it never raises — on failure the
adapter's fallback chain takes over.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from honeytrap.ai.backends._http import post_json
from honeytrap.ai.backends.base import ResponseBackend, ResponseRequest, ResponseResult

logger = logging.getLogger(__name__)

_RETRY_BACKOFFS: tuple[float, ...] = (0.5, 1.5)


class AnthropicBackend(ResponseBackend):
    """Anthropic Messages API client."""

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key_env: str = "ANTHROPIC_API_KEY",
        base_url: str = "https://api.anthropic.com",
        model: str = "claude-sonnet-4-6",
        temperature: float = 0.3,
        max_tokens: int = 512,
        timeout: float = 10.0,
        api_version: str = "2023-06-01",
    ) -> None:
        """Capture config; nothing is eagerly connected."""
        self.api_key_env = api_key_env
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = float(temperature)
        self.max_tokens = int(max_tokens)
        self.timeout = float(timeout)
        self.api_version = api_version

    def _headers(self) -> dict[str, str]:
        api_key = os.environ.get(self.api_key_env, "")
        if not api_key:
            return {}
        return {
            "x-api-key": api_key,
            "anthropic-version": self.api_version,
        }

    async def generate(self, request: ResponseRequest) -> ResponseResult:
        """POST to ``/v1/messages`` and extract the first text block."""
        headers = self._headers()
        if not headers:
            return ResponseResult(
                content="", latency_ms=0.0, backend_name=self.name, shape_ok=False
            )
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": request.max_tokens or self.max_tokens,
            "temperature": self.temperature,
            "system": request.system_prompt
            or (
                "You are a service process responding to an attacker probe. "
                "Reply exclusively with plausible protocol output."
            ),
            "messages": [
                {"role": "user", "content": request.inbound},
            ],
        }
        url = f"{self.base_url}/v1/messages"
        start = time.time()
        last_error: str | None = None

        for attempt, backoff in enumerate([0.0, *_RETRY_BACKOFFS]):
            if backoff:
                await asyncio.sleep(backoff)
            resp = await post_json(
                url,
                payload,
                headers=headers,
                read_timeout=self.timeout,
            )
            if resp.status == 200:
                data = resp.json()
                content_blocks = data.get("content", [])
                text_chunks = [
                    blk.get("text", "")
                    for blk in content_blocks
                    if isinstance(blk, dict) and blk.get("type") == "text"
                ]
                content = "".join(text_chunks)
                tokens = int(
                    data.get("usage", {}).get("output_tokens", 0)
                    + data.get("usage", {}).get("input_tokens", 0)
                )
                return ResponseResult(
                    content=content,
                    latency_ms=self._elapsed_ms(start),
                    tokens_used=tokens,
                    backend_name=self.name,
                    cached=False,
                    shape_ok=bool(content),
                )
            if 400 <= resp.status < 500:
                last_error = f"status={resp.status} err={resp.error}"
                break
            last_error = f"status={resp.status} err={resp.error}"
            logger.debug("Anthropic attempt %d failed: %s", attempt + 1, last_error)

        logger.warning("Anthropic backend giving up: %s", last_error)
        return ResponseResult(
            content="",
            latency_ms=self._elapsed_ms(start),
            backend_name=self.name,
            shape_ok=False,
        )
