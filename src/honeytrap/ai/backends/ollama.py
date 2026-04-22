"""Ollama backend using the native ``/api/chat`` endpoint.

Ollama's JSON envelope differs from OpenAI's even when ``stream=False``:
the completion lives under ``message.content``. We parse that shape and,
if the response body is empty, surface an empty ``ResponseResult`` so
the adapter cascades down the chain.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from honeytrap.ai.backends._http import post_json
from honeytrap.ai.backends.base import ResponseBackend, ResponseRequest, ResponseResult

logger = logging.getLogger(__name__)

_RETRY_BACKOFFS: tuple[float, ...] = (0.5, 1.5)


class OllamaBackend(ResponseBackend):
    """Ollama `/api/chat` REST client."""

    name = "ollama"

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1:8b",
        temperature: float = 0.3,
        max_tokens: int = 512,
        timeout: float = 10.0,
    ) -> None:
        """Capture config."""
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = float(temperature)
        self.max_tokens = int(max_tokens)
        self.timeout = float(timeout)

    async def generate(self, request: ResponseRequest) -> ResponseResult:
        """Issue the chat call; no auth by default."""
        payload: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": request.max_tokens or self.max_tokens,
            },
            "messages": [
                {
                    "role": "system",
                    "content": (
                        request.system_prompt
                        or "You are a service process responding to an attacker probe. "
                        "Reply exclusively with plausible protocol output."
                    ),
                },
                {"role": "user", "content": request.inbound},
            ],
        }
        url = f"{self.base_url}/api/chat"
        start = time.time()
        last_error: str | None = None

        for attempt, backoff in enumerate([0.0, *_RETRY_BACKOFFS]):
            if backoff:
                await asyncio.sleep(backoff)
            resp = await post_json(url, payload, read_timeout=self.timeout)
            if resp.status == 200:
                data = resp.json()
                content = ""
                if isinstance(data, dict):
                    message = data.get("message")
                    if isinstance(message, dict):
                        content = str(message.get("content") or "")
                if not content:
                    last_error = "empty ollama response"
                    break
                return ResponseResult(
                    content=content,
                    latency_ms=self._elapsed_ms(start),
                    tokens_used=0,
                    backend_name=self.name,
                    cached=False,
                    shape_ok=True,
                )
            if 400 <= resp.status < 500:
                last_error = f"status={resp.status} err={resp.error}"
                break
            last_error = f"status={resp.status} err={resp.error}"
            logger.debug("Ollama attempt %d failed: %s", attempt + 1, last_error)

        logger.warning("Ollama backend giving up: %s", last_error)
        return ResponseResult(
            content="",
            latency_ms=self._elapsed_ms(start),
            backend_name=self.name,
            shape_ok=False,
        )
