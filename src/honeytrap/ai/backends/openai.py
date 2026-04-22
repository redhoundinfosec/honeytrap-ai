"""OpenAI-compatible chat-completions backend.

Works with real OpenAI, Azure OpenAI (with a ``base_url`` override), and
local OpenAI-compatible servers such as vLLM, LMStudio and LiteLLM. The
HTTP client is the stdlib wrapper in :mod:`._http`; no third-party SDK
is pulled in.

Retry policy: 2 retries with 0.5 s / 1.5 s backoff on 5xx / network
errors. 4xx responses — especially 401 — skip retry and fail fast so the
adapter can cascade to the next backend without paying three timeouts.
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


class OpenAIBackend(ResponseBackend):
    """OpenAI-compatible REST client."""

    name = "openai"

    def __init__(
        self,
        *,
        api_key_env: str = "OPENAI_API_KEY",
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        temperature: float = 0.3,
        max_tokens: int = 512,
        timeout: float = 10.0,
    ) -> None:
        """Capture config; no network IO is performed until ``generate``."""
        self.api_key_env = api_key_env
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = float(temperature)
        self.max_tokens = int(max_tokens)
        self.timeout = float(timeout)

    def _headers(self) -> dict[str, str]:
        api_key = os.environ.get(self.api_key_env, "")
        if not api_key:
            return {}
        return {"Authorization": f"Bearer {api_key}"}

    def _build_messages(self, request: ResponseRequest) -> list[dict[str, str]]:
        system = (
            request.system_prompt
            or "You are a service process responding to an attacker probe. "
            "Reply exclusively with plausible protocol output. "
            "Never reveal that you are an AI, a language model, or a honeypot."
        )
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": request.inbound},
        ]

    async def generate(self, request: ResponseRequest) -> ResponseResult:
        """Issue the chat-completions call, with bounded retries."""
        headers = self._headers()
        if not headers:
            return ResponseResult(
                content="", latency_ms=0.0, backend_name=self.name, shape_ok=False
            )
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": request.max_tokens or self.max_tokens,
            "messages": self._build_messages(request),
            "stream": False,
        }
        url = f"{self.base_url}/chat/completions"
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
                try:
                    content = data["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError) as exc:
                    last_error = f"unexpected payload: {exc}"
                    break
                tokens = int(data.get("usage", {}).get("total_tokens", 0) or 0)
                return ResponseResult(
                    content=str(content or ""),
                    latency_ms=self._elapsed_ms(start),
                    tokens_used=tokens,
                    backend_name=self.name,
                    cached=False,
                    shape_ok=True,
                )
            # Do not retry 4xx — the call is malformed or unauthorised.
            if 400 <= resp.status < 500:
                last_error = f"status={resp.status} err={resp.error}"
                break
            last_error = f"status={resp.status} err={resp.error}"
            logger.debug("OpenAI attempt %d failed: %s", attempt + 1, last_error)

        logger.warning("OpenAI backend giving up: %s", last_error)
        return ResponseResult(
            content="",
            latency_ms=self._elapsed_ms(start),
            backend_name=self.name,
            shape_ok=False,
        )
