"""LLM-backed response generator with automatic fallback to the rule engine.

The responder is protocol-agnostic; it accepts a free-form ``prompt`` string
describing the attacker's request and an optional ``personality`` blurb, and
returns the model's completion as a string. If the AI provider is disabled
or fails for any reason, it falls back to a short rule-based string.

Implementation notes
~~~~~~~~~~~~~~~~~~~~

* OpenAI is optional. We import it lazily and degrade gracefully.
* Ollama and "custom" providers use the OpenAI-compatible REST shape through
  the standard ``openai`` SDK with ``base_url`` overrides.
* Caching: identical prompts within a sliding window return the cached
  result to reduce latency and API cost.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from typing import Any

from honeytrap.ai.rule_engine import RuleEngine
from honeytrap.core.config import AIConfig
from honeytrap.exceptions import AIResponseError

logger = logging.getLogger(__name__)


class _LRUCache:
    """Tiny TTL+LRU cache for responder outputs."""

    def __init__(self, maxsize: int = 256, ttl_seconds: float = 600.0) -> None:
        """Initialize the LRU cache with a max size and TTL."""
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._store: dict[str, tuple[float, str]] = {}

    def get(self, key: str) -> str | None:
        """Return the cached value for key, or None if missing/expired."""
        entry = self._store.get(key)
        if not entry:
            return None
        ts, value = entry
        if time.time() - ts > self.ttl:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: str) -> None:
        """Store a value in the cache, evicting the oldest entry if full."""
        if len(self._store) >= self.maxsize:
            # evict oldest
            oldest = min(self._store.items(), key=lambda kv: kv[1][0])[0]
            self._store.pop(oldest, None)
        self._store[key] = (time.time(), value)


class AIResponder:
    """Async LLM responder with graceful fallback."""

    def __init__(self, config: AIConfig, rules: RuleEngine) -> None:
        """Initialize the AI responder with the rule engine and optional LLM client."""
        self.config = config
        self.rules = rules
        self._client: Any = None
        self._client_ready = False
        self._cache = _LRUCache()

    # ------------------------------------------------------------------
    # Client lifecycle
    # ------------------------------------------------------------------
    def _ensure_client(self) -> Any | None:
        if self._client_ready:
            return self._client
        self._client_ready = True
        if not self.config.enabled:
            return None
        try:  # openai is optional
            from openai import AsyncOpenAI  # type: ignore[import-not-found]
        except ImportError:
            logger.warning("openai package not installed — AI disabled")
            return None

        provider = (self.config.provider or "openai").lower()
        base_url = self.config.endpoint or None
        if provider == "ollama" and not base_url:
            base_url = "http://localhost:11434/v1"
        api_key = self.config.api_key or "EMPTY"
        try:
            self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not initialize AsyncOpenAI client: %s", exc)
            self._client = None
        return self._client

    # ------------------------------------------------------------------
    # Main entrypoint
    # ------------------------------------------------------------------
    async def generate(
        self,
        *,
        prompt: str,
        system: str = "",
        max_tokens: int | None = None,
        fallback: str = "",
    ) -> str:
        """Generate a response, falling back to ``fallback`` on any failure."""
        client = self._ensure_client()
        if client is None:
            return fallback or self._safe_default(prompt)

        cache_key = hashlib.sha256(f"{system}||{prompt}".encode()).hexdigest()
        if (cached := self._cache.get(cache_key)) is not None:
            return cached

        try:
            result = await asyncio.wait_for(
                self._call_model(client, prompt=prompt, system=system, max_tokens=max_tokens),
                timeout=self.config.timeout_seconds,
            )
            self._cache.set(cache_key, result)
            return result
        except asyncio.TimeoutError:
            logger.warning("AI responder timed out after %.1fs", self.config.timeout_seconds)
        except AIResponseError as exc:
            logger.warning("AI responder rejected: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AI responder failed: %s", exc)

        if self.config.fallback_to_rules:
            return fallback or self._safe_default(prompt)
        return ""

    async def _call_model(
        self, client: Any, *, prompt: str, system: str, max_tokens: int | None
    ) -> str:
        """Issue the chat completion call."""
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            resp = await client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                max_tokens=max_tokens or self.config.max_tokens,
                temperature=0.7,
            )
        except Exception as exc:  # noqa: BLE001
            raise AIResponseError(f"LLM call failed: {exc}") from exc

        try:
            content = resp.choices[0].message.content  # type: ignore[attr-defined]
        except (AttributeError, IndexError) as exc:
            raise AIResponseError(f"Unexpected LLM response shape: {exc}") from exc
        return (content or "").strip()

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_default(prompt: str) -> str:
        """Return a safe, short deflection when the AI layer is unavailable."""
        _ = prompt  # unused; kept for symmetry
        return ""

    @property
    def available(self) -> bool:
        """Return ``True`` if the client is configured and loaded."""
        return self._ensure_client() is not None
