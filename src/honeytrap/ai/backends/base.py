"""Backend contract shared by every adaptive-response provider.

A backend turns a :class:`ResponseRequest` into a :class:`ResponseResult`.
Every backend must tolerate partial context, must time out cleanly, and
must never raise to the caller — the adapter layer expects
:meth:`ResponseBackend.generate` to always return something. The template
backend, always-on and zero-dep, is the safety net when remote calls
fail.

All backends live in their own module (:mod:`.template`, :mod:`.openai`,
:mod:`.anthropic`, :mod:`.ollama`) and are wired together by the factory
in :mod:`honeytrap.ai.backends` (the package ``__init__``).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResponseRequest:
    """Inputs passed to every backend.

    Attributes:
        protocol: Canonical protocol name (``ssh``, ``http``, ``smtp``, ...).
        inbound: Attacker payload truncated to ``max_inbound_bytes`` bytes.
        memory_snapshot: Small JSON-ready dict summarising the session.
        persona: Profile-derived persona facts (company, locale, hostname,
            etc.) used by template and prompt builders.
        system_prompt: Optional system prompt override.
        max_tokens: Upper bound on generated tokens (LLM backends only).
        temperature: Sampling temperature (LLM backends only).
        session_id: Stable identifier used as a deterministic seed for the
            template backend.
        intent: Current classifier label, may be ``None``.
    """

    protocol: str
    inbound: str
    memory_snapshot: dict[str, Any] = field(default_factory=dict)
    persona: dict[str, Any] = field(default_factory=dict)
    system_prompt: str | None = None
    max_tokens: int = 512
    temperature: float = 0.3
    session_id: str = ""
    intent: str | None = None


@dataclass
class ResponseResult:
    """Output every backend returns.

    Attributes:
        content: The generated response. Always ``str``; the adapter
            converts to bytes when writing to the wire.
        latency_ms: Wall-clock latency of the backend call.
        tokens_used: Best-effort token count; 0 when unknown.
        backend_name: Name of the backend that produced the content.
        cached: ``True`` if the response came from the cache rather than
            a fresh backend call.
        shape_ok: ``True`` if the content respected the protocol-shape
            validator. The adapter checks this before sending to the wire.
    """

    content: str
    latency_ms: float
    tokens_used: int = 0
    backend_name: str = ""
    cached: bool = False
    shape_ok: bool = True


class ResponseBackend(ABC):
    """Abstract async backend."""

    name: str = "base"

    @abstractmethod
    async def generate(self, request: ResponseRequest) -> ResponseResult:
        """Produce a response for ``request``.

        Implementations must never raise — any upstream failure must be
        translated into an empty-content :class:`ResponseResult` so the
        adapter can cascade to the next backend.
        """

    @staticmethod
    def _elapsed_ms(start: float) -> float:
        """Return milliseconds elapsed since ``start``."""
        return round((time.time() - start) * 1000.0, 2)
