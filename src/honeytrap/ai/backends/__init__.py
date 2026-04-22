"""Backend package with a factory that builds the fallback chain.

``get_backend`` returns a single :class:`ResponseBackend` that silently
cascades through a primary -> secondary -> template chain. The template
backend is always appended last so callers are guaranteed a non-empty
response even when every configured remote backend fails.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from honeytrap.ai.backends.anthropic import AnthropicBackend
from honeytrap.ai.backends.base import ResponseBackend, ResponseRequest, ResponseResult
from honeytrap.ai.backends.ollama import OllamaBackend
from honeytrap.ai.backends.openai import OpenAIBackend
from honeytrap.ai.backends.template import TemplateBackend

logger = logging.getLogger(__name__)

__all__ = [
    "AnthropicBackend",
    "ChainBackend",
    "OllamaBackend",
    "OpenAIBackend",
    "ResponseBackend",
    "ResponseRequest",
    "ResponseResult",
    "TemplateBackend",
    "build_backend",
    "get_backend",
    "instantiate",
]


@dataclass
class BackendHealth:
    """Per-backend health used by the ``/api/v1/ai/backends`` endpoint."""

    name: str
    last_success_ts: float = 0.0
    last_error: str | None = None
    calls: int = 0
    failures: int = 0


_SAFETY_TRIPWIRES: tuple[str, ...] = (
    "as an ai",
    "as a language model",
    "i'm an ai",
    "i am an ai",
    "i cannot",
    "openai",
    "anthropic",
    "i do not have the ability",
    "i don't have the ability",
)


class ChainBackend(ResponseBackend):
    """Fallback chain with per-link health tracking.

    The chain walks ``backends`` in order and returns the first result
    with ``shape_ok=True`` and non-empty content. The last backend must
    be a :class:`TemplateBackend` so the chain can never return empty.
    """

    name = "chain"

    def __init__(self, backends: list[ResponseBackend]) -> None:
        """Wrap ``backends`` into a single failover chain."""
        if not backends:
            raise ValueError("chain requires at least one backend")
        if not isinstance(backends[-1], TemplateBackend):
            backends = [*backends, TemplateBackend()]
        self.backends = backends
        self.health: dict[str, BackendHealth] = {
            b.name: BackendHealth(name=b.name) for b in backends
        }

    def _safety_violation(self, text: str) -> bool:
        lowered = text.lower()
        return any(trip in lowered for trip in _SAFETY_TRIPWIRES)

    async def generate(self, request: ResponseRequest) -> ResponseResult:
        """Walk the chain; guarantee a non-empty response."""
        last_result: ResponseResult | None = None
        for backend in self.backends:
            health = self.health[backend.name]
            health.calls += 1
            try:
                result = await backend.generate(request)
            except Exception as exc:  # noqa: BLE001
                logger.warning("backend %s raised: %s", backend.name, exc)
                health.failures += 1
                health.last_error = str(exc)
                continue
            if not result.shape_ok or not result.content.strip():
                health.failures += 1
                health.last_error = "empty or shape-rejected response"
                last_result = result
                continue
            if backend.name != "template" and self._safety_violation(result.content):
                logger.info(
                    "backend %s output tripped safety filter; falling through",
                    backend.name,
                )
                health.failures += 1
                health.last_error = "safety tripwire"
                continue
            health.last_success_ts = time.time()
            health.last_error = None
            return result
        # Only reachable if *everything* above produced empty content,
        # including template. Return the last seen result as-is.
        return last_result or ResponseResult(
            content="",
            latency_ms=0.0,
            backend_name=self.name,
            shape_ok=False,
        )


def instantiate(spec: dict[str, Any] | None) -> ResponseBackend | None:
    """Build a single backend from a config dict.

    ``spec`` must carry at minimum a ``type`` key. Unknown / missing
    types return ``None`` so the caller can skip and continue.
    """
    if not spec:
        return None
    kind = str(spec.get("type", "")).lower()
    if kind in {"", "none", "disabled"}:
        return None
    if kind == "template":
        return TemplateBackend(prompts_dir=spec.get("prompts_dir"))
    if kind == "openai":
        return OpenAIBackend(
            api_key_env=str(spec.get("api_key_env", "OPENAI_API_KEY")),
            base_url=str(spec.get("base_url", "https://api.openai.com/v1")),
            model=str(spec.get("model", "gpt-4o-mini")),
            temperature=float(spec.get("temperature", 0.3)),
            max_tokens=int(spec.get("max_tokens", 512)),
            timeout=float(spec.get("timeout", 10.0)),
        )
    if kind == "anthropic":
        return AnthropicBackend(
            api_key_env=str(spec.get("api_key_env", "ANTHROPIC_API_KEY")),
            base_url=str(spec.get("base_url", "https://api.anthropic.com")),
            model=str(spec.get("model", "claude-sonnet-4-6")),
            temperature=float(spec.get("temperature", 0.3)),
            max_tokens=int(spec.get("max_tokens", 512)),
            timeout=float(spec.get("timeout", 10.0)),
        )
    if kind == "ollama":
        return OllamaBackend(
            base_url=str(spec.get("base_url", "http://localhost:11434")),
            model=str(spec.get("model", "llama3.1:8b")),
            temperature=float(spec.get("temperature", 0.3)),
            max_tokens=int(spec.get("max_tokens", 512)),
            timeout=float(spec.get("timeout", 10.0)),
        )
    logger.warning("unknown backend type %r — skipping", kind)
    return None


def build_backend(
    specs: list[dict[str, Any] | None],
    *,
    prompts_dir: str | None = None,
) -> ChainBackend:
    """Compose a :class:`ChainBackend` from config specs.

    Invalid specs are skipped. A template backend is always appended
    last, either from an explicit spec or a fresh default.
    """
    backends: list[ResponseBackend] = []
    seen_template = False
    for spec in specs:
        backend = instantiate(spec)
        if backend is None:
            continue
        if isinstance(backend, TemplateBackend):
            seen_template = True
        backends.append(backend)
    if not seen_template:
        backends.append(TemplateBackend(prompts_dir=prompts_dir))
    return ChainBackend(backends)


def get_backend(config: dict[str, Any] | None) -> ChainBackend:
    """Build a chain backend from an ``ai.backends`` config block.

    ``config`` is the ``backends`` sub-dict; keys ``primary``,
    ``secondary``, ``tertiary`` are used in order. Missing or disabled
    entries are dropped. The resulting chain is guaranteed to contain
    at least the template backend.
    """
    ordered: list[dict[str, Any] | None] = []
    if config:
        for slot in ("primary", "secondary", "tertiary"):
            ordered.append(config.get(slot))
    prompts_dir = config.get("prompts_dir") if config else None
    return build_backend(ordered, prompts_dir=prompts_dir)
