"""AI layer: rule engine, LLM responder, memory, intent, adaptive backends.

Submodules are imported lazily to avoid a circular import with
``honeytrap.core.engine`` (which itself imports ``AIResponder``).
"""

from honeytrap.ai.adapter import AdapterResult, ProtocolResponder
from honeytrap.ai.backends import (
    AnthropicBackend,
    ChainBackend,
    OllamaBackend,
    OpenAIBackend,
    ResponseBackend,
    ResponseRequest,
    ResponseResult,
    TemplateBackend,
    build_backend,
    get_backend,
)
from honeytrap.ai.cache import CacheStats, ResponseCache
from honeytrap.ai.intent import HIGH_SEVERITY_LABELS, IntentLabel, classify
from honeytrap.ai.memory import (
    AuthAttempt,
    InMemoryStore,
    MemoryStore,
    SessionMemory,
    SqliteMemoryStore,
    build_store,
)
from honeytrap.ai.redact import redact_prompt

__all__ = [
    "AdapterResult",
    "AnthropicBackend",
    "AuthAttempt",
    "CacheStats",
    "ChainBackend",
    "HIGH_SEVERITY_LABELS",
    "InMemoryStore",
    "IntentLabel",
    "MemoryStore",
    "OllamaBackend",
    "OpenAIBackend",
    "ProtocolResponder",
    "ResponseBackend",
    "ResponseCache",
    "ResponseRequest",
    "ResponseResult",
    "SessionMemory",
    "SqliteMemoryStore",
    "TemplateBackend",
    "build_backend",
    "build_store",
    "classify",
    "get_backend",
    "redact_prompt",
]
