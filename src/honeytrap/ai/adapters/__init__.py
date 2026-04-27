"""Per-protocol adaptive-response adapters.

Cycle 16 introduces a single :class:`BaseAdapter` contract and four new
concrete adapters (HTTP, SMTP, Telnet, FTP) on top of the existing
backend chain (template / openai / anthropic / ollama), intent
classifier, per-session memory, and response cache. The SSH path keeps
its existing :class:`~honeytrap.ai.adapter.ProtocolResponder` orchestrator
but is also exposed as :class:`SshAdapter` so dashboards and metrics can
treat all five protocols uniformly.

The factory :func:`get_adapter` looks up an adapter by canonical
protocol name. ``protocol`` strings are case-insensitive.
"""

from __future__ import annotations

from typing import Any

from honeytrap.ai.adapters.base import AdapterPrompt, AdapterResponse, BaseAdapter
from honeytrap.ai.adapters.ftp import FtpAdapter
from honeytrap.ai.adapters.http import HttpAdapter, build_http_extra
from honeytrap.ai.adapters.smtp import SmtpAdapter
from honeytrap.ai.adapters.ssh import SshAdapter
from honeytrap.ai.adapters.telnet import TelnetAdapter, latency_cap_ms

__all__ = [
    "AdapterPrompt",
    "AdapterResponse",
    "BaseAdapter",
    "FtpAdapter",
    "HttpAdapter",
    "SmtpAdapter",
    "SshAdapter",
    "TelnetAdapter",
    "build_http_extra",
    "get_adapter",
    "latency_cap_ms",
    "register_adapter",
    "supported_protocols",
]


_REGISTRY: dict[str, type[BaseAdapter]] = {
    "http": HttpAdapter,
    "https": HttpAdapter,
    "smtp": SmtpAdapter,
    "telnet": TelnetAdapter,
    "ftp": FtpAdapter,
    "ssh": SshAdapter,
}


def register_adapter(protocol: str, adapter_cls: type[BaseAdapter]) -> None:
    """Register a custom adapter for ``protocol``.

    Useful for downstream plugins that want to extend the AI layer to
    additional protocols (POP3, IMAP, ...) without touching this
    package. Existing entries are overwritten silently.
    """
    _REGISTRY[protocol.lower()] = adapter_cls


def get_adapter(protocol: str, **kwargs: Any) -> BaseAdapter:
    """Build an adapter for ``protocol`` with ``kwargs`` forwarded.

    Args:
        protocol: Canonical protocol name (``ssh``, ``http``, ``smtp``,
            ``telnet``, ``ftp``). Case-insensitive.
        **kwargs: Forwarded to the adapter's constructor (``chain``,
            ``cache``, ``enabled``, ``redact_secrets``,
            ``safety_event_callback``, ``max_inbound_bytes``).

    Raises:
        KeyError: When ``protocol`` is not registered.
    """
    cls = _REGISTRY[protocol.lower()]
    return cls(**kwargs)


def supported_protocols() -> tuple[str, ...]:
    """Return the registered protocol names (sorted)."""
    return tuple(sorted(_REGISTRY.keys()))
