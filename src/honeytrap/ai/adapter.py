"""Adaptive response orchestrator used by every protocol handler.

Given inbound bytes plus a :class:`SessionMemory`, the adapter:

1. Consults the response cache.
2. Refreshes intent classification.
3. Asks the configured backend chain to generate a response.
4. Validates the response against the protocol's expected shape.
5. Records metrics (cache hit ratio, intent counts, backend usage).

The adapter is deliberately synchronous to construct so a protocol
handler can create one per service without a heavy DI graph; the
``get_response`` entry point is async so it can await backend calls.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from honeytrap.ai.backends import ChainBackend, ResponseRequest, TemplateBackend
from honeytrap.ai.cache import ResponseCache
from honeytrap.ai.intent import HIGH_SEVERITY_LABELS, IntentLabel, classify
from honeytrap.ai.memory import SessionMemory
from honeytrap.ai.redact import redact_prompt

if TYPE_CHECKING:  # pragma: no cover
    from honeytrap.ops.health import MetricsRegistry

logger = logging.getLogger(__name__)


_HTTP_STATUS_RE = re.compile(rb"^HTTP/\d\.\d \d{3}")
_SMTP_CODE_RE = re.compile(rb"^\d{3}[ -]")


@dataclass
class AdapterResult:
    """What the adapter hands back to a protocol handler."""

    response: bytes
    intent: IntentLabel
    confidence: float
    rationale: list[str]
    backend_used: str
    cached: bool
    shape_ok: bool


class ProtocolResponder:
    """Top-level adapter: cache -> classifier -> backend chain."""

    def __init__(
        self,
        *,
        chain: ChainBackend | None = None,
        cache: ResponseCache | None = None,
        metrics: MetricsRegistry | None = None,
        enabled: bool = False,
        redact_secrets: bool = True,
        alert_callback: Any | None = None,
    ) -> None:
        """Wire up the adapter components.

        Args:
            chain: The configured backend chain. Defaults to template-only.
            cache: The response cache. ``None`` disables caching.
            metrics: Optional metrics registry for counters.
            enabled: Master switch. When ``False``, ``get_response``
                returns an empty :class:`AdapterResult` so the handler
                falls back to its static path.
            redact_secrets: Scrub obvious tokens from prompts.
            alert_callback: Optional callable invoked on HIGH-severity
                intent transitions. Must accept ``(memory, intent,
                rationale)``.
        """
        self.chain = chain or ChainBackend([TemplateBackend()])
        self.cache = cache
        self.metrics = metrics
        self.enabled = enabled
        self.redact_secrets = redact_secrets
        self.alert_callback = alert_callback
        self._last_intent_per_session: dict[str, IntentLabel] = {}
        self._register_metrics()

    def _register_metrics(self) -> None:
        if self.metrics is None:
            return
        self.metrics.register(
            "honeytrap_ai_cache_hit_ratio",
            "AI response-cache hit ratio",
            "gauge",
        )
        self.metrics.register(
            "honeytrap_ai_intent_total",
            "Counts of intent-classification outputs",
            "counter",
        )
        self.metrics.register(
            "honeytrap_ai_backend_used_total",
            "Counts of which backend answered a request",
            "counter",
        )
        self.metrics.register(
            "honeytrap_ai_memory_sessions",
            "Current count of tracked AI sessions",
            "gauge",
        )
        self.metrics.register(
            "honeytrap_ai_memory_evictions_total",
            "Cumulative count of evicted AI memory entries",
            "counter",
        )

    # ------------------------------------------------------------------
    # Shape validation
    # ------------------------------------------------------------------
    def _validate_shape(self, protocol: str, content: str) -> bool:
        """Return True when ``content`` looks like a valid wire response."""
        proto = protocol.lower()
        if not content:
            return False
        data = content.encode("utf-8", errors="ignore")
        if proto in {"http", "https"}:
            return bool(_HTTP_STATUS_RE.match(data))
        if proto == "smtp":
            # Multi-line responses are allowed but each line must start
            # with a 3-digit code per RFC 5321.
            for raw in data.splitlines():
                if raw and not _SMTP_CODE_RE.match(raw):
                    return False
            return True
        if proto == "ssh":
            try:
                content.encode("utf-8")
            except UnicodeEncodeError:
                return False
            return True
        if proto == "telnet":
            return True
        return True

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    async def get_response(
        self,
        *,
        protocol: str,
        inbound: str | bytes,
        memory: SessionMemory,
        persona: dict[str, Any] | None = None,
        system_prompt: str | None = None,
    ) -> AdapterResult:
        """Return an adaptive response for ``inbound`` on ``protocol``."""
        if not self.enabled:
            return AdapterResult(
                response=b"",
                intent=memory.intent or IntentLabel.UNKNOWN,
                confidence=memory.confidence,
                rationale=list(memory.rationale),
                backend_used="disabled",
                cached=False,
                shape_ok=True,
            )
        inbound_str = (
            inbound.decode("utf-8", errors="replace") if isinstance(inbound, bytes) else inbound
        )
        truncated = inbound_str[:4096]
        memory.record_command(truncated, protocol=protocol)
        label, confidence, rationale = classify(memory)
        previous_label = self._last_intent_per_session.get(memory.session_id)
        memory.intent = label
        memory.confidence = confidence
        memory.rationale = rationale
        self._last_intent_per_session[memory.session_id] = label
        self._incr_intent(label)
        self._fire_alert_if_needed(memory, previous_label, label, rationale)

        snapshot = self._memory_snapshot(memory)
        snapshot_json = json.dumps(snapshot, sort_keys=True)
        cache_key: str | None = None
        if self.cache is not None:
            cache_key = self.cache.key(
                protocol=protocol, inbound=truncated, memory_snapshot=snapshot_json
            )
            cached = self.cache.get(cache_key)
            self._update_cache_metric()
            if cached is not None:
                memory.record_backend(cached.backend_name, cached.latency_ms)
                self._incr_backend(cached.backend_name)
                return AdapterResult(
                    response=cached.content.encode("utf-8", errors="ignore"),
                    intent=label,
                    confidence=confidence,
                    rationale=rationale,
                    backend_used=cached.backend_name,
                    cached=True,
                    shape_ok=cached.shape_ok,
                )

        safe_inbound = redact_prompt(truncated) if self.redact_secrets else truncated
        request = ResponseRequest(
            protocol=protocol,
            inbound=safe_inbound,
            memory_snapshot=snapshot,
            persona=persona or {},
            system_prompt=system_prompt,
            session_id=memory.session_id,
            intent=label.value,
        )
        result = await self.chain.generate(request)
        if not self._validate_shape(protocol, result.content):
            logger.info(
                "shape validation failed for %s backend=%s; falling back to template",
                protocol,
                result.backend_name,
            )
            fallback = await TemplateBackend().generate(request)
            fallback.shape_ok = self._validate_shape(protocol, fallback.content)
            result = fallback

        memory.record_backend(result.backend_name, result.latency_ms)
        self._incr_backend(result.backend_name)
        if self.cache is not None and cache_key is not None and result.shape_ok:
            self.cache.set(cache_key, result)
            self._update_cache_metric()
        return AdapterResult(
            response=result.content.encode("utf-8", errors="ignore"),
            intent=label,
            confidence=confidence,
            rationale=rationale,
            backend_used=result.backend_name,
            cached=result.cached,
            shape_ok=result.shape_ok,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _memory_snapshot(self, memory: SessionMemory) -> dict[str, Any]:
        full = memory.to_dict()
        return {
            "source_ip": full["source_ip"],
            "turn_count": full["turn_count"],
            "protocol_history": full["protocol_history"][-5:],
            "command_history": full["command_history"][-8:],
            "intent": full["intent"],
            "attck_techniques": full["attck_techniques"],
        }

    def _update_cache_metric(self) -> None:
        if self.metrics is None or self.cache is None:
            return
        self.metrics.set_gauge(
            "honeytrap_ai_cache_hit_ratio",
            float(self.cache.stats.ratio),
        )

    def _incr_intent(self, label: IntentLabel) -> None:
        if self.metrics is None:
            return
        self.metrics.inc_counter(
            "honeytrap_ai_intent_total",
            labels={"label": label.value},
        )

    def _incr_backend(self, backend_name: str) -> None:
        if self.metrics is None:
            return
        self.metrics.inc_counter(
            "honeytrap_ai_backend_used_total",
            labels={"backend": backend_name},
        )

    def _fire_alert_if_needed(
        self,
        memory: SessionMemory,
        previous: IntentLabel | None,
        current: IntentLabel,
        rationale: list[str],
    ) -> None:
        if self.alert_callback is None:
            return
        if current not in HIGH_SEVERITY_LABELS:
            return
        if previous == current:
            return
        try:
            self.alert_callback(memory, current, rationale)
        except Exception as exc:  # noqa: BLE001
            logger.warning("intent alert callback failed: %s", exc)
