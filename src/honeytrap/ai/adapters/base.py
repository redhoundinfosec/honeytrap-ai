"""Abstract base class for per-protocol adaptive-response adapters.

The Cycle-16 adapter pattern factors the cache -> classifier -> backend
chain that previously lived only on the SSH happy-path into a single
reusable ``BaseAdapter``. Every protocol that wants AI-augmented
responses (HTTP, SMTP, Telnet, FTP, SSH) subclasses
:class:`BaseAdapter` and implements:

* :meth:`template_response` — deterministic, zero-network fallback that
  must always succeed and must always produce a wire-correct response.
* :meth:`validate_shape` — protocol-shape validator that scrubs or
  truncates output that would otherwise corrupt the wire dialogue.
* :meth:`cache_key` — protocol-aware cache key so adapter outputs are
  shareable across like-prompts (same path, same EHLO target, etc.).
* :meth:`safety_filter` — opsec scrub that strips attacker-supplied
  secrets, internal hostnames, absolute filesystem paths and dashboard
  escape sequences from any response before it goes to the wire.

The shared collaborators (intent classifier, per-session memory,
response cache, backend chain, safety event hook) live on the base so
subclasses can stay small and protocol-focused.
"""

from __future__ import annotations

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from honeytrap.ai.backends import ChainBackend, ResponseRequest, TemplateBackend
from honeytrap.ai.cache import ResponseCache
from honeytrap.ai.intent import HIGH_SEVERITY_LABELS, IntentLabel, classify
from honeytrap.ai.memory import SessionMemory
from honeytrap.ai.redact import redact_prompt

logger = logging.getLogger(__name__)


_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWT
    re.compile(r"\b\d{13,19}\b"),  # CC-shaped digit runs (no separators)
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),  # Google API key
)
_INTERNAL_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/home/[A-Za-z0-9_\-]+/workspace"),
    re.compile(r"/Users/[A-Za-z0-9_\-]+/"),
    re.compile(r"C:\\\\Users\\\\[A-Za-z0-9_\-]+\\\\"),
)
_DASHBOARD_ESCAPE = re.compile(r"^\x1b\[.*?(?:m|H|J)")
_ATTACKER_SECRET_HINT = ("password=", "passwd=", "secret=", "token=", "api_key=")


@dataclass
class AdapterPrompt:
    """Inputs handed to an adapter for a single response generation.

    Attributes:
        inbound: Raw attacker payload (one command line, one HTTP request,
            one SMTP verb, ...). Truncation for very large payloads is
            done by individual adapters.
        persona: Profile-derived persona facts (server header, hostname,
            os_persona, etc.). Adapters MAY add further keys before
            forwarding to the backend chain.
        system_prompt: Optional system prompt passed verbatim to the
            backend chain. ``None`` lets each backend pick its default.
        extra: Open-ended dict for protocol-specific context (HTTP method,
            cwd, mail_from, etc.). Adapters interpret keys per-protocol.
    """

    inbound: str
    persona: dict[str, Any] = field(default_factory=dict)
    system_prompt: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdapterResponse:
    """What an adapter returns to a protocol handler.

    Attributes:
        content: The response in protocol-correct form, ready for the
            wire. The exact type is left to the adapter (str for SSH /
            Telnet shell text; bytes for HTTP raw response; multi-line
            CR/LF string for SMTP / FTP).
        intent: Latest intent label after this turn.
        confidence: Classifier confidence in ``intent``.
        rationale: Short list of human-readable signals that drove the
            classifier.
        backend_used: Name of the backend that produced ``content``.
        cached: ``True`` if served from the response cache.
        shape_ok: ``True`` if the content passed shape validation.
        safety_trimmed: ``True`` if the safety filter modified content.
        safety_reasons: List of reasons (one per filter that fired) the
            safety filter cited for trimming.
    """

    content: str
    intent: IntentLabel
    confidence: float
    rationale: list[str]
    backend_used: str
    cached: bool
    shape_ok: bool
    safety_trimmed: bool = False
    safety_reasons: list[str] = field(default_factory=list)


class BaseAdapter(ABC):
    """Shared per-protocol adapter scaffolding.

    Subclasses customise five hook points: ``protocol`` (class attr),
    ``template_response``, ``validate_shape``, ``cache_key``, and
    ``safety_filter``. The canonical orchestration lives in
    :meth:`respond`.
    """

    protocol: str = "base"

    def __init__(
        self,
        *,
        chain: ChainBackend | None = None,
        cache: ResponseCache | None = None,
        enabled: bool = True,
        redact_secrets: bool = True,
        safety_event_callback: Any | None = None,
        max_inbound_bytes: int = 8192,
    ) -> None:
        """Wire the adapter's collaborators.

        Args:
            chain: Configured backend chain. ``None`` means template-only
                operation, which is also the safe default for production
                deployments without an LLM credential.
            cache: Response cache. ``None`` disables caching for this
                adapter (useful in tests).
            enabled: Master switch. When ``False`` the adapter still
                produces a deterministic template response so the
                handler never sees an empty payload.
            redact_secrets: Run :func:`redact_prompt` over prompts before
                forwarding them to the backend chain.
            safety_event_callback: Optional callable
                ``(protocol, reasons, sample) -> None`` invoked when the
                safety filter trims output. Used by the dashboard to
                surface ``ai_safety`` events.
            max_inbound_bytes: Hard cap on the inbound prompt size — any
                excess is dropped with a debug log. Applied per-call so
                long-running sessions can stream commands cheaply.
        """
        self.chain = chain or ChainBackend([TemplateBackend()])
        self.cache = cache
        self.enabled = enabled
        self.redact_secrets = redact_secrets
        self.safety_event_callback = safety_event_callback
        self.max_inbound_bytes = max_inbound_bytes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def respond(self, session_id: str, prompt: AdapterPrompt) -> AdapterResponse:
        """Run the cache -> classifier -> backend chain pipeline.

        ``session_id`` is used to seed the deterministic templates and
        to derive a stable cache key when no in-memory ``SessionMemory``
        is available; callers that already have a memory should pass it
        in via :attr:`AdapterPrompt.extra` under key ``"memory"``.
        """
        memory: SessionMemory = prompt.extra.get("memory") or SessionMemory(
            session_id=session_id, source_ip=str(prompt.persona.get("source_ip", ""))
        )
        truncated = prompt.inbound[: self.max_inbound_bytes]
        memory.record_command(truncated, protocol=self.protocol)
        label, confidence, rationale = classify(memory)
        memory.intent = label
        memory.confidence = confidence
        memory.rationale = rationale

        # Cache lookup — keyed by the protocol-specific cache_key plus
        # the session-memory snapshot so two distinct sessions in the
        # same posture share answers.
        ck: str | None = None
        if self.cache is not None:
            ck = self._build_cache_key(prompt, memory)
            cached = self.cache.get(ck)
            if cached is not None:
                content = self._post_safety(cached.content, prompt)
                return AdapterResponse(
                    content=content.value,
                    intent=label,
                    confidence=confidence,
                    rationale=rationale,
                    backend_used=cached.backend_name,
                    cached=True,
                    shape_ok=cached.shape_ok,
                    safety_trimmed=content.trimmed,
                    safety_reasons=content.reasons,
                )

        # If the master switch is off, hand back the deterministic
        # template directly. This is also the production-safe default.
        if not self.enabled:
            template = self.template_response(prompt)
            shaped = self.validate_shape(template)
            scrubbed = self._post_safety(shaped, prompt)
            return AdapterResponse(
                content=scrubbed.value,
                intent=label,
                confidence=confidence,
                rationale=rationale,
                backend_used="template",
                cached=False,
                shape_ok=True,
                safety_trimmed=scrubbed.trimmed,
                safety_reasons=scrubbed.reasons,
            )

        # Generate via the backend chain.
        safe_inbound = redact_prompt(truncated) if self.redact_secrets else truncated
        request = ResponseRequest(
            protocol=self.protocol,
            inbound=safe_inbound,
            memory_snapshot=self._memory_snapshot(memory),
            persona=prompt.persona,
            system_prompt=prompt.system_prompt,
            session_id=memory.session_id,
            intent=label.value,
        )
        result = await self.chain.generate(request)
        content_str = result.content
        shaped_str = self.validate_shape(content_str)
        if shaped_str != content_str and not shaped_str:
            # Output was wholly invalid -> fall back to the template.
            template = self.template_response(prompt)
            shaped_str = self.validate_shape(template)
            backend_name = "template"
        else:
            backend_name = result.backend_name
        scrubbed = self._post_safety(shaped_str, prompt)
        if self.cache is not None and ck is not None and scrubbed.value:
            from honeytrap.ai.backends.base import ResponseResult

            self.cache.set(
                ck,
                ResponseResult(
                    content=scrubbed.value,
                    latency_ms=result.latency_ms,
                    tokens_used=result.tokens_used,
                    backend_name=backend_name,
                    cached=False,
                    shape_ok=True,
                ),
            )
        # High-severity intent transitions are logged at INFO so an
        # operator gets a breadcrumb without needing to enable DEBUG.
        if label in HIGH_SEVERITY_LABELS:
            logger.info(
                "adapter %s flagged HIGH-severity intent %s for session %s",
                self.protocol,
                label.value,
                memory.session_id,
            )
        return AdapterResponse(
            content=scrubbed.value,
            intent=label,
            confidence=confidence,
            rationale=rationale,
            backend_used=backend_name,
            cached=False,
            shape_ok=True,
            safety_trimmed=scrubbed.trimmed,
            safety_reasons=scrubbed.reasons,
        )

    # ------------------------------------------------------------------
    # Hooks subclasses must implement
    # ------------------------------------------------------------------
    @abstractmethod
    def template_response(self, prompt: AdapterPrompt) -> str:
        """Deterministic, zero-network fallback for ``prompt``."""

    @abstractmethod
    def validate_shape(self, response: str) -> str:
        """Return ``response`` unchanged if wire-valid, else trim/empty."""

    @abstractmethod
    def cache_key(self, prompt: AdapterPrompt) -> str:
        """Return a stable cache key (excluding memory snapshot)."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def safety_filter(self, response: str, prompt: AdapterPrompt) -> tuple[str, list[str]]:
        """Strip attacker-supplied secrets and host fingerprints.

        Returns the possibly-redacted response plus a list of reasons.
        Subclasses can override to add protocol-specific scrubs but the
        default covers the must-not-leak categories required by the
        Cycle-16 charter.
        """
        reasons: list[str] = []
        result = response
        # 1. Block attacker-supplied secrets being echoed back. Inspect
        # both the inbound line and any structured body the adapter
        # forwarded under ``extra["body"]`` (HTTP forms, etc.).
        haystacks: list[str] = [prompt.inbound]
        body = prompt.extra.get("body")
        if isinstance(body, str) and body:
            haystacks.append(body)
        elif isinstance(body, bytes):
            try:
                haystacks.append(body.decode("utf-8", errors="ignore"))
            except Exception:  # noqa: BLE001
                pass
        for hay in haystacks:
            for hint in _ATTACKER_SECRET_HINT:
                idx = hay.lower().find(hint)
                if idx == -1:
                    continue
                after = hay[idx + len(hint) :]
                secret = after.split("&", 1)[0].split(" ", 1)[0].strip()
                if secret and len(secret) >= 4 and secret in result:
                    result = result.replace(secret, "[redacted]")
                    reasons.append("attacker_secret_echo")
        # 2. Strip generic secret-shaped tokens.
        for pattern in _SECRET_PATTERNS:
            new = pattern.sub("[redacted]", result)
            if new != result:
                reasons.append(f"secret_pattern:{pattern.pattern[:24]}")
                result = new
        # 3. Strip absolute paths from the host filesystem.
        for pattern in _INTERNAL_PATH_PATTERNS:
            new = pattern.sub("/var/lib/app", result)
            if new != result:
                reasons.append("internal_path")
                result = new
        # 4. Remove dashboard-targeting escape sequences at the start.
        if _DASHBOARD_ESCAPE.match(result):
            result = _DASHBOARD_ESCAPE.sub("", result, count=1)
            reasons.append("dashboard_escape")
        return result, reasons

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _build_cache_key(self, prompt: AdapterPrompt, memory: SessionMemory) -> str:
        base = self.cache_key(prompt)
        snap = ":".join(memory.command_history[-3:])
        digest = hashlib.sha1(f"{base}|{snap}".encode()).hexdigest()
        return f"{self.protocol}:{digest}"

    @staticmethod
    def _memory_snapshot(memory: SessionMemory) -> dict[str, Any]:
        return {
            "source_ip": memory.source_ip,
            "turn_count": memory.turn_count,
            "command_history": list(memory.command_history[-8:]),
            "intent": memory.intent.value if memory.intent else None,
        }

    def _post_safety(self, content: str, prompt: AdapterPrompt) -> _SafetyApplied:
        """Apply :meth:`safety_filter` and notify hook on changes."""
        new_content, reasons = self.safety_filter(content, prompt)
        trimmed = bool(reasons)
        if trimmed and self.safety_event_callback is not None:
            try:
                self.safety_event_callback(self.protocol, reasons, content[:128])
            except Exception as exc:  # noqa: BLE001
                logger.warning("safety_event_callback failed: %s", exc)
        return _SafetyApplied(value=new_content, trimmed=trimmed, reasons=reasons)


@dataclass
class _SafetyApplied:
    """Outcome of running :meth:`BaseAdapter.safety_filter`."""

    value: str
    trimmed: bool
    reasons: list[str]
