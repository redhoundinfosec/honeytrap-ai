"""Service facade that isolates route handlers from the live engine.

The API server needs to answer questions like "list sessions" and "get
JA3 top-N" without binding directly to :class:`honeytrap.core.engine.Engine`;
that would make tests heavy and couple the API to the engine's private
state. Instead, route handlers depend on :class:`HoneytrapService`,
which has narrow methods that the engine-backed production impl and
the in-memory test impl both satisfy.

The engine-backed implementation is intentionally forgiving: any
subsystem that isn't present (e.g. forensics disabled) simply returns
empty data rather than raising.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from honeytrap.api.models import (
    AlertRecord,
    APIKeyPublic,
    EventRecord,
    MetricsSnapshot,
    ProfileInfo,
    SessionSummary,
)

logger = logging.getLogger(__name__)


@dataclass
class PaginatedResult:
    """List + optional cursor envelope returned by paging endpoints."""

    items: list[Any]
    next_cursor: str | None = None


@dataclass
class ControlState:
    """Mutable run-state exposed through the ``/control`` endpoints."""

    paused: bool = False
    shutdown_requested: bool = False


class HoneytrapService(Protocol):
    """Minimal surface the API needs from the running honeypot."""

    control: ControlState

    def version(self) -> str: ...

    def uptime_seconds(self) -> float: ...

    def list_sessions(
        self,
        *,
        ip: str | None,
        protocol: str | None,
        since: str | None,
        until: str | None,
        limit: int,
        cursor: str | None,
    ) -> PaginatedResult: ...

    def get_session(self, session_id: str) -> dict[str, Any] | None: ...

    def list_session_events(
        self, session_id: str, *, limit: int, cursor: str | None
    ) -> PaginatedResult: ...

    def session_timeline(self, session_id: str, *, as_text: bool) -> str | list[dict[str, Any]]: ...

    def session_pcap(self, session_id: str) -> bytes: ...

    def session_jsonl(self, session_id: str) -> bytes: ...

    def list_alerts(
        self,
        *,
        severity: str | None,
        since: str | None,
        acknowledged: bool | None,
        limit: int,
        cursor: str | None,
    ) -> PaginatedResult: ...

    def ack_alert(self, alert_id: str, *, actor: str, note: str | None) -> AlertRecord | None: ...

    def attck_counts(self) -> dict[str, int]: ...

    def iocs(self, *, ioc_type: str | None) -> list[dict[str, Any]]: ...

    def tls_top(self, *, top: int) -> list[dict[str, Any]]: ...

    def ai_session_memory(self, session_id: str) -> dict[str, Any] | None: ...

    def ai_intent_counts(self) -> dict[str, int]: ...

    def ai_backend_health(self) -> list[dict[str, Any]]: ...

    def prometheus_text(self) -> str: ...

    def metrics_summary(self) -> MetricsSnapshot: ...

    def list_profiles(self) -> list[ProfileInfo]: ...

    def get_profile(self, name: str) -> ProfileInfo | None: ...

    def reload_profile(self) -> dict[str, Any]: ...

    def redacted_config(self) -> dict[str, Any]: ...

    def pause(self) -> None: ...

    def resume(self) -> None: ...

    def shutdown(self) -> None: ...


# ---------------------------------------------------------------------------
# In-memory implementation used by tests and CLI dry runs.
# ---------------------------------------------------------------------------


@dataclass
class _StoredSession:
    """Internal session model for :class:`InMemoryService`."""

    session_id: str
    protocol: str
    remote_ip: str
    remote_port: int
    local_port: int
    started_at: str
    ended_at: str | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    events: list[EventRecord] = field(default_factory=list)
    pcap: bytes = b""
    jsonl: bytes = b""
    timeline: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> SessionSummary:
        """Return a :class:`SessionSummary` view of this session."""
        return SessionSummary(
            session_id=self.session_id,
            protocol=self.protocol,
            remote_ip=self.remote_ip,
            remote_port=self.remote_port,
            local_port=self.local_port,
            started_at=self.started_at,
            ended_at=self.ended_at,
            frame_count=len(self.events),
            bytes_in=self.bytes_in,
            bytes_out=self.bytes_out,
        )


class InMemoryService:
    """Test-oriented service that keeps everything in RAM.

    Fixtures assemble a service, populate it with deterministic data,
    hand it to :class:`~honeytrap.api.server.APIServer`, and assert on
    responses. Production code uses :class:`EngineService` instead.
    """

    def __init__(self, *, version: str = "0.1.0-test") -> None:
        """Create an empty service with a fixed clock-independent state."""
        self._version = version
        self._started_at = _monotime()
        self._sessions: dict[str, _StoredSession] = {}
        self._alerts: dict[str, AlertRecord] = {}
        self._attck: dict[str, int] = {}
        self._iocs: list[dict[str, Any]] = []
        self._tls: list[dict[str, Any]] = []
        self._profiles: list[ProfileInfo] = []
        self._config: dict[str, Any] = {}
        self._prom_text: str = "# HELP noop noop\n# TYPE noop counter\nnoop 0\n"
        self._reload_counter = 0
        self.control = ControlState()
        self._ai_memories: dict[str, dict[str, Any]] = {}
        self._ai_intents: dict[str, int] = {}
        self._ai_backend_health: list[dict[str, Any]] = []

    # -- AI-related mutators used by tests ------------------------------
    def set_ai_memory(self, session_id: str, snapshot: dict[str, Any]) -> None:
        """Register a fake session memory snapshot for API tests."""
        self._ai_memories[session_id] = dict(snapshot)

    def set_ai_intents(self, counts: dict[str, int]) -> None:
        """Replace the intent-counts series returned by the API."""
        self._ai_intents = dict(counts)

    def set_ai_backend_health(self, rows: list[dict[str, Any]]) -> None:
        """Replace the backend health snapshot for the ``/ai/backends`` route."""
        self._ai_backend_health = list(rows)

    # -- mutators used by tests ----------------------------------------
    def add_session(self, session: _StoredSession) -> None:
        """Store a pre-built session for listing and retrieval."""
        self._sessions[session.session_id] = session

    def add_alert(self, alert: AlertRecord) -> None:
        """Register an alert available through :meth:`list_alerts`."""
        self._alerts[alert.id] = alert

    def set_attck(self, counts: dict[str, int]) -> None:
        """Replace the ATT&CK counts returned by :meth:`attck_counts`."""
        self._attck = dict(counts)

    def set_iocs(self, iocs: list[dict[str, Any]]) -> None:
        """Replace the IOC list returned by :meth:`iocs`."""
        self._iocs = list(iocs)

    def set_tls(self, items: list[dict[str, Any]]) -> None:
        """Replace the TLS fingerprint list returned by :meth:`tls_top`."""
        self._tls = list(items)

    def set_profiles(self, profiles: list[ProfileInfo]) -> None:
        """Replace the profile list returned by :meth:`list_profiles`."""
        self._profiles = list(profiles)

    def set_config(self, config: dict[str, Any]) -> None:
        """Replace the dict returned by :meth:`redacted_config`."""
        self._config = dict(config)

    def set_prometheus(self, text: str) -> None:
        """Override the Prometheus exposition text."""
        self._prom_text = text

    # -- HoneytrapService interface ------------------------------------
    def version(self) -> str:
        """Return the semver-like version string for this instance."""
        return self._version

    def uptime_seconds(self) -> float:
        """Return monotonic uptime since construction."""
        return max(0.0, _monotime() - self._started_at)

    def list_sessions(
        self,
        *,
        ip: str | None,
        protocol: str | None,
        since: str | None,
        until: str | None,
        limit: int,
        cursor: str | None,
    ) -> PaginatedResult:
        """Return a filtered, cursor-paginated list of session summaries."""
        items = list(self._sessions.values())
        if ip:
            items = [s for s in items if s.remote_ip == ip]
        if protocol:
            items = [s for s in items if s.protocol.lower() == protocol.lower()]
        if since:
            items = [s for s in items if s.started_at >= since]
        if until:
            items = [s for s in items if s.started_at <= until]
        items.sort(key=lambda s: s.started_at)
        start = int(cursor) if cursor and cursor.isdigit() else 0
        end = start + max(1, int(limit))
        slice_ = items[start:end]
        next_cursor = str(end) if end < len(items) else None
        return PaginatedResult(
            items=[s.summary().to_json() for s in slice_],
            next_cursor=next_cursor,
        )

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Return the full session object or ``None`` if unknown."""
        sess = self._sessions.get(session_id)
        if sess is None:
            return None
        payload = sess.summary().to_json()
        payload["events"] = [e.to_json() for e in sess.events]
        return payload

    def list_session_events(
        self, session_id: str, *, limit: int, cursor: str | None
    ) -> PaginatedResult:
        """Paginate events for a single session, 404 expressed as empty."""
        sess = self._sessions.get(session_id)
        if sess is None:
            return PaginatedResult(items=[])
        start = int(cursor) if cursor and cursor.isdigit() else 0
        end = start + max(1, int(limit))
        slice_ = sess.events[start:end]
        next_cursor = str(end) if end < len(sess.events) else None
        return PaginatedResult(
            items=[e.to_json() for e in slice_],
            next_cursor=next_cursor,
        )

    def session_timeline(self, session_id: str, *, as_text: bool) -> str | list[dict[str, Any]]:
        """Return the session timeline either as text or as a JSON list."""
        sess = self._sessions.get(session_id)
        if sess is None:
            return "" if as_text else []
        if as_text:
            return "\n".join(
                f"{entry.get('timestamp', '')} {entry.get('kind', '')} "
                f"{entry.get('description', '')}"
                for entry in sess.timeline
            )
        return list(sess.timeline)

    def session_pcap(self, session_id: str) -> bytes:
        """Return the raw PCAP bytes (empty when unknown)."""
        sess = self._sessions.get(session_id)
        return sess.pcap if sess else b""

    def session_jsonl(self, session_id: str) -> bytes:
        """Return the gzipped JSONL bytes (empty when unknown)."""
        sess = self._sessions.get(session_id)
        return sess.jsonl if sess else b""

    def list_alerts(
        self,
        *,
        severity: str | None,
        since: str | None,
        acknowledged: bool | None,
        limit: int,
        cursor: str | None,
    ) -> PaginatedResult:
        """Return a filtered, cursor-paginated list of alert records."""
        items = list(self._alerts.values())
        if severity:
            items = [a for a in items if a.severity.upper() == severity.upper()]
        if since:
            items = [a for a in items if a.timestamp >= since]
        if acknowledged is not None:
            items = [a for a in items if a.acknowledged == acknowledged]
        items.sort(key=lambda a: a.timestamp)
        start = int(cursor) if cursor and cursor.isdigit() else 0
        end = start + max(1, int(limit))
        slice_ = items[start:end]
        next_cursor = str(end) if end < len(items) else None
        return PaginatedResult(
            items=[a.to_json() for a in slice_],
            next_cursor=next_cursor,
        )

    def ack_alert(self, alert_id: str, *, actor: str, note: str | None) -> AlertRecord | None:
        """Mark an alert acknowledged and return the updated record."""
        alert = self._alerts.get(alert_id)
        if alert is None:
            return None
        alert.acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc).isoformat()
        alert.acknowledged_by = actor
        alert.note = note
        return alert

    def attck_counts(self) -> dict[str, int]:
        """Return the ATT&CK technique -> count mapping."""
        return dict(self._attck)

    def iocs(self, *, ioc_type: str | None) -> list[dict[str, Any]]:
        """Return IOCs, optionally filtered to a single type."""
        if ioc_type is None:
            return list(self._iocs)
        return [i for i in self._iocs if i.get("type") == ioc_type]

    def tls_top(self, *, top: int) -> list[dict[str, Any]]:
        """Return the top-N TLS fingerprints, capped at ``top``."""
        return list(self._tls[: max(0, int(top))])

    def ai_session_memory(self, session_id: str) -> dict[str, Any] | None:
        """Return the fake session memory set by :meth:`set_ai_memory`."""
        return dict(self._ai_memories[session_id]) if session_id in self._ai_memories else None

    def ai_intent_counts(self) -> dict[str, int]:
        """Return the intent-label histogram."""
        return dict(self._ai_intents)

    def ai_backend_health(self) -> list[dict[str, Any]]:
        """Return the configured backends' last-success timestamps."""
        return list(self._ai_backend_health)

    def prometheus_text(self) -> str:
        """Return the Prometheus text exposition."""
        return self._prom_text

    def metrics_summary(self) -> MetricsSnapshot:
        """Return a lightweight metrics summary suitable for dashboards."""
        return MetricsSnapshot(
            uptime_seconds=self.uptime_seconds(),
            active_sessions=sum(1 for s in self._sessions.values() if s.ended_at is None),
            connections_total=len(self._sessions),
            events_total=sum(len(s.events) for s in self._sessions.values()),
            alerts_sent_total=len(self._alerts),
            api_requests_total=0,
        )

    def list_profiles(self) -> list[ProfileInfo]:
        """Return all known device profiles."""
        return list(self._profiles)

    def get_profile(self, name: str) -> ProfileInfo | None:
        """Return a single profile by name or ``None``."""
        for prof in self._profiles:
            if prof.name == name:
                return prof
        return None

    def reload_profile(self) -> dict[str, Any]:
        """Bump the reload counter; returns an acknowledgement dict."""
        self._reload_counter += 1
        return {"reloaded": True, "count": self._reload_counter}

    def redacted_config(self) -> dict[str, Any]:
        """Return a sanitised copy of the effective configuration."""
        return dict(self._config)

    def pause(self) -> None:
        """Flip the paused flag in :attr:`control`."""
        self.control.paused = True

    def resume(self) -> None:
        """Clear the paused flag in :attr:`control`."""
        self.control.paused = False

    def shutdown(self) -> None:
        """Mark the service as having received a shutdown request."""
        self.control.shutdown_requested = True


def _monotime() -> float:
    """Wrapper around :func:`time.monotonic` for test monkey-patching."""
    import time

    return time.monotonic()


def public_api_key(record: Any) -> APIKeyPublic:
    """Convert an :class:`~honeytrap.api.auth.APIKey` into the public DTO."""
    return APIKeyPublic(
        id=record.id,
        name=record.name,
        role=record.role.value,
        prefix=record.prefix,
        created_at=record.created_at,
        last_used_at=record.last_used_at,
        revoked_at=record.revoked_at,
    )
