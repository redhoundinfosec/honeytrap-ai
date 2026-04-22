"""Pure-dataclass projections of domain objects exposed through the API.

These mirror the shapes already produced by ``to_dict`` methods in the
existing forensics, alerts, and intel modules, but centralise the field
definitions so :mod:`honeytrap.api.openapi` can introspect them cleanly.

Every model implements :meth:`to_json` to produce a stable JSON dict.
No pydantic dependency is introduced.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class SessionSummary:
    """Lightweight session listing item."""

    session_id: str
    protocol: str
    remote_ip: str
    remote_port: int
    local_port: int
    started_at: str
    ended_at: str | None
    frame_count: int
    bytes_in: int
    bytes_out: int
    truncated: bool = False

    def to_json(self) -> dict[str, Any]:
        """Return the JSON dict for this record."""
        return asdict(self)


@dataclass
class EventRecord:
    """Normalised protocol event for listing endpoints."""

    session_id: str
    timestamp: str
    direction: str
    protocol: str
    source_ip: str
    size: int

    def to_json(self) -> dict[str, Any]:
        """Return the JSON dict for this record."""
        return asdict(self)


@dataclass
class AlertRecord:
    """Public projection of :class:`honeytrap.alerts.models.Alert`."""

    id: str
    severity: str
    title: str
    summary: str
    source_ip: str
    protocol: str
    session_id: str
    timestamp: str
    acknowledged: bool = False
    acknowledged_at: str | None = None
    acknowledged_by: str | None = None
    note: str | None = None
    attck_techniques: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        """Return the JSON dict for this record."""
        return asdict(self)


@dataclass
class MetricsSnapshot:
    """JSON summary of key Prometheus counters."""

    uptime_seconds: float
    active_sessions: int
    connections_total: int
    events_total: int
    alerts_sent_total: int
    api_requests_total: int

    def to_json(self) -> dict[str, Any]:
        """Return the JSON dict for this snapshot."""
        return asdict(self)


@dataclass
class ProfileInfo:
    """Minimal profile record for listing endpoints."""

    name: str
    category: str
    description: str
    services: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        """Return the JSON dict for this record."""
        return asdict(self)


@dataclass
class APIKeyPublic:
    """Secret-free public projection of an :class:`~honeytrap.api.auth.APIKey`."""

    id: str
    name: str
    role: str
    prefix: str
    created_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None

    def to_json(self) -> dict[str, Any]:
        """Return the JSON dict for this record."""
        return asdict(self)
