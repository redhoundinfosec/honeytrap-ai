"""Data models for the HoneyTrap alerting subsystem.

The :class:`Alert` dataclass is the single currency used by the rule
engine, channels, and templates. :class:`AlertSeverity` is an
:class:`enum.IntEnum` so severity thresholds compose naturally with
ordinary comparison operators.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class AlertSeverity(enum.IntEnum):
    """Severity levels for alerts.

    Higher integer value means higher severity so comparisons like
    ``severity >= AlertSeverity.HIGH`` work as expected.
    """

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @classmethod
    def from_name(cls, name: str | AlertSeverity) -> AlertSeverity:
        """Parse a case-insensitive severity name or pass-through an enum value."""
        if isinstance(name, AlertSeverity):
            return name
        key = str(name).strip().upper()
        if key in cls.__members__:
            return cls[key]
        raise ValueError(f"Unknown alert severity: {name!r}")


@dataclass
class Alert:
    """A single alert emitted by the rule engine and dispatched to channels."""

    title: str
    summary: str
    severity: AlertSeverity = AlertSeverity.MEDIUM
    source_ip: str = ""
    protocol: str = ""
    session_id: str = ""
    attck_techniques: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    raw_event: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the alert."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.name,
            "severity_level": int(self.severity),
            "title": self.title,
            "summary": self.summary,
            "source_ip": self.source_ip,
            "protocol": self.protocol,
            "session_id": self.session_id,
            "attck_techniques": list(self.attck_techniques),
            "iocs": {k: list(v) for k, v in self.iocs.items()},
            "tags": sorted(self.tags),
            "raw_event": dict(self.raw_event),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Alert:
        """Reconstruct an :class:`Alert` from the dict produced by :meth:`to_dict`."""
        severity = AlertSeverity.from_name(payload.get("severity", "MEDIUM"))
        ts_raw = payload.get("timestamp")
        if isinstance(ts_raw, datetime):
            ts = ts_raw
        elif isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw)
            except ValueError:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)
        iocs_raw = payload.get("iocs") or {}
        iocs: dict[str, list[str]] = {k: list(v) for k, v in iocs_raw.items()}
        return cls(
            title=str(payload.get("title", "")),
            summary=str(payload.get("summary", "")),
            severity=severity,
            source_ip=str(payload.get("source_ip", "")),
            protocol=str(payload.get("protocol", "")),
            session_id=str(payload.get("session_id", "")),
            attck_techniques=list(payload.get("attck_techniques") or []),
            iocs=iocs,
            tags=set(payload.get("tags") or []),
            raw_event=dict(payload.get("raw_event") or {}),
            id=str(payload.get("id") or uuid.uuid4()),
            timestamp=ts,
        )
