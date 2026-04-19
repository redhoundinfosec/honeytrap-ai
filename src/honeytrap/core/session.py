"""Per-attacker session tracking.

Every connection is tied to a :class:`Session` object keyed by ``(ip, port)``
tuples. Sessions survive across protocol handlers so the reporting layer can
correlate cross-protocol behavior from the same IP.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """Tracks a single attacker-initiated interaction."""

    session_id: str
    remote_ip: str
    remote_port: int
    protocol: str
    local_port: int
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    country_code: str = "XX"
    country_name: str = "Unknown"
    asn: str = ""
    commands: list[str] = field(default_factory=list)
    credentials_tried: list[tuple[str, str]] = field(default_factory=list)
    bytes_in: int = 0
    bytes_out: int = 0
    tags: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def record_command(self, command: str) -> None:
        """Append a command issued by the attacker."""
        self.commands.append(command)

    def record_credentials(self, username: str, password: str) -> None:
        """Append a credential attempt (username, password)."""
        self.credentials_tried.append((username, password))

    def add_tag(self, tag: str) -> None:
        """Tag a session with a behavior marker (e.g., ``brute_force``)."""
        self.tags.add(tag)

    def close(self) -> None:
        """Mark the session as ended."""
        if self.ended_at is None:
            self.ended_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float:
        """Return session duration in seconds, live if still open."""
        end = self.ended_at or datetime.now(timezone.utc)
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Serialize for logging."""
        return {
            "session_id": self.session_id,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "protocol": self.protocol,
            "local_port": self.local_port,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "asn": self.asn,
            "commands": list(self.commands),
            "credentials_tried": [list(pair) for pair in self.credentials_tried],
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "tags": sorted(self.tags),
            "metadata": dict(self.metadata),
            "duration_seconds": self.duration_seconds,
        }


class SessionManager:
    """Holds active and recently-closed sessions in memory."""

    def __init__(self, max_history: int = 500) -> None:
        """Initialize session manager with database and log references."""
        self._active: dict[str, Session] = {}
        self._history: list[Session] = []
        self._max_history = max_history
        self._by_ip: dict[str, list[str]] = defaultdict(list)

    def create(
        self,
        remote_ip: str,
        remote_port: int,
        protocol: str,
        local_port: int,
    ) -> Session:
        """Create and register a new session."""
        session_id = uuid.uuid4().hex[:12]
        session = Session(
            session_id=session_id,
            remote_ip=remote_ip,
            remote_port=remote_port,
            protocol=protocol,
            local_port=local_port,
        )
        self._active[session_id] = session
        self._by_ip[remote_ip].append(session_id)
        logger.debug("Session %s created for %s:%d (%s)", session_id, remote_ip, remote_port, protocol)
        return session

    def close(self, session_id: str) -> Session | None:
        """Close and archive a session by id."""
        session = self._active.pop(session_id, None)
        if session is None:
            return None
        session.close()
        self._history.append(session)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]
        return session

    def active(self) -> list[Session]:
        """Return a list of currently active sessions."""
        return list(self._active.values())

    def history(self) -> list[Session]:
        """Return an immutable snapshot of recent sessions."""
        return list(self._history)

    def by_ip(self, ip: str) -> list[Session]:
        """Return every session (active or archived) associated with an IP."""
        ids = self._by_ip.get(ip, [])
        result: list[Session] = []
        for sid in ids:
            if sid in self._active:
                result.append(self._active[sid])
        for session in self._history:
            if session.remote_ip == ip:
                result.append(session)
        return result
