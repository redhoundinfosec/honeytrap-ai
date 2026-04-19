"""Log event data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Event:
    """A single honeypot event destined for logs, DB, and the UI."""

    protocol: str
    event_type: str
    remote_ip: str
    message: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    remote_port: int = 0
    local_port: int = 0
    session_id: str = ""
    country_code: str = "XX"
    country_name: str = "Unknown"
    asn: str = ""
    username: str = ""
    password: str = ""
    path: str = ""
    method: str = ""
    user_agent: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dict."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "protocol": self.protocol,
            "event_type": self.event_type,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "local_port": self.local_port,
            "session_id": self.session_id,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "asn": self.asn,
            "username": self.username,
            "password": self.password,
            "path": self.path,
            "method": self.method,
            "user_agent": self.user_agent,
            "message": self.message,
            "data": self.data,
        }
