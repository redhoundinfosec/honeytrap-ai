"""SQLite persistence for structured attack data.

The database is the *critical* tier of the logging pipeline: even when
JSONL files get pruned, the SQLite store keeps compact rows for every
event, making it the authoritative source for reports.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

from honeytrap.logging.models import Event

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    protocol TEXT NOT NULL,
    event_type TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER DEFAULT 0,
    local_port INTEGER DEFAULT 0,
    session_id TEXT DEFAULT '',
    country_code TEXT DEFAULT 'XX',
    country_name TEXT DEFAULT 'Unknown',
    asn TEXT DEFAULT '',
    username TEXT DEFAULT '',
    password TEXT DEFAULT '',
    path TEXT DEFAULT '',
    method TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    message TEXT DEFAULT '',
    data TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events(remote_ip);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_country ON events(country_code);
CREATE INDEX IF NOT EXISTS idx_events_proto ON events(protocol);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
"""


class AttackDatabase:
    """Thin threadsafe wrapper around a local SQLite file."""

    def __init__(self, path: Path) -> None:
        """Open or create the SQLite attack database at the given path."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            isolation_level=None,  # autocommit
        )
        self._conn.executescript(_SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL;")

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def record_event(self, event: Event) -> None:
        """Insert a single event row."""
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO events (
                        timestamp, protocol, event_type, remote_ip, remote_port,
                        local_port, session_id, country_code, country_name, asn,
                        username, password, path, method, user_agent, message, data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.timestamp.isoformat(),
                        event.protocol,
                        event.event_type,
                        event.remote_ip,
                        event.remote_port,
                        event.local_port,
                        event.session_id,
                        event.country_code,
                        event.country_name,
                        event.asn,
                        event.username,
                        event.password,
                        event.path,
                        event.method,
                        event.user_agent,
                        event.message,
                        json.dumps(event.data, ensure_ascii=False, default=str),
                    ),
                )
            except sqlite3.Error as exc:
                logger.warning("SQLite insert failed: %s", exc)

    # ------------------------------------------------------------------
    # Reads used by the reporting layer
    # ------------------------------------------------------------------
    def count(self) -> int:
        """Return total event count."""
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM events")
            return int(cur.fetchone()[0])

    def top_attackers(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the top attacker IPs by event count."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT remote_ip, country_code, country_name,
                       COUNT(*) AS events,
                       COUNT(DISTINCT protocol) AS protocols,
                       GROUP_CONCAT(DISTINCT protocol) AS protocol_list
                FROM events
                WHERE remote_ip != ''
                GROUP BY remote_ip
                ORDER BY events DESC
                LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def country_distribution(self) -> list[dict[str, Any]]:
        """Return events per country."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT country_code, country_name, COUNT(*) AS events,
                       COUNT(DISTINCT remote_ip) AS unique_ips
                FROM events
                GROUP BY country_code, country_name
                ORDER BY events DESC
                """
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def top_credentials(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most-tried username/password combos."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT username, password, COUNT(*) AS attempts
                FROM events
                WHERE event_type = 'auth_attempt'
                  AND (username != '' OR password != '')
                GROUP BY username, password
                ORDER BY attempts DESC
                LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def top_paths(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most-requested HTTP paths."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT path, COUNT(*) AS hits
                FROM events
                WHERE path != ''
                GROUP BY path
                ORDER BY hits DESC
                LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def events_by_protocol(self) -> list[dict[str, Any]]:
        """Return event counts per protocol."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT protocol, COUNT(*) AS events
                FROM events
                GROUP BY protocol
                ORDER BY events DESC
                """
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def events_by_type(self) -> list[dict[str, Any]]:
        """Return event counts per type."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT event_type, COUNT(*) AS events
                FROM events
                GROUP BY event_type
                ORDER BY events DESC
                """
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent events (for dashboards and reports)."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT timestamp, protocol, event_type, remote_ip,
                       country_code, path, username, message
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def unique_ip_count(self) -> int:
        """Return count of distinct attacker IPs."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(DISTINCT remote_ip) FROM events WHERE remote_ip != ''"
            )
            return int(cur.fetchone()[0])

    def geo_behavior(self) -> list[dict[str, Any]]:
        """Summarize attacker behavior per country for geo-response comparison."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT country_code, country_name,
                       COUNT(*) AS events,
                       COUNT(DISTINCT remote_ip) AS unique_ips,
                       COUNT(DISTINCT session_id) AS sessions,
                       SUM(CASE WHEN event_type = 'auth_attempt' THEN 1 ELSE 0 END) AS auth_attempts,
                       SUM(CASE WHEN event_type = 'exploit_attempt' THEN 1 ELSE 0 END) AS exploits
                FROM events
                GROUP BY country_code, country_name
                ORDER BY events DESC
                """
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
