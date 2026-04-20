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

CREATE TABLE IF NOT EXISTS attack_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    sub_technique_id TEXT DEFAULT '',
    confidence REAL DEFAULT 0.8,
    matched_on TEXT DEFAULT '',
    timestamp TEXT NOT NULL,
    remote_ip TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_attack_event ON attack_mappings(event_id);
CREATE INDEX IF NOT EXISTS idx_attack_tech ON attack_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_attack_tactic ON attack_mappings(tactic);
CREATE INDEX IF NOT EXISTS idx_attack_ip ON attack_mappings(remote_ip);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    confidence REAL DEFAULT 0.8,
    session_id TEXT DEFAULT '',
    sightings INTEGER DEFAULT 1,
    UNIQUE(type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_session ON iocs(session_id);
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
    def record_event(self, event: Event) -> int | None:
        """Insert a single event row.

        Returns the inserted row id, or ``None`` on failure.
        """
        with self._lock:
            try:
                cur = self._conn.execute(
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
                return int(cur.lastrowid) if cur.lastrowid is not None else None
            except sqlite3.Error as exc:
                logger.warning("SQLite insert failed: %s", exc)
                return None

    def record_attack_mapping(
        self,
        event_id: int,
        mapping: Any,
        *,
        timestamp: str | None = None,
        remote_ip: str = "",
    ) -> None:
        """Persist a single :class:`ATTACKMapping` row.

        ``mapping`` is typed ``Any`` to avoid a hard dependency cycle with the
        intel module; the object must expose ``technique_id``, ``technique_name``,
        ``tactic``, ``sub_technique_id``, ``confidence``, and ``matched_on``.
        """
        from datetime import datetime, timezone

        ts = timestamp or datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO attack_mappings (
                        event_id, technique_id, technique_name, tactic,
                        sub_technique_id, confidence, matched_on, timestamp, remote_ip
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        mapping.technique_id,
                        mapping.technique_name,
                        mapping.tactic,
                        mapping.sub_technique_id or "",
                        float(mapping.confidence),
                        getattr(mapping, "matched_on", "") or "",
                        ts,
                        remote_ip,
                    ),
                )
            except sqlite3.Error as exc:
                logger.warning("SQLite insert failed (attack_mapping): %s", exc)

    def record_ioc(self, ioc: Any) -> None:
        """Insert or update an IOC row.

        Re-observing an existing (type, value) pair refreshes ``last_seen``,
        raises confidence if higher, and increments the sighting counter.
        """
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO iocs (
                        type, value, context, first_seen, last_seen,
                        confidence, session_id, sightings
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(type, value) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        confidence = MAX(iocs.confidence, excluded.confidence),
                        sightings = iocs.sightings + 1
                    """,
                    (
                        ioc.type,
                        ioc.value,
                        ioc.context,
                        ioc.first_seen.isoformat(),
                        ioc.last_seen.isoformat(),
                        float(ioc.confidence),
                        ioc.session_id,
                    ),
                )
            except sqlite3.Error as exc:
                logger.warning("SQLite insert failed (ioc): %s", exc)

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

    # ------------------------------------------------------------------
    # Threat intelligence queries
    # ------------------------------------------------------------------
    def get_top_techniques(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most-observed MITRE ATT&CK techniques."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT technique_id, technique_name, tactic,
                       COUNT(*) AS events,
                       COUNT(DISTINCT remote_ip) AS unique_ips,
                       AVG(confidence) AS avg_confidence
                FROM attack_mappings
                GROUP BY technique_id, technique_name, tactic
                ORDER BY events DESC
                LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_tactic_distribution(self) -> list[dict[str, Any]]:
        """Return event counts grouped by ATT&CK tactic."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT tactic, COUNT(*) AS events,
                       COUNT(DISTINCT technique_id) AS techniques
                FROM attack_mappings
                GROUP BY tactic
                ORDER BY events DESC
                """
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_technique_to_attacker(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return technique IDs correlated with attacker IPs."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT technique_id, technique_name, remote_ip,
                       COUNT(*) AS events
                FROM attack_mappings
                WHERE remote_ip != ''
                GROUP BY technique_id, remote_ip
                ORDER BY events DESC
                LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_attack_timeline(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return recent attack mappings in chronological order (newest first)."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT timestamp, technique_id, technique_name, tactic,
                       remote_ip, confidence
                FROM attack_mappings
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_iocs_by_type(self, ioc_type: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return IOCs of a given type, ordered by sightings desc."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT type, value, context, first_seen, last_seen,
                       confidence, session_id, sightings
                FROM iocs
                WHERE type = ?
                ORDER BY sightings DESC, last_seen DESC
                LIMIT ?
                """,
                (ioc_type, limit),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_ioc_summary(self) -> list[dict[str, Any]]:
        """Return a per-type summary of IOC counts."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT type, COUNT(*) AS unique_values, SUM(sightings) AS sightings
                FROM iocs
                GROUP BY type
                ORDER BY sightings DESC
                """
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_top_iocs(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most frequently-seen IOCs across all types."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT type, value, sightings, confidence, last_seen
                FROM iocs
                ORDER BY sightings DESC, last_seen DESC
                LIMIT ?
                """,
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

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
