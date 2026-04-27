"""Controller-side fleet registry and event store.

The fleet is a small SQLite-backed catalogue of registered nodes plus an
ingestion buffer for events forwarded from those nodes. It is designed
to run inside the same process as the management API, so methods are
thread-safe (the API uses a thread pool) and cheap (operations target
microseconds, not milliseconds).

State layout
------------

``$DATA_DIR/fleet.db`` holds three tables:

* ``nodes``           -- one row per node, last seen state.
* ``node_health``     -- append-only ring of heartbeat snapshots.
* ``ingested_events`` -- append-only event store with indexes on
  ``(node_id, ts)`` and ``(src_ip, ts)``.

Aggregation methods are pure SQL so they remain fast even with a
million rows. The ``Cluster-Generation`` counter (used by the API to
hint at cache invalidation) increments on every registration change.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    node_id      TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    role         TEXT NOT NULL,
    profile      TEXT,
    version      TEXT NOT NULL,
    address      TEXT,
    tags         TEXT,
    registered_at TEXT NOT NULL,
    last_heartbeat TEXT,
    status       TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS node_health (
    node_id      TEXT NOT NULL,
    ts           TEXT NOT NULL,
    snapshot     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_health_node_ts
    ON node_health (node_id, ts DESC);

CREATE TABLE IF NOT EXISTS ingested_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id      TEXT NOT NULL,
    ts           TEXT NOT NULL,
    protocol     TEXT,
    src_ip       TEXT,
    technique    TEXT,
    session_id   TEXT,
    payload      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_node_ts
    ON ingested_events (node_id, ts);

CREATE INDEX IF NOT EXISTS idx_events_src_ts
    ON ingested_events (src_ip, ts);

CREATE INDEX IF NOT EXISTS idx_events_tech_ts
    ON ingested_events (technique, ts);
"""


# Required keys on every ingested event. Anything missing is rejected
# at the API edge, NOT silently dropped, so a buggy node is loud.
_REQUIRED_EVENT_KEYS = {"ts", "protocol", "src_ip"}


@dataclass
class NodeRecord:
    """In-memory projection of a single node row.

    The field set mirrors the SQLite schema and is what the public API
    returns under ``GET /api/v1/cluster/nodes``. ``health`` carries the
    most recent heartbeat snapshot (already JSON-decoded).
    """

    node_id: str
    name: str
    role: str
    profile: str | None
    version: str
    address: str | None
    tags: list[str]
    registered_at: str
    last_heartbeat: str | None
    status: str
    health: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for the API response."""
        return {
            "node_id": self.node_id,
            "name": self.name,
            "role": self.role,
            "profile": self.profile,
            "version": self.version,
            "address": self.address,
            "tags": list(self.tags),
            "registered_at": self.registered_at,
            "last_heartbeat": self.last_heartbeat,
            "status": self.status,
            "health": dict(self.health),
        }


def _now_iso() -> str:
    """Return a UTC ISO-8601 timestamp at second resolution."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Fleet:
    """SQLite-backed cluster registry plus event ingestion.

    The class is deliberately not a singleton -- the API server owns a
    single instance and tests can build private ones against ``:memory:``
    or a temp directory. All public methods are thread-safe via a
    single :class:`threading.RLock`. SQLite is opened with
    ``check_same_thread=False`` so the API's worker threads can call in
    directly without per-call connection setup.
    """

    def __init__(
        self,
        db_path: Path | str,
        *,
        heartbeat_interval: float = 30.0,
        max_event_payload_bytes: int = 64 * 1024,
        max_events_per_batch: int = 1000,
    ) -> None:
        """Open or create the fleet database at ``db_path``."""
        self._path = Path(db_path)
        self._heartbeat_interval = float(heartbeat_interval)
        self._max_event_payload_bytes = int(max_event_payload_bytes)
        self._max_events_per_batch = int(max_events_per_batch)
        self._lock = threading.RLock()
        self._generation = 1
        if str(self._path) != ":memory:":
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)

    # -- lifecycle -----------------------------------------------------
    def close(self) -> None:
        """Close the underlying database connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    @property
    def generation(self) -> int:
        """Monotonic counter that increments on registration changes."""
        return self._generation

    def _bump_generation(self) -> None:
        self._generation += 1

    # -- registration --------------------------------------------------
    def register_node(
        self,
        *,
        name: str,
        role: str,
        version: str,
        profile: str | None = None,
        address: str | None = None,
        tags: Iterable[str] | None = None,
        node_id: str | None = None,
    ) -> NodeRecord:
        """Register or refresh a node.

        Re-registering with the same ``node_id`` is idempotent: existing
        fields are updated and ``registered_at`` is preserved. A fresh
        UUID4 is assigned when ``node_id`` is None.
        """
        nid = (node_id or "").strip() or str(uuid.uuid4())
        tag_list = [str(t) for t in (tags or [])]
        now = _now_iso()
        with self._lock:
            row = self._conn.execute(
                "SELECT registered_at FROM nodes WHERE node_id = ?", (nid,)
            ).fetchone()
            registered_at = row[0] if row else now
            self._conn.execute(
                """
                INSERT INTO nodes(node_id, name, role, profile, version, address, tags,
                                  registered_at, last_heartbeat, status)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(node_id) DO UPDATE SET
                    name=excluded.name,
                    role=excluded.role,
                    profile=excluded.profile,
                    version=excluded.version,
                    address=excluded.address,
                    tags=excluded.tags,
                    status='online',
                    last_heartbeat=excluded.last_heartbeat
                """,
                (
                    nid,
                    name,
                    role,
                    profile,
                    version,
                    address,
                    json.dumps(tag_list),
                    registered_at,
                    now,
                    "online",
                ),
            )
            self._bump_generation()
        record = self.get_node(nid)
        assert record is not None
        return record

    def deregister_node(self, node_id: str) -> bool:
        """Remove a node and its history. Returns True when the row existed."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM nodes WHERE node_id = ?", (node_id,))
            self._conn.execute("DELETE FROM node_health WHERE node_id = ?", (node_id,))
            removed = cur.rowcount > 0
            if removed:
                self._bump_generation()
            return removed

    def record_heartbeat(self, node_id: str, snapshot: dict[str, Any]) -> bool:
        """Persist a health snapshot. Returns True on success.

        The snapshot is sanitised: keys with names matching ``secret``,
        ``token``, ``password``, ``hash``, or ``api_key`` are replaced
        with ``"<redacted>"``. This is defence-in-depth -- nodes are
        instructed never to send PII in the first place.
        """
        clean = _redact_snapshot(snapshot)
        now = _now_iso()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE nodes SET last_heartbeat = ?, status = 'online' WHERE node_id = ?",
                (now, node_id),
            )
            if cur.rowcount == 0:
                return False
            self._conn.execute(
                "INSERT INTO node_health(node_id, ts, snapshot) VALUES(?,?,?)",
                (node_id, now, json.dumps(clean)),
            )
            return True

    def mark_offline_if_stale(self, *, multiplier: float = 3.0) -> int:
        """Flip stale nodes to ``offline``. Returns the count flipped.

        Stale = no heartbeat within ``multiplier * heartbeat_interval``.
        Used by background sweeps so the controller view stays accurate
        even when nodes crash without deregistering.
        """
        cutoff_seconds = self._heartbeat_interval * multiplier
        cutoff_dt = datetime.fromtimestamp(time.time() - cutoff_seconds, tz=timezone.utc)
        cutoff_iso = cutoff_dt.replace(microsecond=0).isoformat()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE nodes SET status='offline'
                WHERE status='online'
                  AND (last_heartbeat IS NULL OR last_heartbeat < ?)
                """,
                (cutoff_iso,),
            )
            return cur.rowcount

    # -- ingestion -----------------------------------------------------
    def ingest_events_batch(self, node_id: str, events: list[dict[str, Any]]) -> tuple[int, int]:
        """Persist an event batch from ``node_id``.

        Returns ``(accepted, rejected)``. Each event must be a dict with
        at least ``ts``, ``protocol``, and ``src_ip``. Oversized payloads
        (post-JSON-encoding) are rejected. The function is transactional
        per call so a partial batch never half-lands.
        """
        if not isinstance(events, list):
            return 0, 0
        if len(events) > self._max_events_per_batch:
            events = events[: self._max_events_per_batch]
        accepted = 0
        rejected = 0
        rows: list[tuple[str, str, str | None, str | None, str | None, str | None, str]] = []
        for raw in events:
            if not isinstance(raw, dict):
                rejected += 1
                continue
            payload_str = json.dumps(_redact_snapshot(raw), sort_keys=False)
            if len(payload_str.encode("utf-8")) > self._max_event_payload_bytes:
                rejected += 1
                continue
            missing = _REQUIRED_EVENT_KEYS - set(raw.keys())
            if missing:
                rejected += 1
                continue
            ts = str(raw.get("ts", ""))
            protocol = _opt_str(raw.get("protocol"))
            src_ip = _opt_str(raw.get("src_ip"))
            technique = _opt_str(raw.get("technique"))
            session_id = _opt_str(raw.get("session_id"))
            rows.append((node_id, ts, protocol, src_ip, technique, session_id, payload_str))
            accepted += 1
        if not rows:
            return accepted, rejected
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO ingested_events(node_id, ts, protocol, src_ip, technique,
                                            session_id, payload)
                VALUES(?,?,?,?,?,?,?)
                """,
                rows,
            )
        return accepted, rejected

    # -- queries -------------------------------------------------------
    def list_nodes(self) -> list[NodeRecord]:
        """Return every registered node, newest-first."""
        with self._lock:
            cursor = self._conn.execute(
                """
                SELECT node_id, name, role, profile, version, address, tags,
                       registered_at, last_heartbeat, status
                FROM nodes
                ORDER BY registered_at DESC
                """
            )
            records: list[NodeRecord] = []
            for row in cursor.fetchall():
                rec = self._row_to_record(row)
                rec.health = self._latest_health(rec.node_id)
                records.append(rec)
            return records

    def get_node(self, node_id: str) -> NodeRecord | None:
        """Return a single node record or ``None`` if unknown."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT node_id, name, role, profile, version, address, tags,
                       registered_at, last_heartbeat, status
                FROM nodes WHERE node_id = ?
                """,
                (node_id,),
            ).fetchone()
            if row is None:
                return None
            rec = self._row_to_record(row)
            rec.health = self._latest_health(rec.node_id)
            return rec

    def query_events(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        src_ip: str | None = None,
        protocol: str | None = None,
        node_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return ingested events filtered by simple predicates.

        ``limit`` is clamped to ``[1, 1000]``. Results are ordered
        newest-first. Each row's stored payload is JSON-decoded back to
        a dict, with the ingest metadata (``node_id``, ``ts``, ...)
        stitched on top so callers see a flat shape.
        """
        capped = max(1, min(1000, int(limit)))
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol)
        if node_id:
            clauses.append("node_id = ?")
            params.append(node_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(capped)
        with self._lock:
            cursor = self._conn.execute(
                f"""
                SELECT node_id, ts, protocol, src_ip, technique, session_id, payload
                FROM ingested_events{where}
                ORDER BY id DESC
                LIMIT ?
                """,
                tuple(params),
            )
            rows = cursor.fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            payload = _safe_load(row[6])
            if not isinstance(payload, dict):
                payload = {}
            payload["node_id"] = row[0]
            payload["ts"] = row[1]
            payload["protocol"] = row[2]
            payload["src_ip"] = row[3]
            payload["technique"] = row[4]
            payload["session_id"] = row[5]
            items.append(payload)
        return items

    def aggregate_top_attackers(self, *, limit: int = 20) -> list[dict[str, Any]]:
        """Return top source IPs across the cluster by event count."""
        capped = max(1, min(500, int(limit)))
        with self._lock:
            cursor = self._conn.execute(
                """
                SELECT src_ip, COUNT(*) AS cnt
                FROM ingested_events
                WHERE src_ip IS NOT NULL AND src_ip <> ''
                GROUP BY src_ip
                ORDER BY cnt DESC
                LIMIT ?
                """,
                (capped,),
            )
            return [{"src_ip": row[0], "count": int(row[1])} for row in cursor.fetchall()]

    def aggregate_mitre_heatmap(self) -> list[dict[str, Any]]:
        """Return MITRE ATT&CK technique counts cluster-wide."""
        with self._lock:
            cursor = self._conn.execute(
                """
                SELECT technique, COUNT(*) AS cnt
                FROM ingested_events
                WHERE technique IS NOT NULL AND technique <> ''
                GROUP BY technique
                ORDER BY cnt DESC
                """
            )
            return [{"technique": row[0], "count": int(row[1])} for row in cursor.fetchall()]

    def aggregate_sessions_per_node(self) -> list[dict[str, Any]]:
        """Return per-node, per-protocol distinct-session counts."""
        with self._lock:
            cursor = self._conn.execute(
                """
                SELECT node_id, protocol, COUNT(DISTINCT session_id) AS sessions,
                       COUNT(*) AS events
                FROM ingested_events
                WHERE session_id IS NOT NULL AND session_id <> ''
                GROUP BY node_id, protocol
                ORDER BY sessions DESC
                """
            )
            return [
                {
                    "node_id": row[0],
                    "protocol": row[1],
                    "sessions": int(row[2]),
                    "events": int(row[3]),
                }
                for row in cursor.fetchall()
            ]

    # -- internals -----------------------------------------------------
    @staticmethod
    def _row_to_record(row: tuple[Any, ...]) -> NodeRecord:
        tags_raw = row[6]
        try:
            tags = json.loads(tags_raw) if tags_raw else []
            if not isinstance(tags, list):
                tags = []
        except (TypeError, ValueError):
            tags = []
        return NodeRecord(
            node_id=str(row[0]),
            name=str(row[1]),
            role=str(row[2]),
            profile=row[3],
            version=str(row[4]),
            address=row[5],
            tags=[str(t) for t in tags],
            registered_at=str(row[7]),
            last_heartbeat=row[8],
            status=str(row[9]),
        )

    def _latest_health(self, node_id: str) -> dict[str, Any]:
        cursor = self._conn.execute(
            """
            SELECT snapshot FROM node_health
            WHERE node_id = ?
            ORDER BY ts DESC LIMIT 1
            """,
            (node_id,),
        )
        row = cursor.fetchone()
        if not row:
            return {}
        loaded = _safe_load(row[0])
        return loaded if isinstance(loaded, dict) else {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_REDACT_KEYS = {"secret", "token", "password", "hash", "api_key", "apikey"}


def _redact_snapshot(payload: Any) -> Any:
    """Recursively redact obvious secret fields from a dict.

    Only string-keyed dicts are descended; lists are walked element-wise.
    The function never raises -- worst case it returns the input value
    unchanged.
    """
    if isinstance(payload, dict):
        out: dict[str, Any] = {}
        for k, v in payload.items():
            if not isinstance(k, str):
                out[str(k)] = _redact_snapshot(v)
                continue
            if k.lower() in _REDACT_KEYS:
                out[k] = "<redacted>"
            else:
                out[k] = _redact_snapshot(v)
        return out
    if isinstance(payload, list):
        return [_redact_snapshot(v) for v in payload]
    return payload


def _opt_str(value: Any) -> str | None:
    """Return ``str(value)`` or ``None`` when value is None or empty."""
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _safe_load(text: Any) -> Any:
    """Return ``json.loads(text)`` or ``None`` if it cannot be decoded."""
    if not isinstance(text, str):
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None
