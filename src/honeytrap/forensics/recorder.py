"""Byte-accurate session recording with pluggable persistence.

The :class:`SessionRecorder` is a passive event-bus subscriber: protocol
handlers emit frames via :meth:`SessionRecorder.record_frame` (typically
through the engine's helper) and the recorder writes them to a
:class:`SessionStore` backend. Two stores ship in-tree:

* :class:`JsonlSessionStore` -- one append-only ``*.jsonl.gz`` per
  session, partitioned by UTC date.
* :class:`SqliteSessionStore` -- a single WAL-mode SQLite database with
  ``sessions``, ``frames``, and ``metadata`` tables.

Caps are enforced at two levels: per-session (default 10 MiB) and
per-day (default 1 GiB). When a cap fires the recorder switches to
*sampling* mode -- the first 100 frames and last 100 frames of the
session are kept and a ``truncated=True`` marker is written so analysts
never see silently dropped data.

Recording can be paused at any time by the engine's
:class:`~honeytrap.core.guardian.ResourceGuardian`; pressure pauses
disk writes but the in-memory frame buffer for active sessions remains
so a recovered session can still be flushed.
"""

from __future__ import annotations

import base64
import contextlib
import gzip
import io
import json
import logging
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


class Direction(str, Enum):
    """Direction of a single recorded frame."""

    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


@dataclass
class SessionFrame:
    """A single byte-accurate frame on the wire."""

    session_id: str
    timestamp_ns: int
    direction: Direction
    payload: bytes
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    is_tls_handshake: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict with base64-encoded payload."""
        return {
            "session_id": self.session_id,
            "timestamp_ns": int(self.timestamp_ns),
            "direction": self.direction.value,
            "payload_b64": base64.b64encode(self.payload).decode("ascii"),
            "source_ip": self.source_ip,
            "source_port": int(self.source_port),
            "dest_ip": self.dest_ip,
            "dest_port": int(self.dest_port),
            "protocol": self.protocol,
            "is_tls_handshake": bool(self.is_tls_handshake),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionFrame:
        """Inverse of :meth:`to_dict`. Tolerates unknown extras."""
        payload_b64 = data.get("payload_b64") or ""
        try:
            payload = base64.b64decode(payload_b64.encode("ascii"))
        except Exception:  # noqa: BLE001 — corrupt frame, recover with empty
            payload = b""
        direction_raw = str(data.get("direction") or Direction.INBOUND.value)
        try:
            direction = Direction(direction_raw)
        except ValueError:
            direction = Direction.INBOUND
        return cls(
            session_id=str(data.get("session_id") or ""),
            timestamp_ns=int(data.get("timestamp_ns") or 0),
            direction=direction,
            payload=payload,
            source_ip=str(data.get("source_ip") or ""),
            source_port=int(data.get("source_port") or 0),
            dest_ip=str(data.get("dest_ip") or ""),
            dest_port=int(data.get("dest_port") or 0),
            protocol=str(data.get("protocol") or ""),
            is_tls_handshake=bool(data.get("is_tls_handshake") or False),
        )


@dataclass
class SessionMetadata:
    """Open/close state for a recorded session."""

    session_id: str
    protocol: str
    remote_ip: str
    remote_port: int
    local_ip: str
    local_port: int
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    frame_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    truncated: bool = False
    truncation_reason: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict."""
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "remote_ip": self.remote_ip,
            "remote_port": int(self.remote_port),
            "local_ip": self.local_ip,
            "local_port": int(self.local_port),
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "frame_count": int(self.frame_count),
            "bytes_in": int(self.bytes_in),
            "bytes_out": int(self.bytes_out),
            "truncated": bool(self.truncated),
            "truncation_reason": self.truncation_reason,
            "tags": list(self.tags),
        }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


DEFAULT_MAX_SESSION_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_DAILY_BYTES = 1024 * 1024 * 1024
DEFAULT_RETENTION_DAYS = 30
KEEP_FIRST_FRAMES = 100
KEEP_LAST_FRAMES = 100


@dataclass
class ForensicsConfig:
    """Operator-facing configuration for the recorder."""

    enabled: bool = True
    store: str = "jsonl"  # jsonl | sqlite
    path: str = "./sessions"
    max_session_bytes: int = DEFAULT_MAX_SESSION_BYTES
    max_daily_bytes: int = DEFAULT_MAX_DAILY_BYTES
    retention_days: int = DEFAULT_RETENTION_DAYS
    record_tls_handshake: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Plain dict (for diagnostics)."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Store base class
# ---------------------------------------------------------------------------


class SessionStore(ABC):
    """Pluggable persistence backend for session frames."""

    @abstractmethod
    def open_session(self, metadata: SessionMetadata) -> None:
        """Register a new session. Idempotent for the same session_id."""

    @abstractmethod
    def append_frame(self, frame: SessionFrame) -> None:
        """Persist a single frame. Must be safe to call from one thread per session."""

    @abstractmethod
    def close_session(self, metadata: SessionMetadata) -> None:
        """Mark the session as closed and flush state."""

    @abstractmethod
    def list_sessions(
        self,
        *,
        ip: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[SessionMetadata]:
        """Return matching sessions ordered by start time descending."""

    @abstractmethod
    def load_frames(self, session_id: str) -> list[SessionFrame]:
        """Return every frame for a session in recorded order."""

    @abstractmethod
    def get_metadata(self, session_id: str) -> SessionMetadata | None:
        """Return the metadata blob for a session, or ``None`` if unknown."""

    @abstractmethod
    def sweep_retention(self, retention_days: int) -> int:
        """Delete data older than ``retention_days``. Returns deleted-row count."""

    def close(self) -> None:  # noqa: B027 -- optional hook, default is no-op
        """Optional teardown hook."""


# ---------------------------------------------------------------------------
# JSONL store
# ---------------------------------------------------------------------------


class JsonlSessionStore(SessionStore):
    """One ``sessions/<YYYY>/<MM>/<DD>/<session>.jsonl.gz`` file per session.

    Each line is a single JSON object: a ``meta`` row at session open,
    one frame row per ``append_frame`` call, and a ``meta_close`` row
    when the session closes. Replay code merges these into a clean
    timeline by ignoring duplicate metadata records and keeping only
    the latest values.
    """

    def __init__(self, root: str | Path) -> None:
        """Create the store rooted at ``root`` (created on demand)."""
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._handles: dict[str, gzip.GzipFile] = {}
        self._paths: dict[str, Path] = {}
        self._lock = threading.RLock()

    # -- locating files -------------------------------------------------
    def _path_for(self, session_id: str, started_at: datetime) -> Path:
        ts = started_at.astimezone(timezone.utc)
        directory = self.root / f"{ts.year:04d}" / f"{ts.month:02d}" / f"{ts.day:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        safe_id = "".join(c for c in session_id if c.isalnum() or c in "-_")
        return directory / f"{safe_id}.jsonl.gz"

    def _writer(self, session_id: str, started_at: datetime) -> gzip.GzipFile:
        with self._lock:
            handle = self._handles.get(session_id)
            if handle is not None:
                return handle
            path = self._path_for(session_id, started_at)
            self._paths[session_id] = path
            handle = gzip.open(path, "ab")  # noqa: SIM115 -- long-lived per-session handle
            self._handles[session_id] = handle
            return handle

    def _close_handle(self, session_id: str) -> None:
        with self._lock:
            handle = self._handles.pop(session_id, None)
            if handle is not None:
                try:
                    handle.flush()
                    handle.close()
                except OSError as exc:  # pragma: no cover — best effort
                    logger.debug("Failed to close handle for %s: %s", session_id, exc)

    # -- SessionStore protocol -----------------------------------------
    def open_session(self, metadata: SessionMetadata) -> None:
        """Write the opening ``meta`` row."""
        handle = self._writer(metadata.session_id, metadata.started_at)
        record = {"kind": "meta", **metadata.to_dict()}
        line = json.dumps(record, ensure_ascii=False) + "\n"
        handle.write(line.encode("utf-8"))
        handle.flush()

    def append_frame(self, frame: SessionFrame) -> None:
        """Append a frame row."""
        started = datetime.fromtimestamp(frame.timestamp_ns / 1_000_000_000, timezone.utc)
        handle = self._writer(frame.session_id, started)
        record = {"kind": "frame", **frame.to_dict()}
        line = json.dumps(record, ensure_ascii=False) + "\n"
        handle.write(line.encode("utf-8"))

    def close_session(self, metadata: SessionMetadata) -> None:
        """Write the closing ``meta_close`` row and close the handle."""
        try:
            handle = self._writer(metadata.session_id, metadata.started_at)
            record = {"kind": "meta_close", **metadata.to_dict()}
            handle.write((json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
            handle.flush()
        finally:
            self._close_handle(metadata.session_id)

    def list_sessions(
        self,
        *,
        ip: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[SessionMetadata]:
        """Walk the root tree and return summary metadata for each file."""
        results: list[SessionMetadata] = []
        for path in sorted(self.root.rglob("*.jsonl.gz")):
            meta = _read_jsonl_metadata(path)
            if meta is None:
                continue
            if ip and meta.remote_ip != ip:
                continue
            if since and meta.started_at < since:
                continue
            if until and meta.started_at > until:
                continue
            results.append(meta)
        results.sort(key=lambda m: m.started_at, reverse=True)
        return results

    def load_frames(self, session_id: str) -> list[SessionFrame]:
        """Locate the file by walking the root tree."""
        for path in self.root.rglob(f"{session_id}.jsonl.gz"):
            return _read_jsonl_frames(path)
        return []

    def get_metadata(self, session_id: str) -> SessionMetadata | None:
        """Return the most-recent metadata block for the session, if any."""
        for path in self.root.rglob(f"{session_id}.jsonl.gz"):
            return _read_jsonl_metadata(path)
        return None

    def sweep_retention(self, retention_days: int) -> int:
        """Delete every ``*.jsonl.gz`` older than ``retention_days``."""
        if retention_days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        removed = 0
        for path in self.root.rglob("*.jsonl.gz"):
            try:
                mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            except OSError:
                continue
            if mtime < cutoff:
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    continue
        return removed

    def close(self) -> None:
        """Flush every open handle."""
        with self._lock:
            for sid in list(self._handles):
                self._close_handle(sid)


def _read_jsonl_lines(path: Path) -> Iterator[dict[str, Any]]:
    """Yield every JSON object in a (possibly truncated) gzipped JSONL file."""
    try:
        with gzip.open(path, "rb") as fh:
            for raw in fh:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    # Truncated mid-line; stop cleanly.
                    return
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        logger.debug("Reading %s failed: %s", path, exc)
        return


def _read_jsonl_metadata(path: Path) -> SessionMetadata | None:
    """Reconstruct the latest metadata snapshot from a JSONL session file."""
    meta_obj: dict[str, Any] | None = None
    bytes_in = 0
    bytes_out = 0
    frame_count = 0
    for record in _read_jsonl_lines(path):
        kind = record.get("kind")
        if kind in {"meta", "meta_close"}:
            meta_obj = record
        elif kind == "frame":
            frame_count += 1
            try:
                payload_len = len(
                    base64.b64decode((record.get("payload_b64") or "").encode("ascii"))
                )
            except Exception:  # noqa: BLE001
                payload_len = 0
            if record.get("direction") == Direction.INBOUND.value:
                bytes_in += payload_len
            else:
                bytes_out += payload_len
    if meta_obj is None:
        return None
    started_at = _parse_iso(meta_obj.get("started_at")) or datetime.now(timezone.utc)
    ended_at = _parse_iso(meta_obj.get("ended_at"))
    # Always recompute totals from the actual frames so a partially
    # written close row doesn't lie about size.
    return SessionMetadata(
        session_id=str(meta_obj.get("session_id") or ""),
        protocol=str(meta_obj.get("protocol") or ""),
        remote_ip=str(meta_obj.get("remote_ip") or ""),
        remote_port=int(meta_obj.get("remote_port") or 0),
        local_ip=str(meta_obj.get("local_ip") or ""),
        local_port=int(meta_obj.get("local_port") or 0),
        started_at=started_at,
        ended_at=ended_at,
        frame_count=frame_count or int(meta_obj.get("frame_count") or 0),
        bytes_in=bytes_in or int(meta_obj.get("bytes_in") or 0),
        bytes_out=bytes_out or int(meta_obj.get("bytes_out") or 0),
        truncated=bool(meta_obj.get("truncated") or False),
        truncation_reason=str(meta_obj.get("truncation_reason") or ""),
        tags=list(meta_obj.get("tags") or []),
    )


def _read_jsonl_frames(path: Path) -> list[SessionFrame]:
    """Reconstruct the chronological frame list from a JSONL file."""
    frames: list[SessionFrame] = []
    for record in _read_jsonl_lines(path):
        if record.get("kind") != "frame":
            continue
        frames.append(SessionFrame.from_dict(record))
    frames.sort(key=lambda f: f.timestamp_ns)
    return frames


def _parse_iso(value: Any) -> datetime | None:
    """Tolerant ISO-8601 parser that always returns a UTC-aware datetime."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# SQLite store
# ---------------------------------------------------------------------------


class SqliteSessionStore(SessionStore):
    """Single-file SQLite store with WAL journaling."""

    def __init__(self, path: str | Path) -> None:
        """Open or create the database at ``path``."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    protocol TEXT NOT NULL,
                    remote_ip TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    local_ip TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    truncated INTEGER NOT NULL DEFAULT 0,
                    truncation_reason TEXT NOT NULL DEFAULT ''
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS frames (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp_ns INTEGER NOT NULL,
                    direction TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    dest_ip TEXT NOT NULL,
                    dest_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    is_tls_handshake INTEGER NOT NULL DEFAULT 0,
                    payload BLOB NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    session_id TEXT PRIMARY KEY,
                    tags TEXT NOT NULL DEFAULT '[]',
                    extra TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_frames_session ON frames(session_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(remote_ip)")
            self._conn.commit()

    # -- SessionStore protocol -----------------------------------------
    def open_session(self, metadata: SessionMetadata) -> None:
        """Insert (or replace) the session row."""
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO sessions
                (session_id, protocol, remote_ip, remote_port, local_ip, local_port,
                 started_at, ended_at, truncated, truncation_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    metadata.session_id,
                    metadata.protocol,
                    metadata.remote_ip,
                    metadata.remote_port,
                    metadata.local_ip,
                    metadata.local_port,
                    metadata.started_at.isoformat(),
                    metadata.ended_at.isoformat() if metadata.ended_at else None,
                    1 if metadata.truncated else 0,
                    metadata.truncation_reason,
                ),
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO metadata (session_id, tags, extra) VALUES (?, ?, ?)",
                (metadata.session_id, json.dumps(metadata.tags), "{}"),
            )
            self._conn.commit()

    def append_frame(self, frame: SessionFrame) -> None:
        """Insert a single frame row."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO frames
                (session_id, timestamp_ns, direction, source_ip, source_port,
                 dest_ip, dest_port, protocol, is_tls_handshake, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    frame.session_id,
                    int(frame.timestamp_ns),
                    frame.direction.value,
                    frame.source_ip,
                    int(frame.source_port),
                    frame.dest_ip,
                    int(frame.dest_port),
                    frame.protocol,
                    1 if frame.is_tls_handshake else 0,
                    sqlite3.Binary(frame.payload),
                ),
            )
            self._conn.commit()

    def close_session(self, metadata: SessionMetadata) -> None:
        """Update the session row's close fields."""
        with self._lock:
            self._conn.execute(
                """
                UPDATE sessions SET ended_at = ?, truncated = ?, truncation_reason = ?
                WHERE session_id = ?
                """,
                (
                    (metadata.ended_at or datetime.now(timezone.utc)).isoformat(),
                    1 if metadata.truncated else 0,
                    metadata.truncation_reason,
                    metadata.session_id,
                ),
            )
            self._conn.commit()

    def list_sessions(
        self,
        *,
        ip: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[SessionMetadata]:
        """Query the ``sessions`` table with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if ip:
            clauses.append("remote_ip = ?")
            params.append(ip)
        if since:
            clauses.append("started_at >= ?")
            params.append(since.isoformat())
        if until:
            clauses.append("started_at <= ?")
            params.append(until.isoformat())
        sql = "SELECT * FROM sessions"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY started_at DESC"
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, params)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
        results = []
        for row in rows:
            data = dict(zip(cols, row, strict=False))
            sid = data["session_id"]
            counts = self._frame_counts(sid)
            results.append(
                SessionMetadata(
                    session_id=sid,
                    protocol=data["protocol"],
                    remote_ip=data["remote_ip"],
                    remote_port=int(data["remote_port"]),
                    local_ip=data["local_ip"],
                    local_port=int(data["local_port"]),
                    started_at=_parse_iso(data["started_at"]) or datetime.now(timezone.utc),
                    ended_at=_parse_iso(data["ended_at"]),
                    frame_count=counts["frames"],
                    bytes_in=counts["in"],
                    bytes_out=counts["out"],
                    truncated=bool(data["truncated"]),
                    truncation_reason=data["truncation_reason"],
                )
            )
        return results

    def load_frames(self, session_id: str) -> list[SessionFrame]:
        """Return every frame for a session ordered by timestamp."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT session_id, timestamp_ns, direction, source_ip, source_port,
                       dest_ip, dest_port, protocol, is_tls_handshake, payload
                FROM frames
                WHERE session_id = ?
                ORDER BY timestamp_ns ASC, id ASC
                """,
                (session_id,),
            )
            rows = cur.fetchall()
        out: list[SessionFrame] = []
        for row in rows:
            (
                sid,
                ts_ns,
                direction,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
                is_tls,
                payload,
            ) = row
            try:
                direction_enum = Direction(direction)
            except ValueError:
                direction_enum = Direction.INBOUND
            out.append(
                SessionFrame(
                    session_id=sid,
                    timestamp_ns=int(ts_ns),
                    direction=direction_enum,
                    payload=bytes(payload),
                    source_ip=src_ip,
                    source_port=int(src_port),
                    dest_ip=dst_ip,
                    dest_port=int(dst_port),
                    protocol=protocol,
                    is_tls_handshake=bool(is_tls),
                )
            )
        return out

    def get_metadata(self, session_id: str) -> SessionMetadata | None:
        """Return metadata for a single session, or None."""
        results = self.list_sessions()
        for meta in results:
            if meta.session_id == session_id:
                return meta
        return None

    def sweep_retention(self, retention_days: int) -> int:
        """Delete every session row older than ``retention_days``."""
        if retention_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT session_id FROM sessions WHERE started_at < ?", (cutoff,))
            doomed = [r[0] for r in cur.fetchall()]
            removed = 0
            for sid in doomed:
                cur.execute("DELETE FROM frames WHERE session_id = ?", (sid,))
                cur.execute("DELETE FROM metadata WHERE session_id = ?", (sid,))
                cur.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))
                removed += 1
            self._conn.commit()
        return removed

    def journal_mode(self) -> str:
        """Return the current SQLite journal mode (used by tests)."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode")
            row = cur.fetchone()
            return str(row[0]) if row else ""

    def _frame_counts(self, session_id: str) -> dict[str, int]:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT direction, COUNT(*), COALESCE(SUM(LENGTH(payload)), 0)
            FROM frames WHERE session_id = ? GROUP BY direction
            """,
            (session_id,),
        )
        bytes_in = 0
        bytes_out = 0
        frames = 0
        for direction, count, total in cur.fetchall():
            frames += int(count)
            if direction == Direction.INBOUND.value:
                bytes_in += int(total)
            else:
                bytes_out += int(total)
        return {"frames": frames, "in": bytes_in, "out": bytes_out}

    def close(self) -> None:
        """Close the database connection."""
        with self._lock, contextlib.suppress(sqlite3.Error):
            self._conn.close()


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------


@dataclass
class _SessionState:
    """Per-session bookkeeping the recorder maintains in memory."""

    metadata: SessionMetadata
    bytes_recorded: int = 0
    head_frames: list[SessionFrame] = field(default_factory=list)
    tail_frames: deque[SessionFrame] = field(default_factory=lambda: deque(maxlen=KEEP_LAST_FRAMES))
    truncated: bool = False
    head_persisted: bool = False


class _MetricSink:
    """Adapter exposing the small slice of metrics the recorder needs."""

    def __init__(
        self,
        on_recorded: Any | None = None,
        on_truncated: Any | None = None,
        on_bytes: Any | None = None,
        on_duration: Any | None = None,
    ) -> None:
        self.on_recorded = on_recorded
        self.on_truncated = on_truncated
        self.on_bytes = on_bytes
        self.on_duration = on_duration


class SessionRecorder:
    """Captures session frames and persists them via a :class:`SessionStore`."""

    def __init__(
        self,
        store: SessionStore,
        config: ForensicsConfig | None = None,
        *,
        guardian: Any | None = None,
        metrics: _MetricSink | None = None,
        clock: Any = None,
    ) -> None:
        """Wire the recorder.

        Args:
            store: Persistence backend.
            config: Operator configuration.
            guardian: Optional resource guardian; the recorder peeks at
                ``_stats.should_refuse`` (cheap, lock-free) before each
                disk write.
            metrics: Optional metric sink — the recorder fires counters
                when registered.
            clock: Injectable monotonic-ns clock for tests.
        """
        self.store = store
        self.config = config or ForensicsConfig()
        self.guardian = guardian
        self.metrics = metrics or _MetricSink()
        self._clock = clock or time.time_ns
        self._sessions: dict[str, _SessionState] = {}
        self._lock = threading.RLock()
        self._daily_bytes: dict[str, int] = {}
        self._enabled = bool(self.config.enabled)

    # -- public API -----------------------------------------------------
    @property
    def enabled(self) -> bool:
        """True when the recorder is permitted to write."""
        return self._enabled

    def disable(self) -> None:
        """Stop recording new frames; existing files are left untouched."""
        self._enabled = False

    def enable(self) -> None:
        """Re-enable recording after :meth:`disable`."""
        self._enabled = bool(self.config.enabled)

    def open_session(
        self,
        *,
        session_id: str,
        protocol: str,
        remote_ip: str,
        remote_port: int,
        local_ip: str = "",
        local_port: int = 0,
    ) -> SessionMetadata | None:
        """Register a new session and persist the open marker."""
        if not self._can_record():
            return None
        meta = SessionMetadata(
            session_id=session_id,
            protocol=protocol,
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_ip=local_ip,
            local_port=local_port,
        )
        state = _SessionState(metadata=meta)
        with self._lock:
            self._sessions[session_id] = state
        try:
            self.store.open_session(meta)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Recorder open_session failed for %s: %s", session_id, exc)
        return meta

    def record_frame(
        self,
        *,
        session_id: str,
        direction: Direction,
        payload: bytes,
        source_ip: str,
        source_port: int,
        dest_ip: str,
        dest_port: int,
        protocol: str = "",
        is_tls_handshake: bool = False,
        timestamp_ns: int | None = None,
    ) -> SessionFrame | None:
        """Append a single frame to the active session.

        Returns the frame as written, or ``None`` when recording was
        skipped (caps reached, guardian pressure, recorder disabled).
        """
        if not self._can_record():
            return None
        if not is_tls_handshake or self.config.record_tls_handshake:
            pass
        else:
            return None
        state = self._sessions.get(session_id)
        if state is None:
            # The handler may not have called open_session — open lazily.
            self.open_session(
                session_id=session_id,
                protocol=protocol or "unknown",
                remote_ip=source_ip if direction is Direction.INBOUND else dest_ip,
                remote_port=source_port if direction is Direction.INBOUND else dest_port,
                local_ip=dest_ip if direction is Direction.INBOUND else source_ip,
                local_port=dest_port if direction is Direction.INBOUND else source_port,
            )
            state = self._sessions.get(session_id)
            if state is None:
                return None
        ts_ns = int(timestamp_ns) if timestamp_ns is not None else int(self._clock())
        frame = SessionFrame(
            session_id=session_id,
            timestamp_ns=ts_ns,
            direction=direction,
            payload=bytes(payload),
            source_ip=source_ip,
            source_port=source_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            protocol=protocol or state.metadata.protocol,
            is_tls_handshake=is_tls_handshake,
        )

        size = len(frame.payload)
        if not self._daily_budget_allows(size):
            self._mark_truncated(state, "daily_cap")
            return self._sample_frame(state, frame)
        if state.bytes_recorded + size > self.config.max_session_bytes:
            self._mark_truncated(state, "session_cap")
            return self._sample_frame(state, frame)

        state.bytes_recorded += size
        state.metadata.frame_count += 1
        if direction is Direction.INBOUND:
            state.metadata.bytes_in += size
        else:
            state.metadata.bytes_out += size

        self._persist_frame(state, frame)
        self._record_metrics(frame)
        return frame

    def close_session(self, session_id: str) -> SessionMetadata | None:
        """Mark a session closed and flush any retained tail frames."""
        with self._lock:
            state = self._sessions.pop(session_id, None)
        if state is None:
            return None
        if state.truncated and state.tail_frames:
            for frame in list(state.tail_frames):
                try:
                    self.store.append_frame(frame)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Failed to persist tail frame: %s", exc)
        state.metadata.ended_at = datetime.now(timezone.utc)
        try:
            self.store.close_session(state.metadata)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Recorder close_session failed for %s: %s", session_id, exc)
        if self.metrics.on_duration is not None:
            try:
                duration = max(
                    0.0,
                    (state.metadata.ended_at - state.metadata.started_at).total_seconds(),
                )
                self.metrics.on_duration(duration)
            except Exception:  # noqa: BLE001
                pass
        return state.metadata

    def metadata(self, session_id: str) -> SessionMetadata | None:
        """Return the in-memory metadata snapshot for a live session."""
        state = self._sessions.get(session_id)
        return state.metadata if state else None

    def sweep_retention(self) -> int:
        """Apply the retention policy from the configured store."""
        return self.store.sweep_retention(self.config.retention_days)

    # -- internal helpers ----------------------------------------------
    def _can_record(self) -> bool:
        if not self._enabled:
            return False
        if self.guardian is not None:
            stats = getattr(self.guardian, "_stats", None)
            if stats is not None and getattr(stats, "should_refuse", False):
                return False
        return True

    def _daily_budget_allows(self, size: int) -> bool:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        used = self._daily_bytes.get(day, 0)
        return (used + size) <= self.config.max_daily_bytes

    def _persist_frame(self, state: _SessionState, frame: SessionFrame) -> None:
        try:
            self.store.append_frame(frame)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Recorder append_frame failed: %s", exc)
            return
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self._daily_bytes[day] = self._daily_bytes.get(day, 0) + len(frame.payload)
        if len(state.head_frames) < KEEP_FIRST_FRAMES:
            state.head_frames.append(frame)
        state.tail_frames.append(frame)

    def _sample_frame(self, state: _SessionState, frame: SessionFrame) -> SessionFrame | None:
        # Sampling mode — keep tail in memory and only flush on close.
        state.tail_frames.append(frame)
        if not state.head_persisted:
            for head in state.head_frames:
                with contextlib.suppress(Exception):
                    self.store.append_frame(head)
            state.head_persisted = True
        return None

    def _mark_truncated(self, state: _SessionState, reason: str) -> None:
        if not state.truncated:
            state.truncated = True
            state.metadata.truncated = True
            state.metadata.truncation_reason = reason
            if self.metrics.on_truncated is not None:
                with contextlib.suppress(Exception):
                    self.metrics.on_truncated(reason)

    def _record_metrics(self, frame: SessionFrame) -> None:
        if self.metrics.on_recorded is not None:
            with contextlib.suppress(Exception):
                self.metrics.on_recorded(frame.protocol)
        if self.metrics.on_bytes is not None:
            with contextlib.suppress(Exception):
                self.metrics.on_bytes(frame.protocol, frame.direction.value, len(frame.payload))


# ---------------------------------------------------------------------------
# Helpers (re-exported for convenience)
# ---------------------------------------------------------------------------


def iter_store_sessions(
    store: SessionStore,
    *,
    ip: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Iterable[SessionMetadata]:
    """Generator wrapper around :meth:`SessionStore.list_sessions`."""
    yield from store.list_sessions(ip=ip, since=since, until=until)


def load_session_from_jsonl(path: str | Path) -> tuple[SessionMetadata | None, list[SessionFrame]]:
    """Load a single ``*.jsonl.gz`` session file -- handy for ad-hoc tools."""
    p = Path(path)
    return _read_jsonl_metadata(p), _read_jsonl_frames(p)


def serialize_jsonl(metadata: SessionMetadata, frames: Iterable[SessionFrame]) -> bytes:
    """Render a single in-memory session as a gzipped JSONL byte string."""
    buf = io.BytesIO()
    with gzip.open(buf, "wb") as gz:
        gz.write((json.dumps({"kind": "meta", **metadata.to_dict()}) + "\n").encode("utf-8"))
        for frame in frames:
            gz.write((json.dumps({"kind": "frame", **frame.to_dict()}) + "\n").encode("utf-8"))
        gz.write((json.dumps({"kind": "meta_close", **metadata.to_dict()}) + "\n").encode("utf-8"))
    return buf.getvalue()
