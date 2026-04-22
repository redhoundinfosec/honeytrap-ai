"""Per-session and per-attacker memory store for the adaptive AI layer.

Memory is the backbone of Cycle 11. Every protocol handler can ask the store
for a :class:`SessionMemory` keyed by ``(session_id, source_ip)``. The store
accumulates context across turns so the intent classifier, response cache,
and backend chain can build progressively more convincing interactions.

Two backends are provided:

* :class:`InMemoryStore` — bounded LRU keyed by source IP. Ephemeral; dies
  with the process. Used by tests and operators who do not want any
  attacker data written to disk.
* :class:`SqliteMemoryStore` — single-file SQLite DB under the honeytrap
  state directory. Survives restarts so multi-session campaign stitching
  remains useful after a crash/restart.

Both backends expose the identical :class:`MemoryStore` ABC so the
adapter code does not care which one is wired up.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from honeytrap.ai.intent import IntentLabel


@dataclass
class AuthAttempt:
    """One recorded authentication attempt."""

    username: str
    password: str
    success: bool
    timestamp: float


@dataclass
class SessionMemory:
    """All accumulated context for a single session.

    The structure is intentionally open: new fields can be appended in
    future cycles without breaking persisted SQLite rows because the
    backing storage is JSON.
    """

    session_id: str
    source_ip: str
    first_seen_ts: float = field(default_factory=time.time)
    last_seen_ts: float = field(default_factory=time.time)
    protocol_history: list[str] = field(default_factory=list)
    command_history: list[str] = field(default_factory=list)
    auth_attempts: list[AuthAttempt] = field(default_factory=list)
    downloaded_files: list[str] = field(default_factory=list)
    uploaded_files: list[str] = field(default_factory=list)
    user_agents: set[str] = field(default_factory=set)
    sni_domains: set[str] = field(default_factory=set)
    tls_fingerprints: set[str] = field(default_factory=set)
    attck_techniques: set[str] = field(default_factory=set)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    intent: IntentLabel | None = None
    confidence: float = 0.0
    rationale: list[str] = field(default_factory=list)
    turn_count: int = 0
    persona_snapshot: dict[str, Any] = field(default_factory=dict)
    free_form_notes: list[str] = field(default_factory=list)
    backend_usage: dict[str, int] = field(default_factory=dict)
    last_backend_latency_ms: float = 0.0

    def record_command(self, command: str, protocol: str | None = None) -> None:
        """Append a command and bump the turn counter."""
        self.command_history.append(command)
        if protocol and protocol not in self.protocol_history:
            self.protocol_history.append(protocol)
        self.turn_count += 1
        self.last_seen_ts = time.time()

    def record_auth(self, username: str, password: str, success: bool) -> None:
        """Append an authentication attempt."""
        self.auth_attempts.append(
            AuthAttempt(
                username=username,
                password=password,
                success=success,
                timestamp=time.time(),
            )
        )
        self.last_seen_ts = time.time()

    def record_backend(self, backend_name: str, latency_ms: float) -> None:
        """Track which backend answered and how long it took."""
        self.backend_usage[backend_name] = self.backend_usage.get(backend_name, 0) + 1
        self.last_backend_latency_ms = float(latency_ms)
        self.last_seen_ts = time.time()

    def add_ioc(self, ioc_type: str, value: str) -> None:
        """Record an IOC observation, de-duplicated."""
        bucket = self.iocs.setdefault(ioc_type, [])
        if value not in bucket:
            bucket.append(value)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict snapshot.

        ``set`` fields are emitted as sorted lists for deterministic
        hashing and for SQLite column storage.
        """
        data = asdict(self)
        for key in ("user_agents", "sni_domains", "tls_fingerprints", "attck_techniques"):
            data[key] = sorted(getattr(self, key))
        data["auth_attempts"] = [asdict(a) for a in self.auth_attempts]
        data["intent"] = self.intent.value if self.intent else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionMemory:
        """Rebuild a :class:`SessionMemory` from :meth:`to_dict` output."""
        intent_value = data.get("intent")
        intent = IntentLabel(intent_value) if intent_value else None
        auth_raw = data.get("auth_attempts") or []
        auth = [AuthAttempt(**row) for row in auth_raw]
        return cls(
            session_id=str(data["session_id"]),
            source_ip=str(data["source_ip"]),
            first_seen_ts=float(data.get("first_seen_ts", time.time())),
            last_seen_ts=float(data.get("last_seen_ts", time.time())),
            protocol_history=list(data.get("protocol_history", [])),
            command_history=list(data.get("command_history", [])),
            auth_attempts=auth,
            downloaded_files=list(data.get("downloaded_files", [])),
            uploaded_files=list(data.get("uploaded_files", [])),
            user_agents=set(data.get("user_agents", [])),
            sni_domains=set(data.get("sni_domains", [])),
            tls_fingerprints=set(data.get("tls_fingerprints", [])),
            attck_techniques=set(data.get("attck_techniques", [])),
            iocs=dict(data.get("iocs", {})),
            intent=intent,
            confidence=float(data.get("confidence", 0.0)),
            rationale=list(data.get("rationale", [])),
            turn_count=int(data.get("turn_count", 0)),
            persona_snapshot=dict(data.get("persona_snapshot", {})),
            free_form_notes=list(data.get("free_form_notes", [])),
            backend_usage=dict(data.get("backend_usage", {})),
            last_backend_latency_ms=float(data.get("last_backend_latency_ms", 0.0)),
        )


class MemoryStore(ABC):
    """Abstract interface shared by the in-memory and sqlite backends."""

    @abstractmethod
    def get_or_create(self, session_id: str, source_ip: str) -> SessionMemory:
        """Return the memory for ``session_id`` or create an empty one."""

    @abstractmethod
    def update(self, memory: SessionMemory) -> None:
        """Persist the mutated memory back to the store."""

    @abstractmethod
    def find_by_ip(self, ip: str) -> list[SessionMemory]:
        """Return every session previously observed from ``ip``."""

    @abstractmethod
    def all_sessions(self) -> list[SessionMemory]:
        """Return every session known to the store (mostly for metrics/API)."""

    @abstractmethod
    def session_count(self) -> int:
        """Return the total number of tracked sessions."""

    @abstractmethod
    def evictions(self) -> int:
        """Return the cumulative number of evicted sessions (LRU only)."""


class InMemoryStore(MemoryStore):
    """Bounded LRU store, ephemeral.

    Two caps are enforced to keep worst-case memory bounded:

    * ``cap_ips`` — maximum number of distinct source IPs tracked at once.
      Oldest IP is evicted when the cap is exceeded.
    * ``cap_sessions_per_ip`` — per-IP cap on the number of sessions kept.
      Oldest session for that IP is evicted first.
    """

    def __init__(
        self,
        *,
        cap_ips: int = 10_000,
        cap_sessions_per_ip: int = 50,
    ) -> None:
        """Create an empty LRU store with the given caps."""
        self.cap_ips = int(cap_ips)
        self.cap_sessions_per_ip = int(cap_sessions_per_ip)
        self._lock = threading.Lock()
        self._by_ip: OrderedDict[str, OrderedDict[str, SessionMemory]] = OrderedDict()
        self._evictions = 0

    def get_or_create(self, session_id: str, source_ip: str) -> SessionMemory:
        """Return or create the memory, promoting the IP to MRU position."""
        with self._lock:
            sessions = self._by_ip.get(source_ip)
            if sessions is None:
                sessions = OrderedDict()
                self._by_ip[source_ip] = sessions
                self._evict_ips_locked()
            self._by_ip.move_to_end(source_ip)
            mem = sessions.get(session_id)
            if mem is None:
                mem = SessionMemory(session_id=session_id, source_ip=source_ip)
                sessions[session_id] = mem
                self._evict_sessions_locked(sessions)
            sessions.move_to_end(session_id)
            return mem

    def update(self, memory: SessionMemory) -> None:
        """No-op for the in-memory store — objects mutate in place."""
        with self._lock:
            sessions = self._by_ip.get(memory.source_ip)
            if sessions is None:
                sessions = OrderedDict()
                self._by_ip[memory.source_ip] = sessions
            sessions[memory.session_id] = memory
            sessions.move_to_end(memory.session_id)
            self._by_ip.move_to_end(memory.source_ip)

    def find_by_ip(self, ip: str) -> list[SessionMemory]:
        """Return every session seen for ``ip``, newest last."""
        with self._lock:
            sessions = self._by_ip.get(ip)
            if sessions is None:
                return []
            return list(sessions.values())

    def all_sessions(self) -> list[SessionMemory]:
        """Return every session across every IP."""
        with self._lock:
            out: list[SessionMemory] = []
            for sessions in self._by_ip.values():
                out.extend(sessions.values())
            return out

    def session_count(self) -> int:
        """Return the total session count across all IPs."""
        with self._lock:
            return sum(len(s) for s in self._by_ip.values())

    def evictions(self) -> int:
        """Return the cumulative eviction count."""
        return self._evictions

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _evict_ips_locked(self) -> None:
        while len(self._by_ip) > self.cap_ips:
            _, evicted = self._by_ip.popitem(last=False)
            self._evictions += len(evicted)

    def _evict_sessions_locked(self, sessions: OrderedDict[str, SessionMemory]) -> None:
        while len(sessions) > self.cap_sessions_per_ip:
            sessions.popitem(last=False)
            self._evictions += 1


class SqliteMemoryStore(MemoryStore):
    """SQLite-backed store for persistence across restarts.

    Single-file WAL-mode database. Uses JSON columns for the bulk of the
    memory payload so schema stays simple and field additions in future
    cycles do not require migrations.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        source_ip TEXT NOT NULL,
        first_seen_ts REAL NOT NULL,
        last_seen_ts REAL NOT NULL,
        payload TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(source_ip);
    """

    def __init__(self, path: str | Path) -> None:
        """Open (or create) the SQLite file and enable WAL mode."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(self._SCHEMA)
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass

    def close(self) -> None:
        """Close the underlying connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def get_or_create(self, session_id: str, source_ip: str) -> SessionMemory:
        """Return the existing row or create + persist an empty one."""
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row is not None:
                return SessionMemory.from_dict(json.loads(row["payload"]))
            mem = SessionMemory(session_id=session_id, source_ip=source_ip)
            payload = json.dumps(mem.to_dict())
            self._conn.execute(
                "INSERT INTO sessions(session_id, source_ip, first_seen_ts, last_seen_ts, payload)"
                " VALUES(?, ?, ?, ?, ?)",
                (
                    session_id,
                    source_ip,
                    mem.first_seen_ts,
                    mem.last_seen_ts,
                    payload,
                ),
            )
            self._conn.commit()
            return mem

    def update(self, memory: SessionMemory) -> None:
        """Persist the supplied memory back to disk."""
        payload = json.dumps(memory.to_dict())
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions(session_id, source_ip, first_seen_ts, last_seen_ts, payload)"
                " VALUES(?, ?, ?, ?, ?)"
                " ON CONFLICT(session_id) DO UPDATE SET"
                "   source_ip=excluded.source_ip,"
                "   last_seen_ts=excluded.last_seen_ts,"
                "   payload=excluded.payload",
                (
                    memory.session_id,
                    memory.source_ip,
                    memory.first_seen_ts,
                    memory.last_seen_ts,
                    payload,
                ),
            )
            self._conn.commit()

    def find_by_ip(self, ip: str) -> list[SessionMemory]:
        """Return every session previously observed for ``ip``."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM sessions WHERE source_ip = ? ORDER BY last_seen_ts",
                (ip,),
            ).fetchall()
        return [SessionMemory.from_dict(json.loads(row["payload"])) for row in rows]

    def all_sessions(self) -> list[SessionMemory]:
        """Return every persisted session."""
        with self._lock:
            rows = self._conn.execute("SELECT payload FROM sessions").fetchall()
        return [SessionMemory.from_dict(json.loads(row["payload"])) for row in rows]

    def session_count(self) -> int:
        """Return the total row count."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()
        return int(row["n"]) if row else 0

    def evictions(self) -> int:
        """SQLite store never evicts — always 0."""
        return 0


def build_store(kind: str, *, state_dir: Path | str, **opts: Any) -> MemoryStore:
    """Factory for the configured memory backend.

    ``kind`` is one of ``"memory"`` or ``"sqlite"``. Unknown values fall
    back to the in-memory store with a stderr warning, which matches the
    rest of the codebase's forgiving config-parsing stance.
    """
    kind_lc = (kind or "memory").strip().lower()
    if kind_lc == "sqlite":
        path = Path(state_dir) / "ai_memory.sqlite3"
        return SqliteMemoryStore(path)
    return InMemoryStore(
        cap_ips=int(opts.get("cap_ips", 10_000)),
        cap_sessions_per_ip=int(opts.get("cap_sessions_per_ip", 50)),
    )
