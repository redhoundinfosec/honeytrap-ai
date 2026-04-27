"""Node-side uplink to a HoneyTrap controller.

Responsibilities
----------------

1. Register with the controller on start and persist the assigned
   ``node_id``.
2. Run a heartbeat loop posting health snapshots every
   ``heartbeat_interval`` seconds.
3. Run an event-forwarder loop that drains a local in-memory queue,
   batches events up to ``event_batch_size`` or ``event_flush_interval``,
   and POSTs them to the controller.
4. Handle controller outages with bounded backoff plus a SQLite
   spillover spool so events survive a controller restart.

Network I/O is performed through a pluggable transport (default:
:class:`UrllibTransport`) so unit tests can substitute an in-process
fake without opening sockets. The transport returns ``(status, body)``
tuples and never raises -- transport errors become the sentinel status
``-1`` so the rest of the code path is plain branching.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from honeytrap.cluster.config import ClusterConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class Transport(Protocol):
    """Pluggable HTTP transport used by :class:`NodeUplink`."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes,
        timeout: float,
    ) -> tuple[int, bytes]:
        """Execute an HTTP request and return ``(status, body)``."""


class UrllibTransport:
    """Default transport built on :mod:`urllib.request`.

    Connection failures and other ``URLError`` instances map to status
    ``-1`` so callers do not need a separate exception path. ``timeout``
    is honoured exactly. TLS verification follows ``tls_verify``.
    """

    def __init__(self, *, tls_verify: bool = True) -> None:
        """Build a transport that may optionally skip TLS verification."""
        self._tls_verify = bool(tls_verify)

    def _ssl_context(self) -> ssl.SSLContext | None:
        if self._tls_verify:
            return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes,
        timeout: float,
    ) -> tuple[int, bytes]:
        """Execute the HTTP call. Errors collapse to status ``-1``."""
        req = urllib.request.Request(url, data=body, method=method.upper())
        for k, v in headers.items():
            req.add_header(k, v)
        ctx = self._ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = resp.read()
                return int(resp.status), data
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read() if hasattr(exc, "read") else b""
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            logger.debug("Uplink HTTP error %s: %s", method, exc)
            return -1, b""


# ---------------------------------------------------------------------------
# Spool
# ---------------------------------------------------------------------------


class _Spool:
    """SQLite-backed overflow spool for events.

    Used only when the in-memory deque is full. The spool stores raw
    JSON event blobs and replays them in FIFO order. The implementation
    is synchronous; callers run it inside an asyncio executor.
    """

    def __init__(self, path: Path | str, *, max_disk_bytes: int) -> None:
        """Open or create the spool at ``path``."""
        self._path = Path(path)
        self._max_disk_bytes = int(max_disk_bytes)
        self._lock = threading.RLock()
        if str(self._path) != ":memory:":
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS spool (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL
            )
            """
        )

    def push(self, event: dict[str, Any]) -> bool:
        """Persist an event. Returns False if the disk cap is exceeded."""
        if self.size_bytes() >= self._max_disk_bytes:
            return False
        with self._lock:
            self._conn.execute(
                "INSERT INTO spool(payload) VALUES (?)",
                (json.dumps(event),),
            )
        return True

    def pop_batch(self, n: int) -> list[tuple[int, dict[str, Any]]]:
        """Return up to ``n`` oldest events along with their row ids."""
        if n <= 0:
            return []
        with self._lock:
            cursor = self._conn.execute(
                "SELECT id, payload FROM spool ORDER BY id ASC LIMIT ?",
                (int(n),),
            )
            rows = cursor.fetchall()
        out: list[tuple[int, dict[str, Any]]] = []
        for row_id, payload in rows:
            try:
                event = json.loads(payload)
            except (TypeError, ValueError):
                continue
            if isinstance(event, dict):
                out.append((int(row_id), event))
        return out

    def discard(self, ids: list[int]) -> None:
        """Permanently remove rows after a successful upload."""
        if not ids:
            return
        with self._lock:
            placeholders = ",".join("?" for _ in ids)
            self._conn.execute(
                f"DELETE FROM spool WHERE id IN ({placeholders})",
                tuple(ids),
            )

    def depth(self) -> int:
        """Return the current row count."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM spool").fetchone()
            return int(row[0]) if row else 0

    def size_bytes(self) -> int:
        """Return the on-disk size of the spool DB, or 0 for in-memory."""
        try:
            return self._path.stat().st_size if self._path.exists() else 0
        except OSError:
            return 0

    def close(self) -> None:
        """Close the underlying database connection."""
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass


# ---------------------------------------------------------------------------
# Status snapshot
# ---------------------------------------------------------------------------


@dataclass
class UplinkStatus:
    """Snapshot of the uplink for ``honeytrap node uplink-status``."""

    node_id: str | None = None
    last_heartbeat_at: float | None = None
    last_event_post_at: float | None = None
    last_error: str | None = None
    queue_depth: int = 0
    spool_depth: int = 0
    spool_bytes: int = 0
    events_forwarded: int = 0
    events_dropped: int = 0
    consecutive_failures: int = 0
    online: bool = False
    backoff_seconds: float = 0.0
    extras: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for human / API output."""
        return {
            "node_id": self.node_id,
            "last_heartbeat_at": self.last_heartbeat_at,
            "last_event_post_at": self.last_event_post_at,
            "last_error": self.last_error,
            "queue_depth": self.queue_depth,
            "spool_depth": self.spool_depth,
            "spool_bytes": self.spool_bytes,
            "events_forwarded": self.events_forwarded,
            "events_dropped": self.events_dropped,
            "consecutive_failures": self.consecutive_failures,
            "online": self.online,
            "backoff_seconds": self.backoff_seconds,
            "extras": dict(self.extras),
        }


# ---------------------------------------------------------------------------
# Uplink
# ---------------------------------------------------------------------------


class NodeUplink:
    """Async client that mirrors a node's events to a controller.

    Wiring:

    * :meth:`enqueue_event` is called by the local pipeline. It NEVER
      blocks: when the in-memory deque is full, the event spills to the
      SQLite spool. When the spool is at the disk cap, the event is
      dropped and counted in :attr:`UplinkStatus.events_dropped`.
    * :meth:`heartbeat_snapshot` is called by the heartbeat loop and is
      expected to be cheap (uptime + queue depth + version).
    * :meth:`start` registers, then schedules the two background tasks
      and returns. :meth:`stop` cancels them and waits for clean exit.
    """

    def __init__(
        self,
        config: ClusterConfig,
        *,
        version: str,
        spool_path: Path | str | None = None,
        transport: Transport | None = None,
        snapshot_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        """Create an uplink. Call :meth:`start` to begin background tasks.

        Args:
            config: Validated :class:`ClusterConfig`.
            version: Honeypot version string. Reported on register.
            spool_path: Override for the spool database path.
            transport: Optional transport injection. Defaults to
                :class:`UrllibTransport` honouring ``tls_verify``.
            snapshot_provider: Optional callable returning a small dict
                merged into every heartbeat. The provider must NOT
                include secrets or PII.
        """
        if not config.enabled:
            raise ValueError("NodeUplink requires cluster.enabled = True")
        if not config.controller_url:
            raise ValueError("NodeUplink requires controller_url")
        if not config.api_key:
            raise ValueError("NodeUplink requires api_key")
        self._config = config
        self._version = version
        self._transport: Transport = transport or UrllibTransport(tls_verify=config.tls_verify)
        self._snapshot_provider = snapshot_provider or (lambda: {})
        self._queue: deque[dict[str, Any]] = deque(maxlen=config.spool_max_events)
        self._spool = _Spool(
            spool_path or ":memory:",
            max_disk_bytes=config.spool_max_disk_bytes,
        )
        self._status = UplinkStatus(node_id=config.node_id)
        self._lock = threading.RLock()
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task[Any]] = []
        self._started_at: float | None = None
        self._registered = False

    # -- public API ----------------------------------------------------
    @property
    def status(self) -> UplinkStatus:
        """Return a copy of the current status snapshot."""
        with self._lock:
            return UplinkStatus(
                node_id=self._status.node_id,
                last_heartbeat_at=self._status.last_heartbeat_at,
                last_event_post_at=self._status.last_event_post_at,
                last_error=self._status.last_error,
                queue_depth=len(self._queue),
                spool_depth=self._spool.depth(),
                spool_bytes=self._spool.size_bytes(),
                events_forwarded=self._status.events_forwarded,
                events_dropped=self._status.events_dropped,
                consecutive_failures=self._status.consecutive_failures,
                online=self._status.online,
                backoff_seconds=self._status.backoff_seconds,
                extras=dict(self._status.extras),
            )

    def enqueue_event(self, event: dict[str, Any]) -> bool:
        """Submit an event for forwarding.

        Returns True on enqueue, False on drop. Always non-blocking.
        """
        if not isinstance(event, dict):
            return False
        with self._lock:
            if len(self._queue) < self._queue.maxlen if self._queue.maxlen else True:
                self._queue.append(event)
                return True
        # In-memory queue is full; spill to disk.
        if self._spool.push(event):
            return True
        with self._lock:
            self._status.events_dropped += 1
        return False

    async def start(self) -> None:
        """Register and launch the heartbeat + forwarder tasks."""
        self._started_at = time.time()
        await self._register_with_retry()
        loop = asyncio.get_event_loop()
        self._tasks = [
            loop.create_task(self._heartbeat_loop(), name="ht-uplink-heartbeat"),
            loop.create_task(self._forwarder_loop(), name="ht-uplink-forwarder"),
        ]

    async def stop(self) -> None:
        """Signal tasks to wind down and await their completion."""
        self._stop.set()
        tasks = list(self._tasks)
        self._tasks.clear()
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._spool.close()

    def heartbeat_snapshot(self) -> dict[str, Any]:
        """Build a heartbeat payload. Always free of secrets and PII."""
        snap: dict[str, Any] = {
            "version": self._version,
            "uptime_seconds": int(time.time() - (self._started_at or time.time())),
            "queue_depth": len(self._queue),
            "spool_depth": self._spool.depth(),
            "events_forwarded": self._status.events_forwarded,
            "events_dropped": self._status.events_dropped,
            "consecutive_failures": self._status.consecutive_failures,
        }
        try:
            extras = self._snapshot_provider() or {}
        except Exception as exc:  # noqa: BLE001
            logger.debug("snapshot provider failed: %s", exc)
            extras = {}
        if isinstance(extras, dict):
            for k, v in extras.items():
                if isinstance(k, str) and k not in snap:
                    snap[k] = v
        return snap

    # -- internals -----------------------------------------------------
    async def _register_with_retry(self) -> None:
        attempt = 0
        backoff = 1.0
        while not self._stop.is_set():
            attempt += 1
            ok = await self._register_once()
            if ok:
                self._registered = True
                with self._lock:
                    self._status.online = True
                    self._status.consecutive_failures = 0
                return
            with self._lock:
                self._status.consecutive_failures = attempt
                self._status.online = False
            sleep_for = min(60.0, backoff + random.uniform(0, backoff / 2))
            with self._lock:
                self._status.backoff_seconds = sleep_for
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=sleep_for)
                return
            except asyncio.TimeoutError:
                pass
            backoff = min(60.0, backoff * 2)

    async def _register_once(self) -> bool:
        body = json.dumps(
            {
                "name": self._config.node_id or "node",
                "role": self._config.role.value,
                "version": self._version,
                "tags": list(self._config.tags),
                "node_id": self._config.node_id,
            }
        ).encode("utf-8")
        url = self._endpoint("/api/v1/cluster/nodes")
        status, response = await self._http("POST", url, body)
        if status not in (200, 201):
            with self._lock:
                self._status.last_error = f"register: status {status}"
            return False
        try:
            payload = json.loads(response.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False
        node_id = str(payload.get("node_id") or "").strip()
        if not node_id:
            return False
        with self._lock:
            self._status.node_id = node_id
            self._config.node_id = node_id
            self._status.last_error = None
        return True

    async def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._send_heartbeat()
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._status.last_error = f"heartbeat: {exc}"
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._config.heartbeat_interval)
                return
            except asyncio.TimeoutError:
                continue

    async def _send_heartbeat(self) -> None:
        if not self._registered:
            return
        nid = self._status.node_id
        if not nid:
            return
        body = json.dumps(self.heartbeat_snapshot()).encode("utf-8")
        url = self._endpoint(f"/api/v1/cluster/nodes/{nid}/heartbeat")
        status, _ = await self._http("PUT", url, body)
        if status in (200, 204):
            with self._lock:
                self._status.last_heartbeat_at = time.time()
                self._status.online = True
                self._status.consecutive_failures = 0
                self._status.last_error = None
                self._status.backoff_seconds = 0.0
        else:
            with self._lock:
                self._status.online = False
                self._status.consecutive_failures += 1
                self._status.last_error = f"heartbeat status {status}"

    async def _forwarder_loop(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            batch = self._drain_batch()
            if not batch.events:
                try:
                    await asyncio.wait_for(
                        self._stop.wait(), timeout=self._config.event_flush_interval
                    )
                    return
                except asyncio.TimeoutError:
                    continue
            ok = await self._post_events(batch.events)
            if ok:
                self._spool.discard(batch.spool_ids)
                with self._lock:
                    self._status.events_forwarded += len(batch.events)
                    self._status.online = True
                    self._status.consecutive_failures = 0
                    self._status.last_event_post_at = time.time()
                    self._status.last_error = None
                    self._status.backoff_seconds = 0.0
                backoff = 1.0
                continue
            # On failure: re-queue events into the spool (they were
            # already removed from the in-memory deque) so they survive
            # process restarts.
            for ev in batch.from_memory:
                if not self._spool.push(ev):
                    with self._lock:
                        self._status.events_dropped += 1
            with self._lock:
                self._status.online = False
                self._status.consecutive_failures += 1
            jitter = random.uniform(0, backoff / 2)
            with self._lock:
                self._status.backoff_seconds = backoff + jitter
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=backoff + jitter)
                return
            except asyncio.TimeoutError:
                pass
            backoff = min(60.0, backoff * 2)

    @dataclass
    class _Batch:
        events: list[dict[str, Any]]
        from_memory: list[dict[str, Any]]
        spool_ids: list[int]

    def _drain_batch(self) -> _Batch:
        cap = self._config.event_batch_size
        events: list[dict[str, Any]] = []
        from_memory: list[dict[str, Any]] = []
        with self._lock:
            while self._queue and len(events) < cap:
                ev = self._queue.popleft()
                events.append(ev)
                from_memory.append(ev)
        spool_ids: list[int] = []
        if len(events) < cap:
            for row_id, ev in self._spool.pop_batch(cap - len(events)):
                events.append(ev)
                spool_ids.append(row_id)
        return NodeUplink._Batch(events=events, from_memory=from_memory, spool_ids=spool_ids)

    async def _post_events(self, events: list[dict[str, Any]]) -> bool:
        if not events:
            return True
        body = json.dumps({"node_id": self._status.node_id, "events": events}).encode("utf-8")
        url = self._endpoint("/api/v1/cluster/events")
        status, _ = await self._http("POST", url, body)
        if status in (200, 202, 204):
            return True
        with self._lock:
            self._status.last_error = f"events status {status}"
        return False

    async def _http(self, method: str, url: str, body: bytes) -> tuple[int, bytes]:
        loop = asyncio.get_running_loop()
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-API-Key": self._config.api_key or "",
            "User-Agent": f"honeytrap-uplink/{self._version}",
        }

        def call() -> tuple[int, bytes]:
            return self._transport.request(method, url, headers=headers, body=body, timeout=10.0)

        return await loop.run_in_executor(None, call)

    def _endpoint(self, path: str) -> str:
        base = (self._config.controller_url or "").rstrip("/")
        return f"{base}{path}"
