"""Append-only gzipped JSONL audit log.

Every non-public request produces one line here. Rotation is size based:
at 100 MiB the active file is closed, renamed with an index suffix, and
a fresh file is opened. Up to 10 rotations are kept before the oldest
is deleted, giving ~1 GiB of on-disk history by default.

The log intentionally records only metadata (method, path, status,
remote address, user agent, body sha-256). Request bodies and headers
are NEVER written, so a leaked audit log cannot disclose secrets.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AuditRecord:
    """A single audit-log line."""

    timestamp: str
    method: str
    path: str
    status: int
    api_key_id: str | None = None
    role: str | None = None
    remote_addr: str = ""
    user_agent: str = ""
    body_sha256: str = ""
    request_id: str = ""
    duration_ms: float = 0.0
    auth_reason: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json_line(self) -> bytes:
        """Return the JSON-encoded line (no trailing newline)."""
        payload = asdict(self)
        if not payload["extra"]:
            payload.pop("extra")
        return json.dumps(payload, sort_keys=True).encode("utf-8")


class AuditLog:
    """Thread-safe append-only audit log with size-based rotation."""

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = 100 * 1024 * 1024,
        max_rotations: int = 10,
    ) -> None:
        """Create the log at ``path``, rotating at ``max_bytes``."""
        self._path = Path(path)
        self._max_bytes = int(max_bytes)
        self._max_rotations = int(max_rotations)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        """Return the active audit-log path."""
        return self._path

    def record(self, rec: AuditRecord) -> None:
        """Append one record, rotating the file first if the cap is hit."""
        line = rec.to_json_line() + b"\n"
        with self._lock:
            self._rotate_if_needed(len(line))
            try:
                with gzip.open(self._path, "ab") as fh:
                    fh.write(line)
            except OSError as exc:  # pragma: no cover -- disk full etc.
                logger.warning("Audit log append failed: %s", exc)

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        try:
            size = self._path.stat().st_size if self._path.exists() else 0
        except OSError:
            size = 0
        if size + incoming_bytes < self._max_bytes:
            return
        for idx in range(self._max_rotations, 0, -1):
            src = self._rotation_path(idx - 1) if idx > 1 else self._path
            dst = self._rotation_path(idx)
            if idx == self._max_rotations and dst.exists():
                with contextlib.suppress(OSError):
                    dst.unlink()
            if src.exists():
                try:
                    src.rename(dst)
                except OSError as exc:  # pragma: no cover -- rare IO fault
                    logger.debug("Audit rotation rename failed: %s", exc)

    def _rotation_path(self, index: int) -> Path:
        return self._path.with_name(f"{self._path.name}.{index}")

    def read_all(self) -> list[dict[str, Any]]:
        """Decode and return every record in the active log.

        Intended for tests and small-scale inspection; streaming consumers
        should read the file directly to avoid loading everything into
        memory at once.
        """
        with self._lock:
            if not self._path.exists():
                return []
            out: list[dict[str, Any]] = []
            try:
                with gzip.open(self._path, "rb") as fh:
                    for raw in fh:
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            out.append(json.loads(raw.decode("utf-8")))
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            continue
            except OSError as exc:  # pragma: no cover
                logger.debug("Audit log read failed: %s", exc)
                return []
            return out


def now_iso() -> str:
    """UTC timestamp to the millisecond -- shared with :class:`AuditRecord`."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
