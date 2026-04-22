"""API-key authentication model and persistence.

Keys are generated as ``htk_<40 urlsafe chars>`` tokens so operators can
grep logs for leaked secrets. Only the SHA-256 digest is ever persisted;
plaintext is shown to the user exactly once at creation time. Lookups
compare digests with :func:`hmac.compare_digest` so timing side channels
are neutralised.

Persistence is a small JSON file under the honeytrap state directory.
It is loaded lazily and written atomically (``tmp`` + rename) so a crash
during a write can never corrupt the keyring.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from honeytrap.api.rbac import Role

logger = logging.getLogger(__name__)

API_KEY_PREFIX = "htk_"
API_KEY_BODY_LEN = 40
PREFIX_VISIBLE_LEN = 8


@dataclass
class APIKey:
    """A single API key record.

    Only :attr:`hashed` (the SHA-256 hex digest of the full token) is
    persisted. :attr:`prefix` is kept so operators can identify a key
    without learning the secret. ``secret`` is populated only when the
    key is first created -- it MUST be cleared before persisting.
    """

    id: str
    name: str
    role: Role
    prefix: str
    hashed: str
    created_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None
    secret: str | None = field(default=None, repr=False, compare=False)

    @property
    def is_revoked(self) -> bool:
        """True when :attr:`revoked_at` is set."""
        return self.revoked_at is not None

    def to_public_dict(self) -> dict[str, Any]:
        """Public JSON projection: never includes :attr:`hashed` or secret."""
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role.value,
            "prefix": self.prefix,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "revoked_at": self.revoked_at,
        }

    def to_storage_dict(self) -> dict[str, Any]:
        """On-disk projection: includes :attr:`hashed`, never the secret."""
        payload = asdict(self)
        payload["role"] = self.role.value
        payload.pop("secret", None)
        return payload

    @classmethod
    def from_storage_dict(cls, data: dict[str, Any]) -> APIKey:
        """Load a key record from its on-disk JSON dict."""
        return cls(
            id=str(data["id"]),
            name=str(data.get("name", "")),
            role=Role.from_str(str(data.get("role", "viewer"))),
            prefix=str(data.get("prefix", "")),
            hashed=str(data["hashed"]),
            created_at=str(data.get("created_at", _now_iso())),
            last_used_at=data.get("last_used_at"),
            revoked_at=data.get("revoked_at"),
        )


def _now_iso() -> str:
    """UTC timestamp in ISO-8601 form, to the second."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def generate_api_key() -> str:
    """Return a freshly generated plaintext API token.

    The token is of the form ``htk_`` plus a 40-character URL-safe random
    body. The prefix lets operators build key-leak detectors that grep
    for ``htk_`` in source control, logs, and pastebins.
    """
    body = secrets.token_urlsafe(API_KEY_BODY_LEN)[:API_KEY_BODY_LEN]
    return f"{API_KEY_PREFIX}{body}"


def hash_key(token: str) -> str:
    """Return the SHA-256 hex digest of a plaintext API token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def visible_prefix(token: str) -> str:
    """Return the operator-visible prefix of a token (``htk_`` + 8 chars)."""
    body = token[len(API_KEY_PREFIX) :] if token.startswith(API_KEY_PREFIX) else token
    return f"{API_KEY_PREFIX}{body[:PREFIX_VISIBLE_LEN]}"


class APIKeyStore:
    """Thread-safe JSON-backed store of :class:`APIKey` records.

    The store keeps an in-memory list and flushes atomically on every
    mutation. Reads are lock-free after the initial load. Lookups compare
    hashed digests using :func:`hmac.compare_digest`.
    """

    def __init__(self, path: Path) -> None:
        """Open or create the keyring at ``path``."""
        self._path = Path(path)
        self._lock = threading.RLock()
        self._keys: dict[str, APIKey] = {}
        self._load()

    @property
    def path(self) -> Path:
        """Return the file path backing this store."""
        return self._path

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8") or "[]")
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load api_keys file %s: %s", self._path, exc)
            return
        if not isinstance(raw, list):
            return
        with self._lock:
            for item in raw:
                if not isinstance(item, dict):
                    continue
                try:
                    key = APIKey.from_storage_dict(item)
                except (KeyError, ValueError) as exc:
                    logger.warning("Skipping malformed api key entry: %s", exc)
                    continue
                self._keys[key.id] = key

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        payload = [k.to_storage_dict() for k in self._keys.values()]
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._path)

    def list(self) -> list[APIKey]:
        """Return a snapshot of all keys ordered by creation time."""
        with self._lock:
            return sorted(self._keys.values(), key=lambda k: k.created_at)

    def get(self, key_id: str) -> APIKey | None:
        """Return the key by id, or None if not present."""
        with self._lock:
            return self._keys.get(key_id)

    def create(self, *, name: str, role: Role) -> tuple[APIKey, str]:
        """Create a new key, flush to disk, and return ``(record, plaintext)``.

        ``record`` has no secret populated; ``plaintext`` is the full
        token that should be shown to the caller exactly once.
        """
        plaintext = generate_api_key()
        record = APIKey(
            id=str(uuid.uuid4()),
            name=name,
            role=role,
            prefix=visible_prefix(plaintext),
            hashed=hash_key(plaintext),
            created_at=_now_iso(),
        )
        with self._lock:
            self._keys[record.id] = record
            self._flush()
        return record, plaintext

    def revoke(self, key_id: str) -> bool:
        """Mark a key revoked and flush. Returns True when the key existed."""
        with self._lock:
            key = self._keys.get(key_id)
            if key is None or key.revoked_at is not None:
                return key is not None
            key.revoked_at = _now_iso()
            self._flush()
            return True

    def touch(self, key_id: str) -> None:
        """Update ``last_used_at`` and persist. Errors are swallowed."""
        with self._lock:
            key = self._keys.get(key_id)
            if key is None:
                return
            key.last_used_at = _now_iso()
            try:
                self._flush()
            except OSError as exc:  # pragma: no cover -- best-effort only
                logger.debug("Failed to persist last_used_at for %s: %s", key_id, exc)

    def lookup_by_token(self, token: str) -> APIKey | None:
        """Return the key matching ``token`` by SHA-256 digest, else None.

        Revoked keys are treated as not matching. Comparison is constant
        time over the hex digest space.
        """
        candidate = hash_key(token)
        with self._lock:
            for key in self._keys.values():
                if key.revoked_at is not None:
                    continue
                if hmac.compare_digest(candidate, key.hashed):
                    return key
        return None

    def count_active(self) -> int:
        """Return the number of non-revoked keys, useful for gauges."""
        with self._lock:
            return sum(1 for k in self._keys.values() if k.revoked_at is None)


# ---------------------------------------------------------------------------
# HMAC request signing
# ---------------------------------------------------------------------------


def build_hmac_string(method: str, path: str, timestamp: str, body: bytes) -> str:
    """Canonicalise a request for HMAC signing.

    The canonical form is ``METHOD|/path|timestamp|sha256(body)``. The
    method is uppercased and the path is taken verbatim; the client must
    send the exact path it used on the wire. The body hash is the hex
    SHA-256 of the raw request body (empty string when body is empty).
    """
    body_hash = hashlib.sha256(body or b"").hexdigest()
    return f"{method.upper()}|{path}|{timestamp}|{body_hash}"


def compute_hmac(secret: str, method: str, path: str, timestamp: str, body: bytes) -> str:
    """Return the hex HMAC-SHA-256 for a canonicalised request."""
    canonical = build_hmac_string(method, path, timestamp, body).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


class ReplayCache:
    """Bounded LRU of recently seen HMAC signatures.

    Implementation: a dict with insertion-ordered keys plus a monotonic
    clock for TTL. Eviction happens opportunistically on ``remember``
    calls rather than via a background thread to keep the class test
    friendly. Size and TTL are configurable; defaults match the spec.
    """

    def __init__(self, *, max_size: int = 10_000, ttl_seconds: int = 600) -> None:
        """Create an empty cache."""
        self._max_size = int(max_size)
        self._ttl = int(ttl_seconds)
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def seen(self, signature: str) -> bool:
        """Return True if ``signature`` is present and still within TTL."""
        now = time.monotonic()
        with self._lock:
            ts = self._seen.get(signature)
            if ts is None:
                return False
            if now - ts > self._ttl:
                del self._seen[signature]
                return False
            return True

    def remember(self, signature: str) -> None:
        """Record ``signature`` and evict stale / overflow entries."""
        now = time.monotonic()
        with self._lock:
            cutoff = now - self._ttl
            if len(self._seen) >= self._max_size:
                stale = [k for k, v in self._seen.items() if v < cutoff]
                for k in stale:
                    self._seen.pop(k, None)
                while len(self._seen) >= self._max_size:
                    self._seen.pop(next(iter(self._seen)))
            self._seen[signature] = now
