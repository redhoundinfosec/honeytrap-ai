"""HoneyTrap management REST API.

A small, self-contained HTTP server that exposes read/write control of a
running HoneyTrap deployment under ``/api/v1``. Features:

* API-key authentication (``htk_``-prefixed tokens) with SHA-256-only
  persistence and constant-time comparison.
* Optional HMAC request signing with a 5-minute clock-skew window and
  replay protection via a bounded LRU of seen signatures.
* Role-based access control (``viewer``, ``analyst``, ``admin``).
* Per-key token-bucket rate limiting with clear ``429`` envelopes.
* Append-only gzipped JSONL audit log, rotated at 100 MiB (10 rotations).
* OpenAPI 3.1 self-description and a self-hosted Rapidoc UI at
  ``/api/v1/docs``.

The transport is stdlib-only (``http.server`` on a background thread);
no new runtime dependency is introduced. ``aiohttp`` is already used by
other subsystems but is intentionally not required here so the API
server remains importable and runnable in stripped-down environments.
"""

from __future__ import annotations

from honeytrap.api.audit import AuditLog
from honeytrap.api.auth import APIKey, APIKeyStore, generate_api_key
from honeytrap.api.config import APIConfig
from honeytrap.api.rbac import Role
from honeytrap.api.server import APIServer

__all__ = [
    "APIConfig",
    "APIKey",
    "APIKeyStore",
    "APIServer",
    "AuditLog",
    "Role",
    "generate_api_key",
]
