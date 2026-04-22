"""Shared fixtures for the management API test suite.

Each test gets its own temporary state directory so audit logs and the
keyring cannot leak between cases. :func:`build_server` assembles an
:class:`APIServer` bound to an :class:`InMemoryService` and returns a
helper object that exposes both the server and a direct-call shortcut
for crafting requests without opening sockets.
"""

from __future__ import annotations

import gzip
import io
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from honeytrap.api import APIConfig, APIServer
from honeytrap.api.auth import APIKeyStore
from honeytrap.api.models import AlertRecord, EventRecord, ProfileInfo
from honeytrap.api.rbac import Role
from honeytrap.api.service import InMemoryService, _StoredSession


@dataclass
class ApiClient:
    """Tiny in-process client. Call :meth:`request` to drive the server."""

    server: APIServer
    service: InMemoryService
    store: APIKeyStore

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: bytes | str | dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Execute a request and return ``(status, headers, body)``."""
        payload: bytes
        if body is None:
            payload = b""
        elif isinstance(body, bytes):
            payload = body
        elif isinstance(body, str):
            payload = body.encode("utf-8")
        else:
            payload = json.dumps(body).encode("utf-8")
        hdr = dict(headers or {})
        if token and "X-API-Key" not in hdr and "x-api-key" not in hdr:
            hdr["X-API-Key"] = token
        response = self.server.handle(
            method=method,
            path=path,
            headers=hdr,
            body=payload,
            remote_addr="127.0.0.1",
        )
        out_headers = dict(response.headers)
        out_headers["Content-Type"] = response.content_type
        return response.status, out_headers, response.body

    def json(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, Any]:
        """Decode the JSON body for convenience."""
        status, _, raw = self.request(method, path, token=token, body=body, headers=headers)
        return status, json.loads(raw.decode("utf-8")) if raw else None


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """Return a temporary state directory for the keyring and audit log."""
    (tmp_path / "state").mkdir()
    return tmp_path / "state"


@pytest.fixture
def client(state_dir: Path) -> ApiClient:
    """Build a server populated with deterministic sample data."""
    return _build_client(state_dir)


def _build_client(state_dir: Path) -> ApiClient:
    config = APIConfig(
        state_dir=state_dir, port=0, rate_limits={"viewer": 600, "analyst": 600, "admin": 600}
    )
    service = InMemoryService()
    service.set_attck({"T1110": 5, "T1059": 3})
    service.set_iocs(
        [
            {"type": "ip", "value": "10.0.0.1", "first_seen": "2026-04-22T00:00:00Z"},
            {"type": "domain", "value": "evil.example", "first_seen": "2026-04-22T00:01:00Z"},
        ]
    )
    service.set_tls([{"ja3": "a" * 32, "count": 9}, {"ja3": "b" * 32, "count": 3}])
    service.set_profiles(
        [
            ProfileInfo(
                name="web_server",
                category="webapp",
                description="Apache look-alike",
                services=[{"protocol": "http", "port": 80}],
            ),
            ProfileInfo(
                name="iot_camera",
                category="iot",
                description="IP camera",
                services=[{"protocol": "telnet", "port": 23}],
            ),
        ]
    )
    service.set_config(
        {"general": {"log_directory": "/var/log/honeytrap"}, "ai": {"api_key": "REDACTED"}}
    )
    # Build a sample session with PCAP + JSONL + timeline.
    sess = _StoredSession(
        session_id="sess-1",
        protocol="ssh",
        remote_ip="203.0.113.5",
        remote_port=44444,
        local_port=22,
        started_at="2026-04-22T10:00:00Z",
        ended_at="2026-04-22T10:00:30Z",
        bytes_in=128,
        bytes_out=64,
        events=[
            EventRecord(
                session_id="sess-1",
                timestamp="2026-04-22T10:00:01Z",
                direction="INBOUND",
                protocol="ssh",
                source_ip="203.0.113.5",
                size=32,
            )
        ],
        pcap=b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16,
        timeline=[
            {
                "timestamp": "2026-04-22T10:00:00Z",
                "kind": "connect",
                "description": "ssh session opened",
            }
        ],
    )
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b'{"session_id":"sess-1"}\n')
    sess.jsonl = buf.getvalue()
    service.add_session(sess)
    service.add_session(
        _StoredSession(
            session_id="sess-2",
            protocol="http",
            remote_ip="198.51.100.7",
            remote_port=50555,
            local_port=80,
            started_at="2026-04-22T10:01:00Z",
            ended_at=None,
            bytes_in=0,
            bytes_out=0,
        )
    )
    service.add_alert(
        AlertRecord(
            id="alert-1",
            severity="HIGH",
            title="Credential stuffing",
            summary="100 failed logins",
            source_ip="203.0.113.5",
            protocol="ssh",
            session_id="sess-1",
            timestamp="2026-04-22T10:02:00Z",
            attck_techniques=["T1110"],
        )
    )
    service.add_alert(
        AlertRecord(
            id="alert-2",
            severity="LOW",
            title="Scan",
            summary="Single probe",
            source_ip="198.51.100.7",
            protocol="http",
            session_id="sess-2",
            timestamp="2026-04-22T10:03:00Z",
        )
    )
    service.set_prometheus(
        "# HELP honeytrap_connections_total Total connections.\n"
        "# TYPE honeytrap_connections_total counter\n"
        "honeytrap_connections_total 2\n"
    )
    store = APIKeyStore(config.state_path(config.api_keys_name))
    server = APIServer(service, store, config)
    return ApiClient(server=server, service=service, store=store)


def make_key(client: ApiClient, *, name: str, role: Role) -> tuple[Any, str]:
    """Create a key via the store (not the HTTP endpoint) and return the token."""
    return client.store.create(name=name, role=role)


def fresh_client(state_dir: Path) -> ApiClient:
    """Build a second client pointing at its own state for isolation tests."""
    return _build_client(state_dir)


def now_ts() -> int:
    """Return the current unix timestamp for HMAC tests."""
    return int(time.time())
