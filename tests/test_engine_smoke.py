"""End-to-end smoke test for the engine.

Binds the HTTP handler on a random high port and verifies a path-traversal
request produces a fake ``/etc/passwd`` body. This covers the critical
HTTP + rule-engine + database + log manager + session manager interplay.
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest
from aiohttp import ClientSession, ClientTimeout

from honeytrap.core.config import Config
from honeytrap.core.engine import Engine
from honeytrap.core.profile import load_profile


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.asyncio
async def test_http_path_traversal_smoke(tmp_path: Path) -> None:
    cfg = Config()
    cfg.general.log_directory = str(tmp_path)
    cfg.general.bind_address = "127.0.0.1"
    cfg.geo.enabled = False  # avoid network calls in tests
    cfg.general.dashboard = False
    cfg.ai.enabled = False

    profile = load_profile("web_server")
    # Replace HTTP port with a free high port to avoid privilege issues.
    for svc in profile.services:
        if svc.protocol == "http":
            svc.port = _free_port()
        else:
            svc.port = _free_port()

    engine = Engine(cfg, profile)
    try:
        await engine.start()
        http_port = next(p for proto, _req, p in engine.active_ports if proto == "http")

        async with ClientSession(timeout=ClientTimeout(total=5)) as session:
            url = f"http://127.0.0.1:{http_port}/cgi-bin/.%2e/%2e%2e/etc/passwd"
            async with session.get(url) as resp:
                body = await resp.text()
                assert resp.status == 200
                assert "root:" in body

        # Database should have recorded at least one exploit_attempt event.
        await asyncio.sleep(0.1)
        types = {row["event_type"] for row in engine.database.events_by_type()}
        assert "exploit_attempt" in types
    finally:
        await engine.stop()
