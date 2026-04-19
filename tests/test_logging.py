"""Tests for the logging layer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from honeytrap.logging.database import AttackDatabase
from honeytrap.logging.manager import LogManager
from honeytrap.logging.models import Event


@pytest.fixture
def tmp_db(tmp_path: Path) -> AttackDatabase:
    db = AttackDatabase(tmp_path / "attacks.db")
    yield db
    db.close()


def test_database_record_and_read(tmp_db: AttackDatabase) -> None:
    event = Event(
        protocol="http",
        event_type="http_request",
        remote_ip="1.2.3.4",
        country_code="US",
        country_name="United States",
        path="/admin",
        method="GET",
        message="GET /admin",
    )
    tmp_db.record_event(event)
    assert tmp_db.count() == 1
    attackers = tmp_db.top_attackers(5)
    assert attackers[0]["remote_ip"] == "1.2.3.4"


def test_top_credentials(tmp_db: AttackDatabase) -> None:
    for _ in range(3):
        tmp_db.record_event(
            Event(
                protocol="ssh",
                event_type="auth_attempt",
                remote_ip="5.6.7.8",
                username="root",
                password="toor",
                message="auth",
            )
        )
    creds = tmp_db.top_credentials(5)
    assert creds[0]["attempts"] == 3


@pytest.mark.asyncio
async def test_log_manager_writes_jsonl(tmp_path: Path) -> None:
    manager = LogManager(tmp_path, max_size_mb=1, retention_days=1)
    await manager.write_event(
        Event(
            protocol="http",
            event_type="http_request",
            remote_ip="1.2.3.4",
            timestamp=datetime.now(timezone.utc),
            message="hello",
        )
    )
    files = list((tmp_path / "events").glob("events_*.jsonl"))
    assert files, "expected a daily event log to be written"
    content = files[0].read_text(encoding="utf-8")
    assert "1.2.3.4" in content
    await manager.close()
