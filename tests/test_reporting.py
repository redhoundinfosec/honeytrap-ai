"""Tests for the reporting layer."""

from __future__ import annotations

from pathlib import Path

from honeytrap.core.config import Config
from honeytrap.logging.database import AttackDatabase
from honeytrap.logging.models import Event
from honeytrap.reporting.generator import ReportGenerator


def _populate(db: AttackDatabase) -> None:
    db.record_event(Event(protocol="http", event_type="http_request", remote_ip="1.1.1.1", country_code="US", country_name="United States", path="/admin"))
    db.record_event(Event(protocol="ssh", event_type="auth_attempt", remote_ip="2.2.2.2", country_code="RU", country_name="Russia", username="root", password="toor"))
    db.record_event(Event(protocol="http", event_type="exploit_attempt", remote_ip="3.3.3.3", country_code="CN", country_name="China", path="/.env"))


def test_report_snapshot(tmp_path: Path) -> None:
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        _populate(db)
        gen = ReportGenerator(Config(), db)
        snap = gen.snapshot()
        assert snap.total_events == 3
        assert snap.unique_ips == 3
        assert len(snap.country_distribution) == 3
    finally:
        db.close()


def test_render_html(tmp_path: Path) -> None:
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        _populate(db)
        gen = ReportGenerator(Config(), db)
        out = gen.render_html(tmp_path / "report.html")
        assert out.exists()
        body = out.read_text(encoding="utf-8")
        assert "HoneyTrap AI" in body
        assert "1.1.1.1" in body
    finally:
        db.close()
