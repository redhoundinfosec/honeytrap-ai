"""Tests for the reporting layer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from honeytrap.core.config import Config
from honeytrap.logging.database import AttackDatabase
from honeytrap.logging.models import Event
from honeytrap.reporting.analyzer import Analyzer
from honeytrap.reporting.generator import ReportGenerator
from honeytrap.reporting.pdf_export import PDFExportError, export_pdf, is_available


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


def test_render_html_contains_chart_images(tmp_path: Path) -> None:
    """Embedded charts must appear as data:image/png;base64 URIs."""
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        _populate(db)
        gen = ReportGenerator(Config(), db)
        out = gen.render_html(tmp_path / "report.html")
        body = out.read_text(encoding="utf-8")
        assert "data:image/png;base64," in body
        # Dark theme colors should be present in CSS
        assert "#1a1a2e" in body
        assert "sidebar" in body
    finally:
        db.close()


def test_render_html_empty_db(tmp_path: Path) -> None:
    """HTML report should render even on an empty database."""
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        gen = ReportGenerator(Config(), db)
        out = gen.render_html(tmp_path / "report.html")
        assert out.exists()
        body = out.read_text(encoding="utf-8")
        assert "HoneyTrap AI" in body
    finally:
        db.close()


def test_snapshot_has_new_fields(tmp_path: Path) -> None:
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        _populate(db)
        snap = Analyzer(db).snapshot()
        assert isinstance(snap.events_by_hour, list)
        assert isinstance(snap.hourly_heatmap, list)
        assert len(snap.hourly_heatmap) == 7
        assert all(len(row) == 24 for row in snap.hourly_heatmap)
        assert isinstance(snap.time_range, tuple)
        assert len(snap.time_range) == 2
    finally:
        db.close()


def test_analyzer_empty_db(tmp_path: Path) -> None:
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        snap = Analyzer(db).snapshot()
        assert snap.total_events == 0
        assert snap.events_by_hour == []
        assert snap.hourly_heatmap == [[0] * 24 for _ in range(7)]
        assert snap.time_range == (None, None)
    finally:
        db.close()


def test_database_events_by_hour(tmp_path: Path) -> None:
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        _populate(db)
        buckets = db.events_by_hour()
        # Events share the same hour so we expect a single bucket
        assert isinstance(buckets, list)
        assert all("hour" in row and "events" in row for row in buckets)
    finally:
        db.close()


def test_database_hourly_heatmap_shape(tmp_path: Path) -> None:
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        _populate(db)
        grid = db.hourly_heatmap_data()
        assert len(grid) == 7
        assert all(len(row) == 24 for row in grid)
    finally:
        db.close()


def test_database_time_range_empty(tmp_path: Path) -> None:
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        assert db.time_range() == (None, None)
    finally:
        db.close()


def test_pdf_export_missing_dep(tmp_path: Path) -> None:
    """When weasyprint is not installed, export_pdf should raise PDFExportError."""
    with (
        patch("honeytrap.reporting.pdf_export._load_weasyprint", return_value=None),
        pytest.raises(PDFExportError),
    ):
        export_pdf("<html></html>", tmp_path / "out.pdf")


def test_pdf_export_with_mock(tmp_path: Path) -> None:
    """A fake weasyprint module should satisfy export_pdf."""

    class _FakeHTML:
        def __init__(self, string: str) -> None:
            self.string = string

        def write_pdf(self, path: str) -> None:
            Path(path).write_bytes(b"%PDF-1.4 fake")

    class _FakeMod:
        HTML = _FakeHTML

    with patch("honeytrap.reporting.pdf_export._load_weasyprint", return_value=_FakeMod):
        out = export_pdf("<html></html>", tmp_path / "out.pdf")
        assert out.exists()
        assert out.read_bytes().startswith(b"%PDF")


def test_pdf_export_is_available_flag() -> None:
    """is_available should be a plain bool."""
    assert isinstance(is_available(), bool)


def test_render_pdf_missing_dep(tmp_path: Path) -> None:
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        _populate(db)
        gen = ReportGenerator(Config(), db)
        with (
            patch("honeytrap.reporting.pdf_export._load_weasyprint", return_value=None),
            pytest.raises(PDFExportError),
        ):
            gen.render_pdf(tmp_path / "r.pdf")
    finally:
        db.close()


def test_build_charts_handles_failure(tmp_path: Path) -> None:
    """If a chart function raises, the generator must substitute an empty string."""
    db = AttackDatabase(tmp_path / "attacks.db")
    try:
        _populate(db)
        gen = ReportGenerator(Config(), db)
        with patch(
            "honeytrap.reporting.generator.charts_mod.attack_timeline_chart",
            side_effect=RuntimeError("boom"),
        ):
            out = gen.render_html(tmp_path / "r.html")
            body = out.read_text(encoding="utf-8")
            # Other charts still embed base64 even if timeline fails
            assert body.count("data:image/png;base64,") >= 1
    finally:
        db.close()
