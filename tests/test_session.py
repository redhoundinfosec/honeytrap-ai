"""Tests for session tracking."""

from __future__ import annotations

from honeytrap.core.session import SessionManager


def test_create_close_archive() -> None:
    mgr = SessionManager()
    s = mgr.create("1.2.3.4", 55555, "http", 80)
    assert len(mgr.active()) == 1
    s.record_command("GET /")
    s.record_credentials("root", "toor")
    s.add_tag("scanner")
    mgr.close(s.session_id)
    assert mgr.active() == []
    assert len(mgr.history()) == 1
    assert mgr.history()[0].ended_at is not None


def test_session_to_dict_roundtrip() -> None:
    mgr = SessionManager()
    s = mgr.create("1.2.3.4", 1, "ftp", 21)
    s.country_code = "RU"
    s.country_name = "Russia"
    d = s.to_dict()
    assert d["remote_ip"] == "1.2.3.4"
    assert d["country_code"] == "RU"
    assert "duration_seconds" in d
