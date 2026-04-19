"""Tests for the rule-based response engine."""

from __future__ import annotations

from honeytrap.ai.rule_engine import RuleEngine
from honeytrap.core.profile import load_profile


def _engine() -> RuleEngine:
    return RuleEngine(load_profile("web_server"))


def test_path_traversal_detected() -> None:
    match = _engine().match_http(
        method="GET",
        path="/cgi-bin/.%2e/%2e%2e/etc/passwd",
        user_agent="curl/7.68",
        remote_ip="1.2.3.4",
    )
    assert match.category == "path_traversal"
    assert "exploit_attempt" in match.tags
    assert "root:" in match.response


def test_admin_panel_detected() -> None:
    match = _engine().match_http(
        method="GET", path="/wp-login.php", user_agent="", remote_ip="1.2.3.4"
    )
    assert match.category == "admin_panel"
    assert "admin_panel_probe" in match.tags


def test_scanner_fingerprint() -> None:
    match = _engine().match_http(
        method="GET",
        path="/",
        user_agent="Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        remote_ip="1.2.3.4",
    )
    assert any(t.startswith("tool:nmap") for t in match.tags)


def test_sensitive_file_env_returns_fake_env() -> None:
    match = _engine().match_http(
        method="GET", path="/.env", user_agent="curl/7.68", remote_ip="1.2.3.4"
    )
    assert match.category == "sensitive_file"
    assert "DB_PASSWORD" in match.response


def test_404_for_unknown_path() -> None:
    match = _engine().match_http(
        method="GET", path="/does-not-exist", user_agent="", remote_ip="1.2.3.4"
    )
    assert match.category == "not_found"
    assert match.status_code == 404


def test_auth_match_brute_force_tag() -> None:
    engine = _engine()
    for _ in range(6):
        match = engine.match_auth(
            protocol="ssh", username="root", password="wrong", remote_ip="9.9.9.9"
        )
    assert "brute_force" in match.tags


def test_auth_weak_cred_hit() -> None:
    match = _engine().match_auth(
        protocol="ssh", username="admin", password="admin123", remote_ip="9.9.9.9"
    )
    assert match.metadata["granted"] is True


def test_shell_response_canned() -> None:
    assert "root" in _engine().shell_response("whoami")
    assert "uid=0(root)" in _engine().shell_response("id")
