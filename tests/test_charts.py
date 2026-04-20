"""Tests for the chart generation layer."""

from __future__ import annotations

import base64

from honeytrap.reporting import charts as charts_mod


def _is_valid_b64_png(s: str) -> bool:
    """Return True if s is a non-empty base64 string decoding to PNG bytes."""
    if not s:
        return False
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return False
    # PNG magic header
    return raw.startswith(b"\x89PNG\r\n\x1a\n")


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------
def test_timeline_with_data() -> None:
    data = [{"hour": f"2026-04-20 {h:02d}", "events": h * 3} for h in range(5)]
    out = charts_mod.attack_timeline_chart(data)
    assert _is_valid_b64_png(out)


def test_timeline_empty() -> None:
    out = charts_mod.attack_timeline_chart([])
    # Empty data still returns the placeholder PNG
    assert _is_valid_b64_png(out)


# ---------------------------------------------------------------------------
# protocol
# ---------------------------------------------------------------------------
def test_protocol_chart_with_data() -> None:
    data = [
        {"protocol": "http", "events": 42},
        {"protocol": "ssh", "events": 13},
        {"protocol": "ftp", "events": 7},
    ]
    out = charts_mod.protocol_distribution_chart(data)
    assert _is_valid_b64_png(out)


def test_protocol_chart_empty() -> None:
    out = charts_mod.protocol_distribution_chart([])
    assert _is_valid_b64_png(out)


# ---------------------------------------------------------------------------
# country
# ---------------------------------------------------------------------------
def test_country_chart_with_data() -> None:
    data = [
        {"country_code": "US", "country_name": "United States", "events": 100},
        {"country_code": "RU", "country_name": "Russia", "events": 80},
        {"country_code": "CN", "country_name": "China", "events": 50},
    ]
    out = charts_mod.country_distribution_chart(data, top_n=2)
    assert _is_valid_b64_png(out)


def test_country_chart_empty() -> None:
    assert _is_valid_b64_png(charts_mod.country_distribution_chart([]))


# ---------------------------------------------------------------------------
# technique
# ---------------------------------------------------------------------------
def test_technique_chart_with_data() -> None:
    data = [
        {"technique_id": "T1110", "technique_name": "Brute Force", "events": 20},
        {"technique_id": "T1059", "technique_name": "Command and Scripting", "events": 9},
    ]
    out = charts_mod.attack_technique_chart(data)
    assert _is_valid_b64_png(out)


def test_technique_chart_empty() -> None:
    assert _is_valid_b64_png(charts_mod.attack_technique_chart([]))


# ---------------------------------------------------------------------------
# tactic heatmap
# ---------------------------------------------------------------------------
def test_tactic_heatmap_with_data() -> None:
    data = [
        {"tactic": "credential-access", "events": 30},
        {"tactic": "initial-access", "events": 15},
    ]
    out = charts_mod.tactic_heatmap(data)
    assert _is_valid_b64_png(out)


def test_tactic_heatmap_empty() -> None:
    assert _is_valid_b64_png(charts_mod.tactic_heatmap([]))


# ---------------------------------------------------------------------------
# credential chart
# ---------------------------------------------------------------------------
def test_credential_chart_with_data() -> None:
    data = [
        {"username": "root", "password": "toor", "attempts": 8},
        {"username": "admin", "password": "admin", "attempts": 5},
    ]
    out = charts_mod.credential_chart(data)
    assert _is_valid_b64_png(out)


def test_credential_chart_empty() -> None:
    assert _is_valid_b64_png(charts_mod.credential_chart([]))


# ---------------------------------------------------------------------------
# hourly heatmap
# ---------------------------------------------------------------------------
def test_hourly_heatmap_with_matrix() -> None:
    grid = [[0] * 24 for _ in range(7)]
    grid[0][9] = 10
    grid[3][14] = 25
    out = charts_mod.hourly_heatmap(grid)
    assert _is_valid_b64_png(out)


def test_hourly_heatmap_with_dicts() -> None:
    data = [
        {"day": 0, "hour": 5, "events": 3},
        {"day": 6, "hour": 23, "events": 11},
    ]
    out = charts_mod.hourly_heatmap(data)
    assert _is_valid_b64_png(out)


def test_hourly_heatmap_empty_matrix() -> None:
    grid = [[0] * 24 for _ in range(7)]
    out = charts_mod.hourly_heatmap(grid)
    # All zeros still renders a placeholder
    assert _is_valid_b64_png(out)


def test_hourly_heatmap_empty() -> None:
    assert _is_valid_b64_png(charts_mod.hourly_heatmap([]))


# ---------------------------------------------------------------------------
# consistency
# ---------------------------------------------------------------------------
def test_all_chart_functions_exported() -> None:
    for name in (
        "attack_timeline_chart",
        "protocol_distribution_chart",
        "country_distribution_chart",
        "attack_technique_chart",
        "tactic_heatmap",
        "credential_chart",
        "hourly_heatmap",
    ):
        assert name in charts_mod.__all__
        assert callable(getattr(charts_mod, name))
