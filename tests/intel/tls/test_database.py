"""FingerprintDatabase tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from honeytrap.intel.tls.database import (
    FingerprintCategory,
    FingerprintDatabase,
    FingerprintDatabaseError,
)


def test_bundled_database_loads() -> None:
    db = FingerprintDatabase.default()
    assert len(db) >= 25


def test_lookup_by_ja3_returns_match() -> None:
    db = FingerprintDatabase.default()
    first = db.entries[0]
    assert first.ja3 is not None
    matches = db.lookup(ja3=first.ja3)
    names = {m.name for m in matches}
    assert first.name in names
    assert matches[0].matched_on in {"ja3", "ja4"}


def test_lookup_by_ja4_returns_match() -> None:
    db = FingerprintDatabase.default()
    ja4_entry = next((e for e in db.entries if e.ja4), None)
    assert ja4_entry is not None
    matches = db.lookup(ja4=ja4_entry.ja4)
    assert any(m.name == ja4_entry.name for m in matches)


def test_lookup_unknown_returns_empty() -> None:
    db = FingerprintDatabase.default()
    assert db.lookup(ja3="0" * 32) == []
    assert db.lookup(ja4="t13d0000h2_deadbeefdead_deadbeefdead") == []


def test_invalid_entry_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        textwrap.dedent(
            """
            fingerprints:
              - name: bogus
                category: library
                confidence: banana
                ja3: "ffffffffffffffffffffffffffffffff"
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(FingerprintDatabaseError):
        FingerprintDatabase.from_yaml(bad)


def test_missing_fingerprint_field_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad2.yaml"
    bad.write_text(
        textwrap.dedent(
            """
            fingerprints:
              - name: neither
                category: library
                confidence: high
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(FingerprintDatabaseError):
        FingerprintDatabase.from_yaml(bad)


def test_categories_enum_coverage() -> None:
    db = FingerprintDatabase.default()
    observed = {e.category for e in db.entries}
    # Database should span multiple categories, not collapse to one.
    assert FingerprintCategory.SCANNER in observed
    assert FingerprintCategory.BROWSER in observed
    assert FingerprintCategory.MALWARE in observed
