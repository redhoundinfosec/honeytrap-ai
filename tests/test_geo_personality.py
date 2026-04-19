"""Tests for geo-personality selection."""

from __future__ import annotations

from honeytrap.ai.geo_personality import GeoPersonalitySelector


def test_default_personality_when_disabled() -> None:
    sel = GeoPersonalitySelector(enabled=False)
    assert sel.for_country("RU").key == "us_startup"


def test_russian_personality_for_ru() -> None:
    sel = GeoPersonalitySelector(enabled=True)
    p = sel.for_country("RU")
    assert p.key == "russian_company"
    assert "ТехноГрупп" in p.company


def test_chinese_personality_for_cn() -> None:
    sel = GeoPersonalitySelector(enabled=True)
    p = sel.for_country("CN")
    assert p.locale == "zh-CN"


def test_default_for_unknown_country() -> None:
    sel = GeoPersonalitySelector(enabled=True)
    assert sel.for_country("ZZ").key == "us_startup"
    assert sel.for_country("").key == "us_startup"
