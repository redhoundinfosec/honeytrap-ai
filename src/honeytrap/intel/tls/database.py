"""YAML-backed JA3/JA4 fingerprint database.

The bundled database ships with ~30 high- to medium-confidence
entries. Operators can layer a custom database on top through the
``--tls-fingerprint-db`` CLI flag.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH: Path = Path(__file__).with_name("fingerprints.yaml")


class FingerprintCategory(str, Enum):
    """High-level category a fingerprint entry is tagged with."""

    SCANNER = "scanner"
    LIBRARY = "library"
    BROWSER = "browser"
    MALWARE = "malware"
    PENTEST_TOOL = "pentest_tool"
    BOT = "bot"
    UNKNOWN = "unknown"


class FingerprintConfidence(str, Enum):
    """How confident the database is in the attribution."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FingerprintDatabaseError(ValueError):
    """Raised when a fingerprint database file fails validation."""


@dataclass(frozen=True)
class FingerprintEntry:
    """One row in the fingerprint database."""

    name: str
    category: FingerprintCategory
    confidence: FingerprintConfidence
    ja3: str | None = None
    ja4: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Match:
    """A successful lookup result."""

    name: str
    category: FingerprintCategory
    confidence: FingerprintConfidence
    matched_on: str  # "ja3" | "ja4"
    ja3: str | None = None
    ja4: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation."""
        return {
            "name": self.name,
            "category": self.category.value,
            "confidence": self.confidence.value,
            "matched_on": self.matched_on,
            "ja3": self.ja3,
            "ja4": self.ja4,
            "references": list(self.references),
        }


def _require(entry: dict[str, Any], key: str, idx: int) -> Any:
    if key not in entry:
        raise FingerprintDatabaseError(f"fingerprint entry #{idx} missing required field {key!r}")
    return entry[key]


def _parse_entry(entry: dict[str, Any], idx: int) -> FingerprintEntry:
    name = str(_require(entry, "name", idx)).strip()
    if not name:
        raise FingerprintDatabaseError(f"fingerprint entry #{idx} has empty name")
    try:
        category = FingerprintCategory(str(_require(entry, "category", idx)).lower())
    except ValueError as exc:
        raise FingerprintDatabaseError(f"fingerprint entry #{idx} invalid category: {exc}") from exc
    try:
        confidence = FingerprintConfidence(str(_require(entry, "confidence", idx)).lower())
    except ValueError as exc:
        raise FingerprintDatabaseError(
            f"fingerprint entry #{idx} invalid confidence: {exc}"
        ) from exc
    ja3 = entry.get("ja3")
    ja4 = entry.get("ja4")
    if not ja3 and not ja4:
        raise FingerprintDatabaseError(f"fingerprint entry #{idx} must provide ja3 or ja4")
    if ja3 is not None:
        ja3 = str(ja3).strip().lower()
        if len(ja3) != 32 or not all(c in "0123456789abcdef" for c in ja3):
            raise FingerprintDatabaseError(
                f"fingerprint entry #{idx} ja3 must be a 32-char hex MD5"
            )
    if ja4 is not None:
        ja4 = str(ja4).strip()
        if "_" not in ja4:
            raise FingerprintDatabaseError(f"fingerprint entry #{idx} ja4 has unexpected format")
    refs = entry.get("references") or []
    if not isinstance(refs, list):
        raise FingerprintDatabaseError(f"fingerprint entry #{idx} references must be a list")
    return FingerprintEntry(
        name=name,
        category=category,
        confidence=confidence,
        ja3=ja3,
        ja4=ja4,
        references=tuple(str(r) for r in refs),
    )


class FingerprintDatabase:
    """In-memory lookup for JA3 and JA4 fingerprints."""

    def __init__(self, entries: list[FingerprintEntry]) -> None:
        """Create a database from an already-parsed list of entries."""
        self._entries: list[FingerprintEntry] = list(entries)
        self._by_ja3: dict[str, list[FingerprintEntry]] = {}
        self._by_ja4: dict[str, list[FingerprintEntry]] = {}
        for e in self._entries:
            if e.ja3:
                self._by_ja3.setdefault(e.ja3, []).append(e)
            if e.ja4:
                self._by_ja4.setdefault(e.ja4, []).append(e)

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[FingerprintEntry, ...]:
        """Return an immutable view of every entry."""
        return tuple(self._entries)

    def lookup(
        self,
        *,
        ja3: str | None = None,
        ja4: str | None = None,
    ) -> list[Match]:
        """Return every entry matching the given JA3 and/or JA4 hash."""
        matches: list[Match] = []
        seen: set[tuple[str, str]] = set()
        if ja3:
            ja3_norm = ja3.lower()
            for entry in self._by_ja3.get(ja3_norm, []):
                key = (entry.name, "ja3")
                if key in seen:
                    continue
                seen.add(key)
                matches.append(
                    Match(
                        name=entry.name,
                        category=entry.category,
                        confidence=entry.confidence,
                        matched_on="ja3",
                        ja3=entry.ja3,
                        ja4=entry.ja4,
                        references=entry.references,
                    )
                )
        if ja4:
            for entry in self._by_ja4.get(ja4, []):
                key = (entry.name, "ja4")
                if key in seen:
                    continue
                seen.add(key)
                matches.append(
                    Match(
                        name=entry.name,
                        category=entry.category,
                        confidence=entry.confidence,
                        matched_on="ja4",
                        ja3=entry.ja3,
                        ja4=entry.ja4,
                        references=entry.references,
                    )
                )
        return matches

    @classmethod
    def from_yaml(cls, path: str | Path) -> FingerprintDatabase:
        """Load and validate a database from a YAML file."""
        p = Path(path)
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise FingerprintDatabaseError(f"fingerprint database not found: {p}") from exc
        except yaml.YAMLError as exc:
            raise FingerprintDatabaseError(
                f"fingerprint database YAML parse failed: {exc}"
            ) from exc
        if not isinstance(raw, dict) or "fingerprints" not in raw:
            raise FingerprintDatabaseError(
                "fingerprint database must have a top-level 'fingerprints' list"
            )
        entries_raw = raw["fingerprints"]
        if not isinstance(entries_raw, list):
            raise FingerprintDatabaseError("'fingerprints' must be a list")
        entries = [_parse_entry(entry, idx) for idx, entry in enumerate(entries_raw)]
        logger.debug("Loaded %d TLS fingerprints from %s", len(entries), p)
        return cls(entries)

    @classmethod
    def default(cls) -> FingerprintDatabase:
        """Load the bundled fingerprint database."""
        return cls.from_yaml(DEFAULT_DB_PATH)
