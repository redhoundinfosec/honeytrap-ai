"""End-to-end TLSFingerprinter tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

from honeytrap.intel.tls.database import (
    FingerprintCategory,
    FingerprintDatabase,
)
from honeytrap.intel.tls.fingerprinter import TLSFingerprinter


def test_fingerprint_end_to_end(curl_bytes: bytes) -> None:
    fp = TLSFingerprinter()
    result = fp.fingerprint(curl_bytes)
    assert result is not None
    assert len(result.ja3) == 32
    assert result.ja3_str.count(",") == 4
    assert result.ja4.startswith(("t", "q"))
    assert result.client_hello.server_name == "example.com"


def test_fingerprint_malformed_returns_none(malformed_short_bytes: bytes) -> None:
    fp = TLSFingerprinter()
    assert fp.fingerprint(malformed_short_bytes) is None


def test_fingerprint_lru_cache(curl_bytes: bytes) -> None:
    fp = TLSFingerprinter()
    fp.cache_clear()
    a = fp.fingerprint(curl_bytes)
    b = fp.fingerprint(curl_bytes)
    assert a is b
    assert fp.cache_info().hits >= 1


def test_fingerprint_scanner_match(nmap_bytes: bytes, tmp_path: Path) -> None:
    # Wire nmap's computed JA3 into a scratch database so the lookup
    # produces a deterministic match regardless of the bundled list.
    first_pass = TLSFingerprinter().fingerprint(nmap_bytes)
    assert first_pass is not None
    db_file = tmp_path / "scanner.yaml"
    db_file.write_text(
        textwrap.dedent(
            f"""
            fingerprints:
              - name: synthetic-nmap
                category: scanner
                confidence: high
                ja3: "{first_pass.ja3}"
                references:
                  - https://nmap.org
            """
        ),
        encoding="utf-8",
    )
    db = FingerprintDatabase.from_yaml(db_file)
    fp = TLSFingerprinter(database=db)
    result = fp.fingerprint(nmap_bytes)
    assert result is not None
    assert any(m.category == FingerprintCategory.SCANNER for m in result.matches)
    assert result.to_dict()["matches"][0]["name"] == "synthetic-nmap"
