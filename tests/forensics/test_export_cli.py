"""CLI export coverage."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from honeytrap.core.config import Config
from honeytrap.forensics.cli import build_export_parser, run_export
from honeytrap.forensics.recorder import (
    Direction,
    JsonlSessionStore,
    SessionFrame,
    SessionMetadata,
)


def _populate(tmp_path: Path) -> None:
    store = JsonlSessionStore(tmp_path)
    meta = SessionMetadata(
        session_id="cli1",
        protocol="ssh",
        remote_ip="9.9.9.9",
        remote_port=2222,
        local_ip="10.0.0.1",
        local_port=22,
        started_at=datetime(2026, 4, 22, 0, 0, tzinfo=timezone.utc),
    )
    store.open_session(meta)
    store.append_frame(
        SessionFrame(
            session_id="cli1",
            timestamp_ns=int(meta.started_at.timestamp() * 1_000_000_000) + 1,
            direction=Direction.INBOUND,
            payload=b"USER admin\r\n",
            source_ip="9.9.9.9",
            source_port=2222,
            dest_ip="10.0.0.1",
            dest_port=22,
            protocol="ssh",
        )
    )
    meta.ended_at = datetime(2026, 4, 22, 0, 1, tzinfo=timezone.utc)
    meta.frame_count = 1
    meta.bytes_in = 12
    store.close_session(meta)
    store.close()


def _config(tmp_path: Path) -> Config:
    cfg = Config()
    cfg.forensics.path = str(tmp_path)
    cfg.forensics.store = "jsonl"
    cfg.general.log_directory = str(tmp_path)
    return cfg


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build_export_parser(sub)
    return parser


def test_export_pcap(tmp_path: Path, capsys) -> None:
    _populate(tmp_path)
    out = tmp_path / "x.pcap"
    args = _parser().parse_args(["export", "pcap", "--session", "cli1", "--out", str(out)])
    code = run_export(args, _config(tmp_path))
    assert code == 0
    assert out.exists() and out.stat().st_size > 0


def test_export_jsonl(tmp_path: Path, capsys) -> None:
    _populate(tmp_path)
    out = tmp_path / "x.jsonl.gz"
    args = _parser().parse_args(["export", "jsonl", "--session", "cli1", "--out", str(out)])
    code = run_export(args, _config(tmp_path))
    assert code == 0
    assert out.exists() and out.stat().st_size > 0


def test_export_timeline_text(tmp_path: Path, capsys) -> None:
    _populate(tmp_path)
    args = _parser().parse_args(["export", "timeline", "--session", "cli1"])
    code = run_export(args, _config(tmp_path))
    captured = capsys.readouterr()
    assert code == 0
    assert "ssh" in captured.out.lower()


def test_export_list(tmp_path: Path, capsys) -> None:
    _populate(tmp_path)
    args = _parser().parse_args(["export", "list"])
    code = run_export(args, _config(tmp_path))
    captured = capsys.readouterr()
    assert code == 0
    assert "cli1" in captured.out


def test_export_pcap_no_match_returns_error(tmp_path: Path, capsys) -> None:
    _populate(tmp_path)
    out = tmp_path / "y.pcap"
    args = _parser().parse_args(["export", "pcap", "--session", "missing", "--out", str(out)])
    code = run_export(args, _config(tmp_path))
    assert code == 1


def test_export_stix_writes_bundle(tmp_path: Path, capsys) -> None:
    """``export stix`` produces a valid STIX 2.1 JSON bundle."""
    import json as _json

    _populate(tmp_path)
    out = tmp_path / "bundle.json"
    args = _parser().parse_args(
        ["export", "stix", "--session", "cli1", "--out", str(out), "--pretty"]
    )
    code = run_export(args, _config(tmp_path))
    assert code == 0
    data = _json.loads(out.read_text(encoding="utf-8"))
    assert data["type"] == "bundle"
    assert data["id"].startswith("bundle--")
    types = {obj["type"] for obj in data["objects"]}
    assert {"identity", "infrastructure", "campaign"}.issubset(types)


def test_export_stix_no_match_returns_error(tmp_path: Path, capsys) -> None:
    _populate(tmp_path)
    out = tmp_path / "bundle.json"
    args = _parser().parse_args(
        ["export", "stix", "--session", "nope", "--out", str(out)]
    )
    code = run_export(args, _config(tmp_path))
    assert code == 1
