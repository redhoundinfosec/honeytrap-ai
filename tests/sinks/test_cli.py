"""CLI tests for ``honeytrap sinks {test,health}``."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from honeytrap.core.config import Config
from honeytrap.sinks.cli import build_sinks_parser, run_sinks_command


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build_sinks_parser(sub)
    return parser


def _config_with_sink(tmp_path: Path) -> Config:
    cfg = Config()
    cfg.sinks.enabled = True
    cfg.sinks.targets = [
        {"type": "file_jsonl", "name": "fjsonl", "path": str(tmp_path)}
    ]
    return cfg


def test_sinks_test_round_trips_an_event(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _config_with_sink(tmp_path)
    args = _parser().parse_args(["sinks", "test", "fjsonl"])
    code = run_sinks_command(args, cfg)
    assert code == 0
    captured = capsys.readouterr()
    assert "fjsonl: ok" in captured.out
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    assert b"synthetic-0" in files[0].read_bytes()


def test_sinks_test_unknown_sink_returns_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _config_with_sink(tmp_path)
    args = _parser().parse_args(["sinks", "test", "nope"])
    code = run_sinks_command(args, cfg)
    assert code == 1
    captured = capsys.readouterr()
    assert "No sink named 'nope'" in captured.err


def test_sinks_health_emits_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _config_with_sink(tmp_path)
    args = _parser().parse_args(["sinks", "health", "--json"])
    code = run_sinks_command(args, cfg)
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "sinks" in payload
    names = {row["name"] for row in payload["sinks"]}
    assert "fjsonl" in names
