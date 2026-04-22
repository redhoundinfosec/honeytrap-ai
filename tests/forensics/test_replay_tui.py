"""Replay-tab helper coverage. Avoids spinning up a Textual app."""

from __future__ import annotations

from pathlib import Path

import pytest

from honeytrap.forensics.recorder import Direction, SessionFrame

# The TUI imports textual; skip if it is not available.
textual = pytest.importorskip("textual")
from honeytrap.ui.dashboard_tui import SessionDetailModal  # noqa: E402


def _frames(n: int = 3) -> list[SessionFrame]:
    return [
        SessionFrame(
            session_id="s",
            timestamp_ns=1_700_000_000_000_000_000 + i * 1_000_000,
            direction=Direction.INBOUND if i % 2 == 0 else Direction.OUTBOUND,
            payload=b"ABCD" * (i + 1),
            source_ip="1.1.1.1",
            source_port=2222,
            dest_ip="10.0.0.1",
            dest_port=22,
            protocol="ssh",
        )
        for i in range(n)
    ]


def test_modal_replay_status_renders() -> None:
    modal = SessionDetailModal("s", events=[], replay_frames=_frames())
    text = modal._render_replay_status()
    assert "PAUSE" in text and "frame 1/3" in text


def test_modal_step_forward_advances_index() -> None:
    modal = SessionDetailModal("s", events=[], replay_frames=_frames())
    initial = modal._frame_index
    modal._frame_index = 1
    modal._render_replay_frame_list()  # smoke
    assert initial == 0


def test_modal_render_hex_for_payload() -> None:
    modal = SessionDetailModal("s", events=[], replay_frames=_frames())
    hex_text = modal._render_replay_hex()
    assert "41 42 43 44" in hex_text  # ABCD


def test_modal_export_jsonl_writes_file(tmp_path: Path) -> None:
    modal = SessionDetailModal("s", events=[], replay_frames=_frames(), export_dir=tmp_path)
    out = modal._export_session("jsonl")
    assert out is not None and out.exists()
    assert out.suffix == ".gz"


def test_modal_export_pcap_writes_file(tmp_path: Path) -> None:
    modal = SessionDetailModal("s", events=[], replay_frames=_frames(), export_dir=tmp_path)
    out = modal._export_session("pcap")
    assert out is not None and out.exists() and out.stat().st_size > 24


def test_modal_without_replay_frames_renders_nothing() -> None:
    modal = SessionDetailModal("s", events=[], replay_frames=None)
    assert modal._replay_frames == []
    assert modal._render_replay_frame_list() == "(no recorded frames)"
