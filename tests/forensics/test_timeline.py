"""Timeline reconstruction coverage."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from honeytrap.forensics.recorder import (
    Direction,
    JsonlSessionStore,
    SessionFrame,
    SessionMetadata,
)
from honeytrap.forensics.timeline import Timeline, TimelineKind, _redact_secrets


def _populate(tmp_path: Path) -> JsonlSessionStore:
    store = JsonlSessionStore(tmp_path)
    meta = SessionMetadata(
        session_id="ssh-1",
        protocol="ssh",
        remote_ip="1.1.1.1",
        remote_port=2222,
        local_ip="10.0.0.1",
        local_port=22,
        started_at=datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc),
    )
    store.open_session(meta)
    base_ns = int(meta.started_at.timestamp() * 1_000_000_000)
    store.append_frame(
        SessionFrame(
            session_id="ssh-1",
            timestamp_ns=base_ns + 1000,
            direction=Direction.INBOUND,
            payload=b"USER admin\r\n",
            source_ip="1.1.1.1",
            source_port=2222,
            dest_ip="10.0.0.1",
            dest_port=22,
            protocol="ssh",
        )
    )
    store.append_frame(
        SessionFrame(
            session_id="ssh-1",
            timestamp_ns=base_ns + 2000,
            direction=Direction.INBOUND,
            payload=b"password=hunter2\r\n",
            source_ip="1.1.1.1",
            source_port=2222,
            dest_ip="10.0.0.1",
            dest_port=22,
            protocol="ssh",
        )
    )
    store.append_frame(
        SessionFrame(
            session_id="ssh-1",
            timestamp_ns=base_ns + 3000,
            direction=Direction.OUTBOUND,
            payload=b"banner OK\r\n",
            source_ip="10.0.0.1",
            source_port=22,
            dest_ip="1.1.1.1",
            dest_port=2222,
            protocol="ssh",
        )
    )
    meta.ended_at = datetime(2026, 4, 22, 12, 1, tzinfo=timezone.utc)
    meta.frame_count = 3
    meta.bytes_in = 28
    meta.bytes_out = 11
    store.close_session(meta)
    return store


def test_for_session_includes_connect_and_disconnect(tmp_path: Path) -> None:
    store = _populate(tmp_path)
    tl = Timeline.for_session(store, "ssh-1")
    kinds = [e.kind for e in tl.entries]
    assert kinds[0] is TimelineKind.CONNECT
    assert kinds[-1] is TimelineKind.DISCONNECT
    store.close()


def test_redact_default_strips_password(tmp_path: Path) -> None:
    store = _populate(tmp_path)
    tl = Timeline.for_session(store, "ssh-1", redact=True)
    body = tl.to_text()
    assert "hunter2" not in body
    assert "[REDACTED]" in body
    store.close()


def test_no_redact_keeps_password(tmp_path: Path) -> None:
    store = _populate(tmp_path)
    tl = Timeline.for_session(store, "ssh-1", redact=False)
    body = tl.to_text()
    assert "hunter2" in body
    store.close()


def test_redact_helper_handles_authorization_header() -> None:
    out = _redact_secrets("Authorization: Basic dXNlcjpwYXNz")
    # The credential-line and basic-auth regexes both fire; the secret is
    # neutralized either way.
    assert "[REDACTED]" in out


def test_redact_helper_handles_user_pass_pair() -> None:
    out = _redact_secrets("USER alice PASS hunter2")
    assert "hunter2" not in out
    assert "[REDACTED]" in out


def test_for_ip_aggregates_sessions(tmp_path: Path) -> None:
    store = _populate(tmp_path)
    tl = Timeline.for_ip(store, "1.1.1.1")
    assert tl.entries
    assert all(e.session_id == "ssh-1" for e in tl.entries)
    store.close()


def test_filter_by_direction_and_substring(tmp_path: Path) -> None:
    store = _populate(tmp_path)
    tl = Timeline.for_session(store, "ssh-1", redact=False)
    only_in = tl.filter(direction=Direction.INBOUND)
    assert all(
        e.direction is Direction.INBOUND
        for e in only_in.entries
        if e.kind not in {TimelineKind.CONNECT, TimelineKind.DISCONNECT}
    )
    matched = tl.filter(substring="admin")
    assert any("admin" in e.description for e in matched.entries)
    store.close()


def test_to_json_and_to_html(tmp_path: Path) -> None:
    store = _populate(tmp_path)
    tl = Timeline.for_session(store, "ssh-1")
    js = tl.to_json()
    assert isinstance(js, list) and js
    payload = json.dumps(js)
    assert "ssh-1" in payload
    html = tl.to_html(title="ssh-1")
    assert "<html" in html.lower() and "ssh-1" in html
    store.close()


def test_kind_counts_returns_distribution(tmp_path: Path) -> None:
    store = _populate(tmp_path)
    tl = Timeline.for_session(store, "ssh-1")
    counts = tl.kind_counts()
    assert counts.get(TimelineKind.CONNECT.value) == 1
    assert counts.get(TimelineKind.DISCONNECT.value) == 1
    store.close()
