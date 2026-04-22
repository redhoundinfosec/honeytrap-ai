"""Chronological timeline reconstruction for replay and reporting.

A :class:`Timeline` merges recorded :class:`SessionFrame` data with
optional intel context (ATT&CK techniques, IOCs, TLS fingerprints) into
an ordered sequence of :class:`TimelineEntry` objects an analyst can
read top-to-bottom. The same entries power the TUI replay tab, the HTML
per-session pages, and the ``honeytrap export timeline`` CLI command.

Credentials surfaced in the human-readable description are redacted by
default. The underlying frame payload remains untouched so a forensic
PCAP export still contains the full bytes the attacker sent.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from honeytrap.forensics.recorder import (
    Direction,
    SessionFrame,
    SessionMetadata,
    SessionStore,
)

# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


class TimelineKind(str, Enum):
    """Categorical tags for timeline entries."""

    CONNECT = "connect"
    AUTH_ATTEMPT = "auth_attempt"
    COMMAND = "command"
    FILE_TRANSFER = "file_transfer"
    TLS_HANDSHAKE = "tls_handshake"
    PAYLOAD_IN = "payload_in"
    PAYLOAD_OUT = "payload_out"
    DISCONNECT = "disconnect"


_PREVIEW_BYTES_DEFAULT = 96
_REDACTION = "[REDACTED]"

_CREDENTIAL_LINE_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|authorization)\s*[:=]\s*\S+"
)
_BASIC_AUTH_RE = re.compile(r"(?i)(Authorization:\s*Basic\s+)\S+")
_USER_PASS_PAIR_RE = re.compile(r"(?i)(USER\s+\S+\s+PASS\s+)\S+")


@dataclass
class TimelineEntry:
    """A single chronological event."""

    timestamp: datetime
    kind: TimelineKind
    description: str
    direction: Direction
    raw_preview: bytes
    raw_full_size: int
    session_id: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    intel: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "kind": self.kind.value,
            "description": self.description,
            "direction": self.direction.value,
            "raw_preview_hex": self.raw_preview.hex(),
            "raw_full_size": int(self.raw_full_size),
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "source_port": int(self.source_port),
            "dest_ip": self.dest_ip,
            "dest_port": int(self.dest_port),
            "protocol": self.protocol,
            "intel": dict(self.intel),
        }


# ---------------------------------------------------------------------------
# Timeline factory
# ---------------------------------------------------------------------------


@dataclass
class Timeline:
    """An ordered set of :class:`TimelineEntry` records."""

    entries: list[TimelineEntry]
    sessions: list[SessionMetadata]

    # -- factories -----------------------------------------------------
    @classmethod
    def for_session(
        cls,
        store: SessionStore,
        session_id: str,
        *,
        intel_lookup: Any = None,
        preview_bytes: int = _PREVIEW_BYTES_DEFAULT,
        redact: bool = True,
    ) -> Timeline:
        """Build a timeline for a single session id."""
        meta = store.get_metadata(session_id)
        frames = store.load_frames(session_id)
        entries: list[TimelineEntry] = []
        if meta is not None:
            entries.append(_make_connect_entry(meta))
            entries.extend(
                _entries_from_frames(
                    meta,
                    frames,
                    intel_lookup=intel_lookup,
                    preview_bytes=preview_bytes,
                    redact=redact,
                )
            )
            entries.append(_make_disconnect_entry(meta, frames))
        return cls(entries=entries, sessions=[meta] if meta else [])

    @classmethod
    def for_sessions(
        cls,
        store: SessionStore,
        session_ids: Iterable[str],
        *,
        intel_lookup: Any = None,
        preview_bytes: int = _PREVIEW_BYTES_DEFAULT,
        redact: bool = True,
    ) -> Timeline:
        """Merge multiple sessions into one chronological list."""
        all_entries: list[TimelineEntry] = []
        sessions: list[SessionMetadata] = []
        for sid in session_ids:
            sub = cls.for_session(
                store,
                sid,
                intel_lookup=intel_lookup,
                preview_bytes=preview_bytes,
                redact=redact,
            )
            all_entries.extend(sub.entries)
            sessions.extend(sub.sessions)
        all_entries.sort(key=lambda e: e.timestamp)
        return cls(entries=all_entries, sessions=sessions)

    @classmethod
    def for_ip(
        cls,
        store: SessionStore,
        ip: str,
        *,
        intel_lookup: Any = None,
        preview_bytes: int = _PREVIEW_BYTES_DEFAULT,
        redact: bool = True,
    ) -> Timeline:
        """Build a campaign-style timeline from every session for one IP."""
        sessions = store.list_sessions(ip=ip)
        return cls.for_sessions(
            store,
            [s.session_id for s in sessions],
            intel_lookup=intel_lookup,
            preview_bytes=preview_bytes,
            redact=redact,
        )

    # -- filters -------------------------------------------------------
    def filter(
        self,
        *,
        direction: Direction | None = None,
        kind: TimelineKind | None = None,
        substring: str | None = None,
        min_size: int | None = None,
        max_size: int | None = None,
    ) -> Timeline:
        """Return a new Timeline with entries matching every filter."""
        sub_text = substring.lower() if substring else None

        def keep(entry: TimelineEntry) -> bool:
            if direction is not None and entry.direction is not direction:
                return False
            if kind is not None and entry.kind is not kind:
                return False
            if sub_text is not None:
                hay = " ".join(
                    [
                        entry.description.lower(),
                        entry.raw_preview.decode("utf-8", "replace").lower(),
                    ]
                )
                if sub_text not in hay:
                    return False
            if min_size is not None and entry.raw_full_size < min_size:
                return False
            return not (max_size is not None and entry.raw_full_size > max_size)

        return Timeline(entries=[e for e in self.entries if keep(e)], sessions=self.sessions)

    # -- output --------------------------------------------------------
    def to_text(self) -> str:
        """Render the timeline as a plain-text outline."""
        lines: list[str] = []
        for entry in self.entries:
            ts = entry.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            arrow = "->" if entry.direction is Direction.INBOUND else "<-"
            lines.append(
                f"{ts}  {entry.kind.value:<14} {arrow} {entry.protocol:<6} "
                f"{entry.source_ip:>15}:{entry.source_port:<5}  {entry.description}"
            )
        return "\n".join(lines)

    def to_json(self) -> list[dict[str, Any]]:
        """Render as a JSON-serializable list."""
        return [entry.to_dict() for entry in self.entries]

    def to_html(self, *, title: str = "Session Timeline") -> str:
        """Render as a self-contained dark-theme HTML page."""
        from html import escape

        body_lines: list[str] = []
        for entry in self.entries:
            ts = entry.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            hex_lines = _hexdump_lines(entry.raw_preview)
            preview = "\n".join(hex_lines)
            body_lines.append(
                "<details class='entry' "
                f"data-kind='{escape(entry.kind.value)}'>\n"
                f"  <summary><span class='ts'>{escape(ts)}</span> "
                f"<span class='kind kind-{escape(entry.kind.value)}'>{escape(entry.kind.value)}</span> "
                f"<span class='dir'>{escape(entry.direction.value)}</span> "
                f"<span class='desc'>{escape(entry.description)}</span></summary>\n"
                f"  <pre class='hex'>{escape(preview)}</pre>\n"
                "</details>"
            )
        return _HTML_TEMPLATE.format(
            title=escape(title),
            count=len(self.entries),
            body="\n".join(body_lines),
        )

    def kind_counts(self) -> dict[str, int]:
        """Return ``{kind: count}`` over the timeline."""
        result: dict[str, int] = {}
        for entry in self.entries:
            result[entry.kind.value] = result.get(entry.kind.value, 0) + 1
        return result


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _make_connect_entry(meta: SessionMetadata) -> TimelineEntry:
    """Synthesize a ``CONNECT`` row from session metadata."""
    return TimelineEntry(
        timestamp=meta.started_at,
        kind=TimelineKind.CONNECT,
        description=(
            f"{meta.protocol.upper()} connection from "
            f"{meta.remote_ip}:{meta.remote_port} -> {meta.local_ip}:{meta.local_port}"
        ),
        direction=Direction.INBOUND,
        raw_preview=b"",
        raw_full_size=0,
        session_id=meta.session_id,
        source_ip=meta.remote_ip,
        source_port=meta.remote_port,
        dest_ip=meta.local_ip,
        dest_port=meta.local_port,
        protocol=meta.protocol,
    )


def _make_disconnect_entry(meta: SessionMetadata, frames: list[SessionFrame]) -> TimelineEntry:
    """Synthesize a ``DISCONNECT`` row at the close timestamp."""
    if meta.ended_at is not None:
        ts = meta.ended_at
    elif frames:
        ts = datetime.fromtimestamp(frames[-1].timestamp_ns / 1_000_000_000, timezone.utc)
    else:
        ts = meta.started_at
    return TimelineEntry(
        timestamp=ts,
        kind=TimelineKind.DISCONNECT,
        description=(
            f"{meta.protocol.upper()} disconnect after {meta.frame_count} frames "
            f"({meta.bytes_in} in / {meta.bytes_out} out)"
        ),
        direction=Direction.OUTBOUND,
        raw_preview=b"",
        raw_full_size=0,
        session_id=meta.session_id,
        source_ip=meta.local_ip,
        source_port=meta.local_port,
        dest_ip=meta.remote_ip,
        dest_port=meta.remote_port,
        protocol=meta.protocol,
    )


def _entries_from_frames(
    meta: SessionMetadata,
    frames: list[SessionFrame],
    *,
    intel_lookup: Any,
    preview_bytes: int,
    redact: bool,
) -> list[TimelineEntry]:
    """Convert each frame into a categorized timeline entry."""
    entries: list[TimelineEntry] = []
    for frame in frames:
        ts = datetime.fromtimestamp(frame.timestamp_ns / 1_000_000_000, timezone.utc)
        kind = _classify_frame(frame, meta)
        description = _describe_frame(frame, meta, kind, redact=redact)
        intel: dict[str, Any] = {}
        if intel_lookup is not None:
            try:
                intel = dict(intel_lookup(frame, meta) or {})
            except Exception:  # noqa: BLE001 — never fail the timeline
                intel = {}
        entries.append(
            TimelineEntry(
                timestamp=ts,
                kind=kind,
                description=description,
                direction=frame.direction,
                raw_preview=frame.payload[:preview_bytes],
                raw_full_size=len(frame.payload),
                session_id=frame.session_id,
                source_ip=frame.source_ip,
                source_port=frame.source_port,
                dest_ip=frame.dest_ip,
                dest_port=frame.dest_port,
                protocol=frame.protocol or meta.protocol,
                intel=intel,
            )
        )
    return entries


def _classify_frame(frame: SessionFrame, meta: SessionMetadata) -> TimelineKind:
    """Bucket a frame into a high-level category for the timeline."""
    if frame.is_tls_handshake:
        return TimelineKind.TLS_HANDSHAKE
    text = frame.payload[:512].decode("utf-8", "replace").lower()
    if any(token in text for token in ("user ", "pass ", "login", "password", "auth ")):
        return TimelineKind.AUTH_ATTEMPT
    if any(token in text for token in ("retr ", "stor ", "get /", "put /", "post /")):
        if "http" in (frame.protocol or "").lower() and "get /" in text:
            return TimelineKind.COMMAND
        return TimelineKind.FILE_TRANSFER
    if frame.direction is Direction.INBOUND and text.strip():
        return TimelineKind.COMMAND if " " not in text[:10] else TimelineKind.PAYLOAD_IN
    if frame.direction is Direction.INBOUND:
        return TimelineKind.PAYLOAD_IN
    return TimelineKind.PAYLOAD_OUT


def _describe_frame(
    frame: SessionFrame,
    meta: SessionMetadata,
    kind: TimelineKind,
    *,
    redact: bool,
) -> str:
    """Return a short human-readable description for an entry."""
    raw = frame.payload[:512].decode("utf-8", "replace")
    raw = raw.replace("\r", "\\r").replace("\n", "\\n").strip()
    if redact:
        raw = _redact_secrets(raw)
    if not raw:
        return f"{len(frame.payload)} bytes"
    if len(raw) > 160:
        raw = raw[:157] + "..."
    label_map = {
        TimelineKind.AUTH_ATTEMPT: "auth",
        TimelineKind.COMMAND: "cmd",
        TimelineKind.FILE_TRANSFER: "xfer",
        TimelineKind.TLS_HANDSHAKE: "tls",
        TimelineKind.PAYLOAD_IN: "in",
        TimelineKind.PAYLOAD_OUT: "out",
    }
    label = label_map.get(kind, "frame")
    return f"{label}({len(frame.payload)}b): {raw}"


def _redact_secrets(text: str) -> str:
    """Strip likely-credential substrings from a description line."""
    text = _CREDENTIAL_LINE_RE.sub(lambda m: f"{m.group(1)}={_REDACTION}", text)
    text = _BASIC_AUTH_RE.sub(lambda m: f"{m.group(1)}{_REDACTION}", text)
    text = _USER_PASS_PAIR_RE.sub(lambda m: f"{m.group(1)}{_REDACTION}", text)
    return text


def _hexdump_lines(data: bytes, width: int = 16) -> list[str]:
    """Return ``offset  hex  ascii`` lines for a hex dump."""
    if not data:
        return ["(empty)"]
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}} {ascii_part}")
    return lines


# ---------------------------------------------------------------------------
# HTML template (dark theme, no external assets)
# ---------------------------------------------------------------------------


_HTML_TEMPLATE = """<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>{title}</title>
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family:ui-monospace,Menlo,monospace; padding:1.5rem; }}
  h1 {{ color:#f0f6fc; margin-top:0; }}
  details {{ background:#161b22; border:1px solid #30363d; padding:.5rem .75rem;
            margin:.4rem 0; border-radius:6px; }}
  summary {{ cursor:pointer; }}
  .ts {{ color:#8b949e; }}
  .kind {{ display:inline-block; padding:.05rem .35rem; margin:0 .35rem; border-radius:4px;
          background:#21262d; color:#79c0ff; font-size:.85em; }}
  .kind-auth_attempt {{ color:#f97583; }}
  .kind-command {{ color:#79c0ff; }}
  .kind-tls_handshake {{ color:#d2a8ff; }}
  .kind-file_transfer {{ color:#7ee787; }}
  .dir {{ color:#8b949e; font-size:.8em; }}
  .desc {{ color:#c9d1d9; }}
  pre.hex {{ color:#8b949e; background:#0a0e14; padding:.5rem;
            border-radius:4px; overflow-x:auto; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class='meta'>{count} timeline entries</p>
{body}
</body>
</html>
"""
