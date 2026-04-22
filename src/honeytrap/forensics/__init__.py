"""Forensic recording, replay, and export for HoneyTrap AI sessions.

The forensics subsystem captures byte-accurate session frames as they
flow through the engine, persists them to a pluggable store (JSONL or
SQLite), and exposes export pipelines for PCAP, JSONL, and chronological
HTML/JSON timelines.

Public surface:

* :class:`SessionRecorder` -- attaches to the event bus and writes frames.
* :class:`SessionFrame` -- the in-memory representation of a single
  inbound or outbound chunk on the wire.
* :class:`SessionStore` (ABC), :class:`JsonlSessionStore`,
  :class:`SqliteSessionStore` -- persistence backends.
* :class:`PcapWriter` -- libpcap-format export with synthesized TCP/IP.
* :class:`Timeline` -- chronological reconstruction with intel attached.
"""

from __future__ import annotations

from honeytrap.forensics.pcap import PcapWriter, SessionFlow, write_pcap
from honeytrap.forensics.recorder import (
    Direction,
    ForensicsConfig,
    JsonlSessionStore,
    SessionFrame,
    SessionMetadata,
    SessionRecorder,
    SessionStore,
    SqliteSessionStore,
)
from honeytrap.forensics.timeline import Timeline, TimelineEntry, TimelineKind

__all__ = [
    "Direction",
    "ForensicsConfig",
    "JsonlSessionStore",
    "PcapWriter",
    "SessionFlow",
    "SessionFrame",
    "SessionMetadata",
    "SessionRecorder",
    "SessionStore",
    "SqliteSessionStore",
    "Timeline",
    "TimelineEntry",
    "TimelineKind",
    "write_pcap",
]
