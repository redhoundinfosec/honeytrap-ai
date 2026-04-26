"""Implementation backing ``honeytrap export ...`` subcommands.

The :func:`build_export_parser` helper attaches the ``export`` group to
an existing :class:`argparse.ArgumentParser`. Each subcommand returns
an integer exit code so the top-level CLI just forwards it.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from honeytrap.core.config import Config
from honeytrap.forensics.pcap import SessionFlow, write_pcap
from honeytrap.forensics.recorder import (
    JsonlSessionStore,
    SessionMetadata,
    SessionStore,
    SqliteSessionStore,
    serialize_jsonl,
)
from honeytrap.forensics.timeline import Timeline

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def build_export_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``export`` subcommand group on ``subparsers``."""
    export_cmd = subparsers.add_parser(
        "export",
        help="Export recorded sessions to PCAP / JSONL / timeline formats.",
    )
    export_sub = export_cmd.add_subparsers(dest="export_command", required=True)

    pcap = export_sub.add_parser("pcap", help="Write a PCAP-lite file.")
    _attach_filters(pcap)
    pcap.add_argument("--out", required=True, help="Output .pcap path.")

    jsonl = export_sub.add_parser("jsonl", help="Write a gzipped JSONL session file.")
    _attach_filters(jsonl)
    jsonl.add_argument("--out", required=True, help="Output .jsonl.gz path.")
    jsonl.add_argument(
        "--redact",
        action="store_true",
        help="Strip credentials from descriptions (raw bytes preserved in payload).",
    )

    timeline = export_sub.add_parser("timeline", help="Write a chronological timeline.")
    timeline.add_argument("--session", required=True, help="Session id to render.")
    timeline.add_argument("--format", choices=["text", "html", "json"], default="text")
    timeline.add_argument("--out", help="Output path; stdout if omitted.")
    timeline.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable credential redaction in the output.",
    )

    listing = export_sub.add_parser("list", help="List recorded sessions.")
    listing.add_argument("--ip", help="Filter by remote IP.")
    listing.add_argument("--since", help="ISO timestamp lower bound (inclusive).")
    listing.add_argument("--until", help="ISO timestamp upper bound (inclusive).")

    stix = export_sub.add_parser("stix", help="Export a STIX 2.1 bundle.")
    stix.add_argument("--session", help="Session id to bundle.")
    stix.add_argument("--ip", help="Filter sessions by attacker IP.")
    stix.add_argument("--since", help="ISO timestamp lower bound (inclusive).")
    stix.add_argument("--until", help="ISO timestamp upper bound (inclusive).")
    stix.add_argument(
        "--out",
        required=True,
        help="Output path for the STIX 2.1 JSON bundle.",
    )
    stix.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON (default is compact).",
    )


def _attach_filters(parser: argparse.ArgumentParser) -> None:
    """Add the shared session/ip/since/until filter flags."""
    parser.add_argument("--session", help="Specific session id.")
    parser.add_argument("--ip", help="Filter by attacker IP.")
    parser.add_argument("--since", help="ISO timestamp lower bound.")
    parser.add_argument("--until", help="ISO timestamp upper bound.")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def open_store(cfg: Config) -> SessionStore:
    """Open the configured session store. Caller closes."""
    forensics = cfg.forensics
    root = Path(forensics.path)
    if not root.is_absolute():
        root = Path(cfg.general.log_directory) / root.name
    if forensics.store == "sqlite":
        return SqliteSessionStore(root / "sessions.db")
    root.mkdir(parents=True, exist_ok=True)
    return JsonlSessionStore(root)


def run_export(args: argparse.Namespace, cfg: Config) -> int:
    """Execute the chosen ``export`` subcommand. Returns an exit code."""
    cmd = getattr(args, "export_command", None)
    if cmd is None:  # pragma: no cover — argparse enforces required
        return 2
    store = open_store(cfg)
    try:
        if cmd == "pcap":
            return _cmd_pcap(args, cfg, store)
        if cmd == "jsonl":
            return _cmd_jsonl(args, cfg, store)
        if cmd == "timeline":
            return _cmd_timeline(args, cfg, store)
        if cmd == "list":
            return _cmd_list(args, cfg, store)
        if cmd == "stix":
            return _cmd_stix(args, cfg, store)
    finally:
        store.close()
    return 2


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _cmd_pcap(args: argparse.Namespace, cfg: Config, store: SessionStore) -> int:
    flows = _collect_flows(args, store)
    if not flows:
        sys.stderr.write("No matching sessions found.\n")
        return 1
    out = Path(args.out)
    write_pcap(out, flows)
    print(f"PCAP written to {out} ({len(flows)} sessions)")
    return 0


def _cmd_jsonl(args: argparse.Namespace, cfg: Config, store: SessionStore) -> int:
    flows = _collect_flows(args, store)
    if not flows:
        sys.stderr.write("No matching sessions found.\n")
        return 1
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if len(flows) == 1:
        out.write_bytes(serialize_jsonl(flows[0].metadata, flows[0].frames))
    else:
        # Concatenate gzipped streams: gzip is concatenation-safe, the
        # readers will yield each stream end-to-end.
        with out.open("wb") as fh:
            for flow in flows:
                fh.write(serialize_jsonl(flow.metadata, flow.frames))
    print(f"JSONL written to {out} ({len(flows)} sessions)")
    return 0


def _cmd_timeline(args: argparse.Namespace, cfg: Config, store: SessionStore) -> int:
    redact = not getattr(args, "no_redact", False)
    timeline = Timeline.for_session(store, args.session, redact=redact)
    if not timeline.entries:
        sys.stderr.write(f"Session {args.session!r} not found.\n")
        return 1
    if args.format == "json":
        rendered = json.dumps(timeline.to_json(), indent=2)
    elif args.format == "html":
        rendered = timeline.to_html(title=f"Session {args.session}")
    else:
        rendered = timeline.to_text()
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(f"Timeline written to {out}")
    else:
        print(rendered)
    return 0


def _cmd_list(args: argparse.Namespace, cfg: Config, store: SessionStore) -> int:
    since = _parse_iso(args.since) if args.since else None
    until = _parse_iso(args.until) if args.until else None
    sessions = store.list_sessions(ip=args.ip, since=since, until=until)
    console = Console()
    table = Table(title="Recorded sessions")
    table.add_column("Session")
    table.add_column("Protocol")
    table.add_column("Remote IP")
    table.add_column("Started")
    table.add_column("Frames", justify="right")
    table.add_column("Bytes (in/out)", justify="right")
    table.add_column("Truncated")
    for s in sessions:
        table.add_row(
            s.session_id,
            s.protocol,
            s.remote_ip,
            s.started_at.isoformat(timespec="seconds"),
            str(s.frame_count),
            f"{s.bytes_in}/{s.bytes_out}",
            "yes" if s.truncated else "no",
        )
    console.print(table)
    return 0 if sessions else 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cmd_stix(args: argparse.Namespace, cfg: Config, store: SessionStore) -> int:
    """Build and persist a STIX 2.1 bundle from session metadata."""
    del cfg  # not currently consulted
    from honeytrap.api.taxii import build_bundle_from_service
    from honeytrap.intel.stix.serializer import dump_compact, dump_pretty

    if args.session:
        meta = store.get_metadata(args.session)
        sessions = [meta] if meta is not None else []
    else:
        since = _parse_iso(args.since) if args.since else None
        until = _parse_iso(args.until) if args.until else None
        sessions = store.list_sessions(ip=args.ip, since=since, until=until)
    if not sessions:
        sys.stderr.write("No matching sessions found.\n")
        return 1
    session_dicts = [
        {
            "session_id": s.session_id,
            "protocol": s.protocol,
            "remote_ip": s.remote_ip,
            "remote_port": s.remote_port,
            "local_port": s.local_port,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "ended_at": s.ended_at.isoformat() if s.ended_at else None,
            "bytes_in": s.bytes_in,
            "bytes_out": s.bytes_out,
        }
        for s in sessions
    ]
    builder = build_bundle_from_service(sessions=session_dicts)
    bundle = builder.build()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    rendered = dump_pretty(bundle) if getattr(args, "pretty", False) else dump_compact(bundle)
    out.write_text(rendered, encoding="utf-8")
    print(f"STIX 2.1 bundle written to {out} ({len(bundle['objects'])} objects)")
    return 0


def _collect_flows(args: argparse.Namespace, store: SessionStore) -> list[SessionFlow]:
    """Resolve the filter flags into a concrete set of session flows."""
    sessions: list[SessionMetadata] = []
    if args.session:
        meta = store.get_metadata(args.session)
        if meta is not None:
            sessions = [meta]
    else:
        since = _parse_iso(args.since) if args.since else None
        until = _parse_iso(args.until) if args.until else None
        sessions = store.list_sessions(ip=args.ip, since=since, until=until)
    flows: list[SessionFlow] = []
    for meta in sessions:
        frames = store.load_frames(meta.session_id)
        flows.append(SessionFlow(metadata=meta, frames=frames))
    return flows


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 string. Falls back to a naive UTC interpretation."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:  # pragma: no cover — surfaced to user
        raise argparse.ArgumentTypeError(f"invalid ISO timestamp: {value}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
