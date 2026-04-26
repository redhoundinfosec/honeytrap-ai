"""``honeytrap sinks`` CLI subcommands.

Two commands are exposed:

* ``honeytrap sinks test <name>`` -- send a synthetic event through
  the configured pipeline so an operator can confirm a fresh sink is
  reachable.
* ``honeytrap sinks health`` -- print a JSON status block for every
  configured sink.

Both commands read sink configuration from the active honeytrap
config; nothing requires the engine to be running.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from honeytrap.core.config import Config
from honeytrap.sinks import (
    LogPipeline,
    OverflowPolicy,
    Sink,
    build_sink,
)

logger = logging.getLogger(__name__)


def build_sinks_parser(subparsers: argparse._SubParsersAction[Any]) -> None:
    """Register the ``sinks`` subcommand group."""
    sinks_cmd = subparsers.add_parser(
        "sinks",
        help="Test or inspect configured SIEM sinks.",
    )
    sinks_sub = sinks_cmd.add_subparsers(dest="sinks_command", required=True)

    test_cmd = sinks_sub.add_parser(
        "test",
        help="Send a synthetic event through a single configured sink.",
    )
    test_cmd.add_argument("name", help="Name of the configured sink to exercise.")

    health_cmd = sinks_sub.add_parser(
        "health",
        help="Print sink health (state, last error, queue depth, dropped count).",
    )
    health_cmd.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit JSON instead of a table.",
    )


def _collect_sinks(cfg: Config) -> list[Sink]:
    """Build :class:`Sink` instances from the config's targets list."""
    sinks: list[Sink] = []
    for spec in cfg.sinks.targets:
        try:
            sinks.append(build_sink(spec))
        except (ValueError, TypeError) as exc:
            logger.error("Skipping invalid sink %r: %s", spec, exc)
    return sinks


def _build_pipeline(cfg: Config, sinks: list[Sink]) -> LogPipeline:
    """Construct the pipeline matching the config's overflow policy."""
    overflow_raw = cfg.sinks.on_overflow or "drop_oldest"
    try:
        overflow = OverflowPolicy(overflow_raw)
    except ValueError:
        overflow = OverflowPolicy.DROP_OLDEST
    pipeline = LogPipeline(
        capacity=int(cfg.sinks.queue_capacity or 10_000),
        overflow=overflow,
    )
    for sink in sinks:
        pipeline.add_sink(sink)
    return pipeline


def _synthetic_event() -> dict[str, Any]:
    """Return a deterministic synthetic event used by ``sinks test``."""
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "kind": "synthetic_test",
        "session_id": "synthetic-0",
        "protocol": "test",
        "source_ip": "203.0.113.99",
        "source_port": 12345,
        "dest_ip": "198.51.100.1",
        "dest_port": 22,
        "bytes_in": 0,
        "bytes_out": 0,
        "action": "synthetic event from honeytrap sinks test",
    }


def run_sinks_command(args: argparse.Namespace, cfg: Config) -> int:
    """Dispatch the ``sinks`` subcommand. Returns an exit code."""
    cmd = getattr(args, "sinks_command", None)
    if cmd == "test":
        return _cmd_test(args, cfg)
    if cmd == "health":
        return _cmd_health(args, cfg)
    print("usage: honeytrap sinks {test,health}", file=sys.stderr)
    return 2


def _cmd_test(args: argparse.Namespace, cfg: Config) -> int:
    """Implementation of ``honeytrap sinks test <name>``."""
    sinks = _collect_sinks(cfg)
    target = next((s for s in sinks if s.name == args.name), None)
    if target is None:
        names = ", ".join(s.name for s in sinks) or "<none configured>"
        print(f"No sink named {args.name!r} (configured: {names})", file=sys.stderr)
        return 1
    event = _synthetic_event()

    async def _run() -> int:
        try:
            await target.send_batch([event])
        except Exception as exc:  # noqa: BLE001 -- surface to operator
            print(f"sink {target.name} failed: {exc}", file=sys.stderr)
            return 1
        finally:
            await target.shutdown()
        print(f"sink {target.name}: ok")
        return 0

    return asyncio.run(_run())


def _cmd_health(args: argparse.Namespace, cfg: Config) -> int:
    """Implementation of ``honeytrap sinks health``."""
    sinks = _collect_sinks(cfg)
    pipeline = _build_pipeline(cfg, sinks)

    async def _run() -> list[dict[str, Any]]:
        rows = await pipeline.health()
        return [
            {
                "name": h.name,
                "state": h.state,
                "last_error": h.last_error,
                "queue_depth": h.queue_depth,
                "dropped_total": h.dropped_total,
                "sent_total": h.sent_total,
            }
            for h in rows
        ]

    snapshot = asyncio.run(_run())
    if getattr(args, "as_json", False) or not snapshot:
        print(json.dumps({"sinks": snapshot}, indent=2, sort_keys=True))
        return 0
    width = max(len(row["name"]) for row in snapshot)
    print(f"{'NAME'.ljust(width)}  STATE        QUEUE  DROPPED  SENT")
    for row in snapshot:
        print(
            f"{row['name'].ljust(width)}  "
            f"{row['state']:<11}  "
            f"{row['queue_depth']:>5}  "
            f"{row['dropped_total']:>7}  "
            f"{row['sent_total']:>5}"
        )
    return 0
