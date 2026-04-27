"""``honeytrap node`` and ``honeytrap controller`` CLI commands.

Two top-level subcommands are exposed by this module:

* ``honeytrap node`` -- node-side helpers (``register``, ``uplink-status``).
* ``honeytrap controller`` -- controller-side queries
  (``list-nodes``, ``list-events``, ``top-attackers``, ``mitre-heatmap``).

Each command is fully implemented as a small function so it can be
unit tested without spawning a process. The functions take an explicit
``console`` argument so test cases can capture Rich output.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.table import Table

from honeytrap.cluster.config import ClusterRole
from honeytrap.exceptions import ConfigError


def build_node_parser(
    subparsers: argparse._SubParsersAction[Any],
) -> None:
    """Register the ``node`` subcommand tree."""
    node_cmd = subparsers.add_parser(
        "node",
        help="Node-side cluster commands (register, uplink-status).",
    )
    node_sub = node_cmd.add_subparsers(dest="node_command", required=False)

    register = node_sub.add_parser("register", help="Write cluster section into a config file.")
    register.add_argument("--controller", required=True, help="Controller base URL.")
    register.add_argument("--api-key", required=True, help="Node API key (htk_...).")
    register.add_argument(
        "--config",
        default="honeytrap.yaml",
        help="Path to honeytrap.yaml (default: ./honeytrap.yaml).",
    )
    register.add_argument("--node-id", default=None, help="Optional stable node identifier.")
    register.add_argument("--tag", action="append", default=[], help="Repeatable tag.")
    register.add_argument(
        "--heartbeat-interval", type=float, default=30.0, help="Heartbeat seconds."
    )
    register.add_argument(
        "--no-tls-verify",
        dest="tls_verify",
        action="store_false",
        default=True,
        help="Skip TLS verification (debug only).",
    )

    status = node_sub.add_parser("uplink-status", help="Print uplink status from the local API.")
    status.add_argument(
        "--api",
        default="http://127.0.0.1:9300",
        help="Local management API base URL.",
    )
    status.add_argument("--api-key", required=True, help="Operator API key.")


def build_controller_parser(
    subparsers: argparse._SubParsersAction[Any],
) -> None:
    """Register the ``controller`` subcommand tree."""
    ctrl = subparsers.add_parser(
        "controller",
        help="Controller-side cluster queries.",
    )
    sub = ctrl.add_subparsers(dest="controller_command", required=False)

    common_kwargs = {"help": "Controller base URL."}
    list_nodes = sub.add_parser("list-nodes", help="Tabular list of nodes.")
    list_nodes.add_argument("--controller", default="http://127.0.0.1:9300", **common_kwargs)
    list_nodes.add_argument("--api-key", required=True)

    list_events = sub.add_parser("list-events", help="Recent events table.")
    list_events.add_argument("--controller", default="http://127.0.0.1:9300", **common_kwargs)
    list_events.add_argument("--api-key", required=True)
    list_events.add_argument("--since", default=None)
    list_events.add_argument("--until", default=None)
    list_events.add_argument("--protocol", default=None)
    list_events.add_argument("--src-ip", dest="src_ip", default=None)
    list_events.add_argument("--node-id", dest="node_id", default=None)
    list_events.add_argument("--limit", type=int, default=100)

    top = sub.add_parser("top-attackers", help="Top attacker IPs.")
    top.add_argument("--controller", default="http://127.0.0.1:9300", **common_kwargs)
    top.add_argument("--api-key", required=True)
    top.add_argument("--limit", type=int, default=20)

    heatmap = sub.add_parser("mitre-heatmap", help="ASCII MITRE heatmap.")
    heatmap.add_argument("--controller", default="http://127.0.0.1:9300", **common_kwargs)
    heatmap.add_argument("--api-key", required=True)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


HttpFn = Callable[[str, str, dict[str, str], bytes], tuple[int, bytes]]


def run_node_command(
    args: argparse.Namespace,
    *,
    console: Console | None = None,
    http: HttpFn | None = None,
) -> int:
    """Dispatch a ``honeytrap node ...`` invocation."""
    cmd = getattr(args, "node_command", None)
    out = console or Console()
    fetch = http or _default_http
    if cmd == "register":
        return _cmd_node_register(args, out)
    if cmd == "uplink-status":
        return _cmd_node_uplink_status(args, out, fetch)
    out.print("[red]usage:[/red] honeytrap node {register,uplink-status}")
    return 2


def run_controller_command(
    args: argparse.Namespace,
    *,
    console: Console | None = None,
    http: HttpFn | None = None,
) -> int:
    """Dispatch a ``honeytrap controller ...`` invocation."""
    cmd = getattr(args, "controller_command", None)
    out = console or Console()
    fetch = http or _default_http
    if cmd == "list-nodes":
        return _cmd_list_nodes(args, out, fetch)
    if cmd == "list-events":
        return _cmd_list_events(args, out, fetch)
    if cmd == "top-attackers":
        return _cmd_top_attackers(args, out, fetch)
    if cmd == "mitre-heatmap":
        return _cmd_mitre_heatmap(args, out, fetch)
    out.print(
        "[red]usage:[/red] honeytrap controller "
        "{list-nodes,list-events,top-attackers,mitre-heatmap}"
    )
    return 2


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------


def _cmd_node_register(args: argparse.Namespace, out: Console) -> int:
    """Persist the controller URL + key into ``args.config``."""
    if not args.api_key.startswith("htk_"):
        out.print("[red]api key must be a htk_-prefixed token[/red]")
        return 2
    path = Path(args.config)
    data: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                data = loaded
        except yaml.YAMLError as exc:
            out.print(f"[red]invalid yaml in {path}: {exc}[/red]")
            return 1
    block: dict[str, Any] = {
        "enabled": True,
        "role": "node",
        "controller_url": args.controller,
        "api_key": args.api_key,
        "heartbeat_interval": args.heartbeat_interval,
        "tls_verify": args.tls_verify,
    }
    if args.node_id:
        block["node_id"] = args.node_id
    if args.tag:
        block["tags"] = list(args.tag)
    data["cluster"] = block
    try:
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    except OSError as exc:
        out.print(f"[red]failed to write {path}: {exc}[/red]")
        return 1
    out.print(f"[green]Wrote cluster section to {path}[/green]")
    return 0


def _cmd_node_uplink_status(args: argparse.Namespace, out: Console, http: HttpFn) -> int:
    """Pretty-print the uplink status fetched from the local API."""
    url = args.api.rstrip("/") + "/api/v1/cluster/nodes"
    status, body = http("GET", url, _auth_headers(args.api_key), b"")
    if status != 200:
        out.print(f"[red]uplink-status failed: HTTP {status}[/red]")
        return 1
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        out.print(f"[red]invalid response: {exc}[/red]")
        return 1
    table = Table(title="Uplink status")
    table.add_column("node_id")
    table.add_column("role")
    table.add_column("status")
    table.add_column("last_heartbeat")
    for node in payload.get("items", []):
        table.add_row(
            str(node.get("node_id", "")),
            str(node.get("role", "")),
            str(node.get("status", "")),
            str(node.get("last_heartbeat") or "-"),
        )
    out.print(table)
    return 0


def _cmd_list_nodes(args: argparse.Namespace, out: Console, http: HttpFn) -> int:
    """Render the ``GET /cluster/nodes`` response as a Rich table."""
    url = args.controller.rstrip("/") + "/api/v1/cluster/nodes"
    status, body = http("GET", url, _auth_headers(args.api_key), b"")
    if status != 200:
        out.print(f"[red]list-nodes failed: HTTP {status}[/red]")
        return 1
    try:
        payload = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        out.print(f"[red]invalid response: {exc}[/red]")
        return 1
    items = payload.get("items", []) or []
    table = Table(title=f"Cluster nodes ({len(items)})")
    table.add_column("node_id")
    table.add_column("role")
    table.add_column("version")
    table.add_column("profile")
    table.add_column("status")
    table.add_column("last_heartbeat")
    for node in items:
        table.add_row(
            str(node.get("node_id", "")),
            str(node.get("role", "")),
            str(node.get("version", "")),
            str(node.get("profile") or "-"),
            _status_pill(str(node.get("status", "unknown"))),
            str(node.get("last_heartbeat") or "-"),
        )
    out.print(table)
    return 0


def _cmd_list_events(args: argparse.Namespace, out: Console, http: HttpFn) -> int:
    """Render filtered cluster events as a Rich table."""
    qs = _qs(
        since=args.since,
        until=args.until,
        protocol=args.protocol,
        src_ip=args.src_ip,
        node_id=args.node_id,
        limit=str(min(1000, max(1, int(args.limit)))),
    )
    url = args.controller.rstrip("/") + "/api/v1/cluster/events"
    if qs:
        url += "?" + qs
    status, body = http("GET", url, _auth_headers(args.api_key), b"")
    if status != 200:
        out.print(f"[red]list-events failed: HTTP {status}[/red]")
        return 1
    try:
        payload = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        out.print(f"[red]invalid response: {exc}[/red]")
        return 1
    items = payload.get("items", []) or []
    table = Table(title=f"Cluster events ({len(items)})")
    table.add_column("ts")
    table.add_column("node_id")
    table.add_column("protocol")
    table.add_column("src_ip")
    table.add_column("technique")
    table.add_column("session_id")
    for ev in items:
        table.add_row(
            str(ev.get("ts", "")),
            str(ev.get("node_id", "")),
            str(ev.get("protocol") or "-"),
            str(ev.get("src_ip") or "-"),
            str(ev.get("technique") or "-"),
            str(ev.get("session_id") or "-"),
        )
    out.print(table)
    return 0


def _cmd_top_attackers(args: argparse.Namespace, out: Console, http: HttpFn) -> int:
    """Render the cluster-wide top-N attackers."""
    qs = _qs(limit=str(int(args.limit)))
    url = args.controller.rstrip("/") + "/api/v1/cluster/aggregate/top-attackers"
    if qs:
        url += "?" + qs
    status, body = http("GET", url, _auth_headers(args.api_key), b"")
    if status != 200:
        out.print(f"[red]top-attackers failed: HTTP {status}[/red]")
        return 1
    try:
        payload = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        out.print(f"[red]invalid response: {exc}[/red]")
        return 1
    items = payload.get("items", []) or []
    table = Table(title=f"Top attackers ({len(items)})")
    table.add_column("rank", justify="right")
    table.add_column("src_ip")
    table.add_column("count", justify="right")
    for idx, row in enumerate(items, start=1):
        table.add_row(str(idx), str(row.get("src_ip", "")), str(row.get("count", 0)))
    out.print(table)
    return 0


def _cmd_mitre_heatmap(args: argparse.Namespace, out: Console, http: HttpFn) -> int:
    """Render the cluster-wide MITRE technique distribution as ASCII bars."""
    url = args.controller.rstrip("/") + "/api/v1/cluster/aggregate/mitre"
    status, body = http("GET", url, _auth_headers(args.api_key), b"")
    if status != 200:
        out.print(f"[red]mitre-heatmap failed: HTTP {status}[/red]")
        return 1
    try:
        payload = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        out.print(f"[red]invalid response: {exc}[/red]")
        return 1
    items = payload.get("items", []) or []
    if not items:
        out.print("[yellow]no MITRE events recorded[/yellow]")
        return 0
    max_count = max(int(i.get("count", 0)) for i in items) or 1
    width = 40
    table = Table(title=f"MITRE heatmap ({len(items)} techniques)")
    table.add_column("technique")
    table.add_column("count", justify="right")
    table.add_column("histogram")
    for row in items:
        count = int(row.get("count", 0))
        bar = "#" * max(1, int((count / max_count) * width))
        table.add_row(str(row.get("technique", "")), str(count), bar)
    out.print(table)
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_headers(api_key: str) -> dict[str, str]:
    """Build the X-API-Key + JSON content headers."""
    return {
        "X-API-Key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
    }


def _qs(**kwargs: str | None) -> str:
    """Encode non-empty kwargs as ``a=b&c=d`` (already URL-safe input)."""
    parts: list[str] = []
    for k, v in kwargs.items():
        if v is None or v == "":
            continue
        parts.append(f"{k}={v}")
    return "&".join(parts)


def _status_pill(status: str) -> str:
    """Map a status string to a Rich-coloured indicator."""
    if status == "online":
        return "[green]online[/green]"
    if status == "offline":
        return "[red]offline[/red]"
    return f"[yellow]{status}[/yellow]"


def _default_http(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
    """Default urllib-based HTTP fetcher used by the CLI commands."""
    req = urllib.request.Request(url, data=body or None, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return int(resp.status), resp.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read() if hasattr(exc, "read") else b""
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return -1, str(exc).encode("utf-8")


def iter_node_commands() -> Iterable[str]:
    """Return the registered ``node`` subcommand names."""
    return ("register", "uplink-status")


def iter_controller_commands() -> Iterable[str]:
    """Return the registered ``controller`` subcommand names."""
    return ("list-nodes", "list-events", "top-attackers", "mitre-heatmap")


def load_cluster_section(config_path: str | Path) -> dict[str, Any]:
    """Read the ``cluster:`` block from a YAML file.

    Returns an empty dict when the file does not exist or has no
    cluster section. Raises :class:`ConfigError` on YAML errors so the
    caller can render a friendly message.
    """
    path = Path(config_path)
    if not path.exists():
        return {}
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        return {}
    block = loaded.get("cluster")
    return dict(block) if isinstance(block, dict) else {}


def main_node(argv: list[str] | None = None) -> int:  # pragma: no cover
    """Standalone entrypoint for ``python -m honeytrap.cluster.cli node``."""
    parser = argparse.ArgumentParser(prog="honeytrap node")
    sub = parser.add_subparsers(dest="_root")
    build_node_parser(sub)
    args = parser.parse_args(argv)
    if "node_command" not in args:
        return 2
    return run_node_command(args)


def main_controller(argv: list[str] | None = None) -> int:  # pragma: no cover
    """Standalone entrypoint for ``python -m honeytrap.cluster.cli controller``."""
    parser = argparse.ArgumentParser(prog="honeytrap controller")
    sub = parser.add_subparsers(dest="_root")
    build_controller_parser(sub)
    args = parser.parse_args(argv)
    return run_controller_command(args)


# Allow ``ClusterRole`` to be referenced from this module for IDE autocomplete.
_ROLE = ClusterRole

# Keep stderr import warm for tests that capture output via redirect.
_STDERR = sys.stderr
