"""Tests for ``honeytrap.cluster.cli``."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from rich.console import Console

from honeytrap.cluster.cli import (
    build_controller_parser,
    build_node_parser,
    iter_controller_commands,
    iter_node_commands,
    load_cluster_section,
    run_controller_command,
    run_node_command,
)
from honeytrap.exceptions import ConfigError


def _console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, width=140, color_system=None, force_terminal=False), buf


def _http_factory(
    responses: dict[str, tuple[int, bytes]],
) -> Any:
    """Return a callable matching ``HttpFn`` that maps URL substrings."""

    def fetch(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        for key, value in responses.items():
            if key in url:
                return value
        return 404, b""

    return fetch


def _ns(**kwargs: Any) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


def test_node_register_writes_yaml(tmp_path: Path) -> None:
    cfg_path = tmp_path / "honeytrap.yaml"
    cfg_path.write_text(yaml.safe_dump({"general": {"foo": 1}}))
    args = _ns(
        node_command="register",
        controller="http://controller.local:9300",
        api_key="htk_test",
        config=str(cfg_path),
        node_id="alpha",
        tag=["edge", "us-east"],
        heartbeat_interval=15.0,
        tls_verify=True,
    )
    out, buf = _console()
    rc = run_node_command(args, console=out)
    assert rc == 0
    body = yaml.safe_load(cfg_path.read_text())
    assert body["general"]["foo"] == 1
    assert body["cluster"]["controller_url"] == "http://controller.local:9300"
    assert body["cluster"]["api_key"] == "htk_test"
    assert body["cluster"]["node_id"] == "alpha"
    assert body["cluster"]["tags"] == ["edge", "us-east"]


def test_node_register_rejects_non_htk_key(tmp_path: Path) -> None:
    args = _ns(
        node_command="register",
        controller="http://c",
        api_key="not-htk",
        config=str(tmp_path / "honeytrap.yaml"),
        node_id=None,
        tag=[],
        heartbeat_interval=30.0,
        tls_verify=True,
    )
    out, buf = _console()
    rc = run_node_command(args, console=out)
    assert rc == 2
    assert "htk_" in buf.getvalue()


def test_node_register_handles_invalid_yaml(tmp_path: Path) -> None:
    cfg = tmp_path / "honeytrap.yaml"
    cfg.write_text("not: valid: yaml: : :")
    args = _ns(
        node_command="register",
        controller="http://c",
        api_key="htk_x",
        config=str(cfg),
        node_id=None,
        tag=[],
        heartbeat_interval=30.0,
        tls_verify=True,
    )
    out, _ = _console()
    rc = run_node_command(args, console=out)
    assert rc == 1


def test_node_register_creates_new_file(tmp_path: Path) -> None:
    cfg = tmp_path / "fresh.yaml"
    args = _ns(
        node_command="register",
        controller="http://c",
        api_key="htk_x",
        config=str(cfg),
        node_id=None,
        tag=[],
        heartbeat_interval=30.0,
        tls_verify=False,
    )
    out, _ = _console()
    rc = run_node_command(args, console=out)
    assert rc == 0
    body = yaml.safe_load(cfg.read_text())
    assert body["cluster"]["tls_verify"] is False


def test_node_uplink_status_renders_table() -> None:
    payload = {
        "items": [
            {
                "node_id": "alpha",
                "role": "node",
                "status": "online",
                "last_heartbeat": "2026-04-27T00:00:00Z",
            }
        ]
    }
    args = _ns(
        node_command="uplink-status",
        api="http://127.0.0.1:9300",
        api_key="htk_x",
    )
    fetch = _http_factory({"/cluster/nodes": (200, json.dumps(payload).encode())})
    out, buf = _console()
    rc = run_node_command(args, console=out, http=fetch)
    assert rc == 0
    output = buf.getvalue()
    assert "alpha" in output
    assert "online" in output


def test_node_uplink_status_failure() -> None:
    args = _ns(node_command="uplink-status", api="http://x", api_key="htk_x")
    fetch = _http_factory({"/cluster/nodes": (500, b"")})
    out, buf = _console()
    rc = run_node_command(args, console=out, http=fetch)
    assert rc == 1
    assert "failed" in buf.getvalue()


def test_node_uplink_status_invalid_response() -> None:
    args = _ns(node_command="uplink-status", api="http://x", api_key="htk_x")
    fetch = _http_factory({"/cluster/nodes": (200, b"not json")})
    out, buf = _console()
    rc = run_node_command(args, console=out, http=fetch)
    assert rc == 1


def test_node_unknown_command_returns_usage() -> None:
    args = _ns(node_command=None)
    out, buf = _console()
    rc = run_node_command(args, console=out)
    assert rc == 2
    assert "usage" in buf.getvalue().lower()


def test_controller_list_nodes_renders() -> None:
    payload = {
        "items": [
            {
                "node_id": "n1",
                "role": "node",
                "version": "1.0",
                "profile": "web",
                "status": "online",
                "last_heartbeat": "2026-04-27T00:00:00Z",
            }
        ]
    }
    args = _ns(
        controller_command="list-nodes",
        controller="http://controller",
        api_key="htk_x",
    )
    fetch = _http_factory({"/cluster/nodes": (200, json.dumps(payload).encode())})
    out, buf = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 0
    assert "n1" in buf.getvalue()


def test_controller_list_nodes_handles_failure() -> None:
    args = _ns(
        controller_command="list-nodes",
        controller="http://controller",
        api_key="htk_x",
    )
    fetch = _http_factory({"/cluster/nodes": (-1, b"")})
    out, buf = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 1


def test_controller_list_nodes_invalid_response() -> None:
    args = _ns(
        controller_command="list-nodes",
        controller="http://controller",
        api_key="htk_x",
    )
    fetch = _http_factory({"/cluster/nodes": (200, b"not json")})
    out, buf = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 1


def test_controller_list_events_with_filters() -> None:
    payload = {
        "items": [
            {
                "ts": "2026-04-27T00:00:00Z",
                "node_id": "n1",
                "protocol": "ssh",
                "src_ip": "1.1.1.1",
                "technique": "T1110",
                "session_id": "s1",
            }
        ]
    }
    args = _ns(
        controller_command="list-events",
        controller="http://controller",
        api_key="htk_x",
        since="2026-01-01T00:00:00Z",
        until=None,
        protocol="ssh",
        src_ip=None,
        node_id=None,
        limit=10,
    )
    captured: list[str] = []

    def fetch(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        captured.append(url)
        return 200, json.dumps(payload).encode()

    out, buf = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 0
    assert "ssh" in buf.getvalue()
    assert "since=" in captured[0]
    assert "protocol=ssh" in captured[0]


def test_controller_list_events_failure_path() -> None:
    args = _ns(
        controller_command="list-events",
        controller="http://controller",
        api_key="htk_x",
        since=None,
        until=None,
        protocol=None,
        src_ip=None,
        node_id=None,
        limit=100,
    )
    fetch = _http_factory({"/cluster/events": (500, b"")})
    out, _ = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 1


def test_controller_list_events_invalid_response() -> None:
    args = _ns(
        controller_command="list-events",
        controller="http://x",
        api_key="htk_x",
        since=None,
        until=None,
        protocol=None,
        src_ip=None,
        node_id=None,
        limit=100,
    )
    fetch = _http_factory({"/cluster/events": (200, b"not json")})
    out, _ = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 1


def test_controller_top_attackers_renders() -> None:
    payload = {"items": [{"src_ip": "9.9.9.9", "count": 10}]}
    args = _ns(
        controller_command="top-attackers",
        controller="http://x",
        api_key="htk_x",
        limit=5,
    )
    fetch = _http_factory({"/top-attackers": (200, json.dumps(payload).encode())})
    out, buf = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 0
    assert "9.9.9.9" in buf.getvalue()


def test_controller_top_attackers_failure() -> None:
    args = _ns(
        controller_command="top-attackers",
        controller="http://x",
        api_key="htk_x",
        limit=5,
    )
    fetch = _http_factory({"/top-attackers": (500, b"")})
    out, _ = _console()
    assert run_controller_command(args, console=out, http=fetch) == 1


def test_controller_top_attackers_invalid_response() -> None:
    args = _ns(
        controller_command="top-attackers",
        controller="http://x",
        api_key="htk_x",
        limit=5,
    )
    fetch = _http_factory({"/top-attackers": (200, b"!!!")})
    out, _ = _console()
    assert run_controller_command(args, console=out, http=fetch) == 1


def test_controller_mitre_heatmap_renders_bars() -> None:
    payload = {"items": [{"technique": "T1110", "count": 5}, {"technique": "T1059", "count": 1}]}
    args = _ns(
        controller_command="mitre-heatmap",
        controller="http://x",
        api_key="htk_x",
    )
    fetch = _http_factory({"/aggregate/mitre": (200, json.dumps(payload).encode())})
    out, buf = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 0
    output = buf.getvalue()
    assert "T1110" in output
    assert "#" in output


def test_controller_mitre_heatmap_empty() -> None:
    args = _ns(
        controller_command="mitre-heatmap",
        controller="http://x",
        api_key="htk_x",
    )
    fetch = _http_factory({"/aggregate/mitre": (200, b'{"items":[]}')})
    out, buf = _console()
    rc = run_controller_command(args, console=out, http=fetch)
    assert rc == 0
    assert "no MITRE" in buf.getvalue()


def test_controller_mitre_heatmap_failure() -> None:
    args = _ns(
        controller_command="mitre-heatmap",
        controller="http://x",
        api_key="htk_x",
    )
    fetch = _http_factory({"/aggregate/mitre": (-1, b"")})
    out, _ = _console()
    assert run_controller_command(args, console=out, http=fetch) == 1


def test_controller_mitre_heatmap_invalid_response() -> None:
    args = _ns(
        controller_command="mitre-heatmap",
        controller="http://x",
        api_key="htk_x",
    )
    fetch = _http_factory({"/aggregate/mitre": (200, b"!!!")})
    out, _ = _console()
    assert run_controller_command(args, console=out, http=fetch) == 1


def test_controller_unknown_command() -> None:
    args = _ns(controller_command=None)
    out, buf = _console()
    rc = run_controller_command(args, console=out)
    assert rc == 2
    assert "usage" in buf.getvalue().lower()


def test_iter_helpers_return_known_commands() -> None:
    assert "register" in tuple(iter_node_commands())
    assert "list-nodes" in tuple(iter_controller_commands())


def test_load_cluster_section_returns_block(tmp_path: Path) -> None:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(yaml.safe_dump({"cluster": {"enabled": True, "role": "node"}}))
    block = load_cluster_section(cfg)
    assert block["enabled"] is True


def test_load_cluster_section_missing_file(tmp_path: Path) -> None:
    assert load_cluster_section(tmp_path / "absent.yaml") == {}


def test_load_cluster_section_no_cluster_block(tmp_path: Path) -> None:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(yaml.safe_dump({"general": {"foo": 1}}))
    assert load_cluster_section(cfg) == {}


def test_load_cluster_section_invalid_yaml(tmp_path: Path) -> None:
    cfg = tmp_path / "h.yaml"
    cfg.write_text("not: valid: yaml: : :")
    with pytest.raises(ConfigError):
        load_cluster_section(cfg)


def test_load_cluster_section_handles_non_dict(tmp_path: Path) -> None:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(yaml.safe_dump([1, 2, 3]))
    assert load_cluster_section(cfg) == {}


def test_argparse_wiring() -> None:
    """Ensure the parser builders register the subcommands without errors."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    build_node_parser(sub)
    build_controller_parser(sub)
    args = parser.parse_args(["node", "register", "--controller", "http://c", "--api-key", "htk_x"])
    assert args.node_command == "register"
    args = parser.parse_args(["controller", "list-nodes", "--api-key", "htk_x"])
    assert args.controller_command == "list-nodes"
