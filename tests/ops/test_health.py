"""Tests for the /healthz, /readyz, /metrics HTTP endpoints."""

from __future__ import annotations

import json
import socket
import time
import urllib.request

import pytest

from honeytrap import __version__
from honeytrap.ops.health import (
    HealthServer,
    MetricsRegistry,
    build_default_registry,
    format_prometheus,
)


def _free_port() -> int:
    """Return an unused TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str) -> tuple[int, dict[str, str], bytes]:
    """Issue a GET and return (status, headers, body_bytes)."""
    with urllib.request.urlopen(url, timeout=3) as resp:
        return resp.status, dict(resp.headers), resp.read()


def _get_allow_error(url: str) -> tuple[int, bytes]:
    """Issue a GET; returns (status, body) even on non-2xx."""
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:  # type: ignore[attr-defined]
        return exc.code, exc.read()


@pytest.fixture()
def server() -> HealthServer:
    """Yield a running HealthServer on a free port; stop on teardown."""
    registry = build_default_registry()
    svr = HealthServer(registry, host="127.0.0.1", port=_free_port())
    svr.start()
    try:
        yield svr
    finally:
        svr.stop()


def test_healthz_returns_200_with_expected_keys(server: HealthServer) -> None:
    status, _hdr, body = _get(f"http://127.0.0.1:{server.bound_port}/healthz")
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "ok"
    assert data["version"] == __version__
    assert isinstance(data["uptime_seconds"], int | float)
    assert data["uptime_seconds"] >= 0


def test_readyz_returns_200_under_normal_load(server: HealthServer) -> None:
    status, body = _get_allow_error(f"http://127.0.0.1:{server.bound_port}/readyz")
    assert status == 200
    assert json.loads(body)["status"] == "ready"


def test_readyz_returns_503_when_guardian_refusing() -> None:
    registry = build_default_registry()

    def refusing() -> tuple[bool, str]:
        return False, "memory pressure"

    svr = HealthServer(
        registry,
        host="127.0.0.1",
        port=_free_port(),
        guardian_ready=refusing,
    )
    svr.start()
    try:
        status, body = _get_allow_error(f"http://127.0.0.1:{svr.bound_port}/readyz")
        assert status == 503
        payload = json.loads(body)
        assert payload["status"] == "not_ready"
        assert payload["reason"] == "memory pressure"
    finally:
        svr.stop()


def test_metrics_returns_prometheus_text(server: HealthServer) -> None:
    status, headers, body = _get(f"http://127.0.0.1:{server.bound_port}/metrics")
    assert status == 200
    assert headers.get("Content-Type", "").startswith("text/plain")
    text = body.decode("utf-8")
    for required in (
        "honeytrap_connections_total",
        "honeytrap_events_total",
        "honeytrap_active_sessions",
        "honeytrap_rate_limited_total",
        "honeytrap_resource_rejections_total",
        "honeytrap_uptime_seconds",
    ):
        assert required in text
    assert "# HELP honeytrap_uptime_seconds" in text
    assert "# TYPE honeytrap_uptime_seconds gauge" in text


def test_counters_increment_after_record(server: HealthServer) -> None:
    server.registry.inc_counter("honeytrap_connections_total", labels={"protocol": "http"})
    server.registry.inc_counter("honeytrap_connections_total", labels={"protocol": "http"})
    server.registry.inc_counter("honeytrap_connections_total", labels={"protocol": "ssh"})
    _, _, body = _get(f"http://127.0.0.1:{server.bound_port}/metrics")
    text = body.decode("utf-8")
    assert 'honeytrap_connections_total{protocol="http"} 2' in text
    assert 'honeytrap_connections_total{protocol="ssh"} 1' in text


def test_health_server_binds_configurable_port() -> None:
    port = _free_port()
    svr = HealthServer(build_default_registry(), host="127.0.0.1", port=port)
    svr.start()
    try:
        assert svr.bound_port == port
        status, _h, _b = _get(f"http://127.0.0.1:{port}/healthz")
        assert status == 200
    finally:
        svr.stop()


def test_health_server_defaults_to_loopback() -> None:
    svr = HealthServer(build_default_registry(), port=_free_port())
    svr.start()
    try:
        assert svr.bound_host == "127.0.0.1"
    finally:
        svr.stop()


def test_health_server_stop_is_clean() -> None:
    svr = HealthServer(build_default_registry(), host="127.0.0.1", port=_free_port())
    svr.start()
    port = svr.bound_port
    svr.stop()
    # After stop, the port should be rebindable.
    time.sleep(0.05)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))


def test_cli_health_disabled_flag_parses() -> None:
    from honeytrap.cli import _parse_args

    args = _parse_args(["--health-disabled"])
    assert args.health_disabled is True
    default_args = _parse_args([])
    assert default_args.health_disabled is False


def test_cli_health_port_flag_parses() -> None:
    from honeytrap.cli import _parse_args

    args = _parse_args(["--health-port", "9999", "--health-host", "0.0.0.0"])
    assert args.health_port == 9999
    assert args.health_host == "0.0.0.0"


def test_prometheus_formatter_emits_zero_counters() -> None:
    registry = MetricsRegistry()
    registry.register("my_counter", "A counter that has never been incremented.", "counter")
    text = format_prometheus(registry)
    assert "# TYPE my_counter counter" in text
    assert "my_counter 0" in text


def test_uptime_metric_is_monotonic(server: HealthServer) -> None:
    _, _, body1 = _get(f"http://127.0.0.1:{server.bound_port}/metrics")
    time.sleep(0.02)
    _, _, body2 = _get(f"http://127.0.0.1:{server.bound_port}/metrics")

    def extract(text: str) -> float:
        for line in text.splitlines():
            if line.startswith("honeytrap_uptime_seconds ") and not line.startswith("# "):
                return float(line.split()[1])
        raise AssertionError("uptime line missing")

    u1 = extract(body1.decode("utf-8"))
    u2 = extract(body2.decode("utf-8"))
    assert u2 >= u1
    assert u2 > 0
