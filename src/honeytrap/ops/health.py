"""HTTP health, readiness, and Prometheus metrics endpoints.

A tiny stdlib-based HTTP server (no new runtime deps) exposes three URLs:

``GET /healthz``
    Always returns 200 with a small JSON payload describing version and
    uptime. Useful for container HEALTHCHECK probes.

``GET /readyz``
    Returns 200 when the event loop is healthy and the resource guardian
    is not refusing connections, 503 otherwise.

``GET /metrics``
    Prometheus text exposition. All counters are always emitted — even
    zero-valued ones — so scrapers can compute rate() over the first
    interval without a cold-start gap.

The server binds to ``127.0.0.1`` by default to keep the health plane off
any exposed network; an operator who genuinely wants it reachable must
opt in with a non-loopback bind host. The server runs on its own thread
so a hung event loop cannot take health probes down with it.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from honeytrap import __version__

logger = logging.getLogger(__name__)


class MetricsRegistry:
    """Thread-safe counter/gauge registry used by the metrics endpoint.

    Counters only increase; gauges can be set to arbitrary values. A
    labelled counter is stored by a tuple of ``(metric_name, sorted_label_items)``
    so the same metric with different labels accumulates independently.
    """

    DEFAULT_HISTOGRAM_BUCKETS: tuple[float, ...] = (
        0.5,
        1.0,
        5.0,
        15.0,
        60.0,
        300.0,
        1800.0,
        3600.0,
    )

    def __init__(self) -> None:
        """Create an empty registry."""
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._help: dict[str, str] = {}
        self._types: dict[str, str] = {}
        self._histograms: dict[str, dict[str, float]] = {}

    def register(self, name: str, help_text: str, metric_type: str) -> None:
        """Declare a metric so it is emitted even before first use."""
        with self._lock:
            self._help[name] = help_text
            self._types[name] = metric_type

    def inc_counter(
        self, name: str, value: float = 1.0, labels: dict[str, str] | None = None
    ) -> None:
        """Increment a counter. Creates the series on first use."""
        key = (name, self._labels_key(labels))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        """Set a gauge to an absolute value."""
        key = (name, self._labels_key(labels))
        with self._lock:
            self._gauges[key] = float(value)

    def observe_histogram(
        self,
        name: str,
        value: float,
        buckets: tuple[float, ...] | None = None,
    ) -> None:
        """Record a histogram observation against the named metric.

        Bucket counts are stored as cumulative tallies keyed by string
        bucket bound so the Prometheus exposition is straightforward.
        """
        with self._lock:
            histo = self._histograms.setdefault(
                name,
                {"_count": 0.0, "_sum": 0.0},
            )
            buckets = buckets or self.DEFAULT_HISTOGRAM_BUCKETS
            for b in buckets:
                key = f"{b}"
                if value <= b:
                    histo[key] = histo.get(key, 0.0) + 1.0
                else:
                    histo.setdefault(key, 0.0)
            histo["+Inf"] = histo.get("+Inf", 0.0) + 1.0
            histo["_count"] += 1.0
            histo["_sum"] += float(value)

    def snapshot(self) -> dict[str, Any]:
        """Return a plain-dict snapshot, mostly for tests."""
        with self._lock:
            return {
                "counters": {
                    (name, dict(label_pairs)): value
                    for (name, label_pairs), value in self._counters.items()
                },
                "gauges": {
                    (name, dict(label_pairs)): value
                    for (name, label_pairs), value in self._gauges.items()
                },
            }

    @staticmethod
    def _labels_key(
        labels: dict[str, str] | None,
    ) -> tuple[tuple[str, str], ...]:
        if not labels:
            return ()
        return tuple(sorted(labels.items()))


def format_prometheus(registry: MetricsRegistry) -> str:
    """Render a :class:`MetricsRegistry` as Prometheus text exposition.

    All registered counters and gauges are emitted. Counters without any
    recorded samples are emitted with value ``0`` so consumers can always
    compute deltas. Label values are escaped for backslash, double-quote
    and newline per the Prometheus text format.
    """
    lines: list[str] = []
    with registry._lock:  # noqa: SLF001 — internal cooperating class
        names = sorted(
            set(registry._help)
            | {n for n, _ in registry._counters}
            | {n for n, _ in registry._gauges}
            | set(registry._histograms)
        )
        for name in names:
            help_text = registry._help.get(name, name)
            metric_type = registry._types.get(name, "counter")
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {metric_type}")
            if metric_type == "histogram" and name in registry._histograms:
                histo = registry._histograms[name]
                buckets = sorted(
                    (k for k in histo if k not in {"_count", "_sum", "+Inf"}),
                    key=float,
                )
                for b in buckets:
                    lines.append(f'{name}_bucket{{le="{b}"}} {_fmt_value(histo[b])}')
                lines.append(
                    f'{name}_bucket{{le="+Inf"}} {_fmt_value(histo.get("+Inf", 0.0))}'
                )
                lines.append(f"{name}_count {_fmt_value(histo['_count'])}")
                lines.append(f"{name}_sum {_fmt_value(histo['_sum'])}")
                continue
            samples = [
                (label_pairs, value)
                for (n, label_pairs), value in registry._counters.items()
                if n == name
            ] + [
                (label_pairs, value)
                for (n, label_pairs), value in registry._gauges.items()
                if n == name
            ]
            if not samples:
                lines.append(f"{name} 0")
                continue
            for label_pairs, value in samples:
                lines.append(_format_sample(name, label_pairs, value))
    lines.append("")
    return "\n".join(lines)


def _format_sample(name: str, label_pairs: tuple[tuple[str, str], ...], value: float) -> str:
    """Format a single metric sample line."""
    if not label_pairs:
        return f"{name} {_fmt_value(value)}"
    parts = [f'{k}="{_escape(v)}"' for k, v in label_pairs]
    return f"{name}{{{','.join(parts)}}} {_fmt_value(value)}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt_value(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return repr(float(value))


class HealthServer:
    """Thread-backed HTTP server serving /healthz, /readyz, /metrics.

    The server listens on a background thread so health probes stay
    responsive even if the asyncio event loop is wedged. Callers construct
    the server with a :class:`MetricsRegistry` and two lightweight
    callables returning current guardian/session state. The callables must
    be thread-safe (they are invoked from the HTTP handler thread).
    """

    def __init__(
        self,
        registry: MetricsRegistry,
        *,
        host: str = "127.0.0.1",
        port: int = 9200,
        guardian_ready: Callable[[], tuple[bool, str]] | None = None,
        active_sessions: Callable[[], int] | None = None,
    ) -> None:
        """Create a server (not yet listening).

        Args:
            registry: Metrics registry to expose on ``/metrics``.
            host: Bind address. Defaults to loopback.
            port: TCP port to listen on.
            guardian_ready: Callable returning ``(ready, reason)``.
                When ``ready`` is False ``/readyz`` returns 503.
            active_sessions: Callable returning current session count.
                Used to update the ``honeytrap_active_sessions`` gauge
                whenever ``/metrics`` is scraped.
        """
        self.registry = registry
        self.host = host
        self.port = port
        self._guardian_ready = guardian_ready or (lambda: (True, ""))
        self._active_sessions = active_sessions or (lambda: 0)
        self._httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._started_at = time.time()

    @property
    def bound_port(self) -> int:
        """Return the port the server is actually listening on (0 if not started)."""
        if self._httpd is None:
            return 0
        return self._httpd.server_address[1]

    @property
    def bound_host(self) -> str:
        """Return the host the server is listening on."""
        if self._httpd is None:
            return self.host
        return self._httpd.server_address[0]

    def start(self) -> None:
        """Bind the socket and start serving in a background thread."""
        if self._httpd is not None:
            return
        handler_cls = self._build_handler_class()
        self._httpd = HTTPServer((self.host, self.port), handler_cls)
        self._started_at = time.time()
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="honeytrap-health",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Health server listening on %s:%s",
            self.bound_host,
            self.bound_port,
        )

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the background server. Safe to call multiple times."""
        if self._httpd is None:
            return
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Health server shutdown error: %s", exc)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._httpd = None
        self._thread = None

    def uptime_seconds(self) -> float:
        """Return monotonic uptime since :meth:`start`."""
        return time.time() - self._started_at

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _build_handler_class(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, _fmt: str, *_args: Any) -> None:
                # Silence default stderr access logs.
                return

            def do_GET(self) -> None:  # noqa: N802 — required by BaseHTTPRequestHandler
                if self.path == "/healthz":
                    self._handle_healthz()
                elif self.path == "/readyz":
                    self._handle_readyz()
                elif self.path == "/metrics":
                    self._handle_metrics()
                else:
                    self.send_error(404, "not found")

            def _handle_healthz(self) -> None:
                body = json.dumps(
                    {
                        "status": "ok",
                        "uptime_seconds": round(server.uptime_seconds(), 3),
                        "version": __version__,
                    }
                ).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")

            def _handle_readyz(self) -> None:
                try:
                    ready, reason = server._guardian_ready()
                except Exception as exc:  # noqa: BLE001
                    ready, reason = False, f"guardian check failed: {exc}"
                payload = {
                    "status": "ready" if ready else "not_ready",
                    "reason": reason,
                    "uptime_seconds": round(server.uptime_seconds(), 3),
                }
                body = json.dumps(payload).encode("utf-8")
                self._send(
                    200 if ready else 503,
                    body,
                    "application/json; charset=utf-8",
                )

            def _handle_metrics(self) -> None:
                try:
                    server.registry.set_gauge(
                        "honeytrap_active_sessions", server._active_sessions()
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("active_sessions gauge refresh failed: %s", exc)
                server.registry.set_gauge("honeytrap_uptime_seconds", server.uptime_seconds())
                text = format_prometheus(server.registry)
                self._send(200, text.encode("utf-8"), "text/plain; version=0.0.4")

            def _send(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

        return _Handler


def build_default_registry() -> MetricsRegistry:
    """Create a registry with all HoneyTrap metrics pre-declared.

    Pre-declaring ensures every metric shows up in ``/metrics`` from the
    first scrape, even if no events have fired yet.
    """
    registry = MetricsRegistry()
    registry.register(
        "honeytrap_connections_total",
        "Total number of connections accepted, by protocol.",
        "counter",
    )
    registry.register(
        "honeytrap_events_total",
        "Total number of protocol events emitted, by protocol and event_type.",
        "counter",
    )
    registry.register(
        "honeytrap_active_sessions",
        "Number of currently active honeypot sessions.",
        "gauge",
    )
    registry.register(
        "honeytrap_rate_limited_total",
        "Total connections rejected by the rate limiter.",
        "counter",
    )
    registry.register(
        "honeytrap_resource_rejections_total",
        "Total connections rejected by the resource guardian.",
        "counter",
    )
    registry.register(
        "honeytrap_uptime_seconds",
        "Uptime of the health server in seconds.",
        "gauge",
    )
    registry.register(
        "honeytrap_alerts_sent_total",
        "Total alerts successfully sent, by channel and severity.",
        "counter",
    )
    registry.register(
        "honeytrap_alerts_dropped_total",
        "Total alerts dropped, by reason (rate-limited, channel-error, below-min-severity).",
        "counter",
    )
    registry.register(
        "honeytrap_tls_fingerprint_total",
        "Total TLS fingerprints observed, by JA3 hash and attributed category/name.",
        "counter",
    )
    registry.register(
        "honeytrap_sessions_recorded_total",
        "Total session frames recorded, by protocol.",
        "counter",
    )
    registry.register(
        "honeytrap_sessions_truncated_total",
        "Total sessions that hit a recording cap, by reason.",
        "counter",
    )
    registry.register(
        "honeytrap_session_bytes_total",
        "Total bytes recorded into sessions, by protocol and direction.",
        "counter",
    )
    registry.register(
        "honeytrap_pcap_exports_total",
        "Total PCAP exports written.",
        "counter",
    )
    registry.register(
        "honeytrap_session_duration_seconds",
        "Session duration histogram (seconds).",
        "histogram",
    )
    return registry
