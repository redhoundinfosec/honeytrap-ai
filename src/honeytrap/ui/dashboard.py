"""Live Rich-based terminal dashboard.

The dashboard subscribes to the engine's event bus and re-renders a
terminal UI every second with:

* Active connections
* Aggregate stats (totals, unique IPs, brute force / scan / file counts, countries)
* Live event log (tail of events)
* Top attackers + top credentials

Ctrl+C exits cleanly.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter, deque
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from honeytrap.logging.models import Event

if TYPE_CHECKING:  # pragma: no cover
    from honeytrap.core.engine import Engine

logger = logging.getLogger(__name__)


class Dashboard:
    """Async terminal dashboard powered by Rich's Live renderer."""

    def __init__(self, engine: Engine, *, refresh_hz: float = 2.0) -> None:
        """Initialize the Rich-based live terminal dashboard."""
        self.engine = engine
        self.refresh_hz = refresh_hz
        self._events: deque[Event] = deque(maxlen=200)
        self._ip_counter: Counter[str] = Counter()
        self._country_counter: Counter[str] = Counter()
        self._cred_counter: Counter[tuple[str, str]] = Counter()
        self._event_type_counter: Counter[str] = Counter()
        self._protocol_counter: Counter[str] = Counter()
        self._unique_ips: set[str] = set()
        self._started_at = datetime.now(timezone.utc)
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def run(self) -> None:
        """Run the dashboard until :meth:`stop` is called."""
        queue = self.engine.subscribe()
        consumer = asyncio.create_task(self._consume(queue))
        try:
            with Live(self._render(), refresh_per_second=self.refresh_hz, screen=False) as live:
                while not self._stop.is_set():
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=1.0 / self.refresh_hz)
                    except asyncio.TimeoutError:
                        pass
                    try:
                        live.update(self._render())
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Dashboard render failed: %s", exc)
        finally:
            consumer.cancel()
            try:
                await consumer
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self.engine.unsubscribe(queue)

    def stop(self) -> None:
        """Signal the dashboard to shut down."""
        self._stop.set()

    # ------------------------------------------------------------------
    # Event consumption
    # ------------------------------------------------------------------
    async def _consume(self, queue: asyncio.Queue[Event]) -> None:
        while True:
            try:
                event = await queue.get()
            except asyncio.CancelledError:
                break
            self._ingest(event)

    def _ingest(self, event: Event) -> None:
        """Update in-memory aggregates for an event."""
        self._events.append(event)
        self._protocol_counter[event.protocol] += 1
        self._event_type_counter[event.event_type] += 1
        if event.remote_ip:
            self._ip_counter[event.remote_ip] += 1
            self._unique_ips.add(event.remote_ip)
        if event.country_code and event.country_code != "XX":
            self._country_counter[event.country_code] += 1
        if event.event_type == "auth_attempt" and (event.username or event.password):
            self._cred_counter[(event.username, event.password)] += 1

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def _render(self) -> Group:
        header = self._render_header()
        top_row = self._render_top_row()
        event_log = self._render_event_log()
        bottom_row = self._render_bottom_row()
        security_row = self._render_security_row()
        footer = Panel(
            Text("[Q]uit   [R]eport   [P]ause   [F]ilter   [E]xport", justify="center"),
            style="bold white on grey11",
        )
        return Group(header, top_row, event_log, bottom_row, security_row, footer)

    def _render_security_row(self) -> Panel:
        """Security / resource panel — rate-limited IPs + guardian stats.

        We read from the engine's limiter/guardian synchronously because
        both expose non-awaited accessors to their internal counters
        (via private attributes). This is a best-effort render; stale
        data is preferable to a coroutine-blocked UI.
        """
        limiter = getattr(self.engine, "rate_limiter", None)
        guardian = getattr(self.engine, "guardian", None)

        blocked = Table(title="Rate-Limited IPs", expand=True)
        blocked.add_column("IP")
        blocked.add_column("Blocks", style="bold red")
        if limiter is not None:
            top = sorted(
                limiter._blocked_ips.items(), key=lambda kv: kv[1], reverse=True
            )[:5]
            for ip, count in top:
                blocked.add_row(ip, str(count))
            if not top:
                blocked.add_row("(none)", "0")

        resources = Table(title="Resources", expand=True, show_header=False)
        resources.add_column("Metric")
        resources.add_column("Value", style="bold cyan")
        if guardian is not None:
            s = guardian._stats
            resources.add_row(
                "Memory",
                f"{s.memory_mb:.0f} / {s.memory_limit_mb:.0f} MB",
            )
            resources.add_row(
                "Connections", f"{s.connections} / {s.connections_cap}"
            )
            resources.add_row(
                "Log dir",
                f"{s.log_dir_bytes / (1024 * 1024):.1f} MB",
            )
            status = "REFUSING" if s.should_refuse else "accepting"
            resources.add_row("Status", status)
            if s.refusal_reason:
                resources.add_row("Reason", s.refusal_reason[:60])
        if limiter is not None:
            resources.add_row("Tracked IPs", str(len(limiter._buckets)))
            resources.add_row("Global active", str(limiter._global_active))

        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(blocked, resources)
        return Panel(grid, title="Security", border_style="red")

    def _render_header(self) -> Panel:
        uptime = datetime.now(timezone.utc) - self._started_at
        profile = self.engine.profile
        title = Text.assemble(
            ("🍯 HoneyTrap AI", "bold yellow"),
            ("  ·  ", "dim"),
            (f"Profile: {profile.name}", "bold white"),
            ("  ·  ", "dim"),
            (f"Uptime: {self._fmt_duration(uptime.total_seconds())}", "bold cyan"),
        )
        return Panel(title, style="on grey11")

    def _render_top_row(self) -> Panel:
        active = Table(title="Active Connections", expand=True, show_lines=False)
        active.add_column("IP")
        active.add_column("Country")
        active.add_column("Proto")
        active.add_column("Port")
        active.add_column("Since")
        for sess in self.engine.sessions.active()[:10]:
            active.add_row(
                sess.remote_ip,
                f"{sess.country_code} {sess.country_name[:16]}",
                sess.protocol.upper(),
                str(sess.local_port),
                f"{sess.duration_seconds:.0f}s",
            )

        stats = Table(title="Stats", expand=True, show_header=False, show_lines=False)
        stats.add_column("Metric")
        stats.add_column("Value", style="bold cyan")
        stats.add_row("Total events", str(sum(self._protocol_counter.values())))
        stats.add_row("Unique IPs", str(len(self._unique_ips)))
        stats.add_row(
            "Brute-force attempts", str(self._event_type_counter.get("auth_attempt", 0))
        )
        stats.add_row(
            "Exploit attempts", str(self._event_type_counter.get("exploit_attempt", 0))
        )
        stats.add_row(
            "HTTP requests", str(self._event_type_counter.get("http_request", 0))
        )
        stats.add_row("Countries seen", str(len(self._country_counter)))

        grid = Table.grid(expand=True)
        grid.add_column(ratio=3)
        grid.add_column(ratio=2)
        grid.add_row(active, stats)
        return Panel(grid, title="Overview", border_style="cyan")

    def _render_event_log(self) -> Panel:
        table = Table(expand=True, show_lines=False)
        table.add_column("Time", style="dim", no_wrap=True)
        table.add_column("Proto", width=7)
        table.add_column("IP", no_wrap=True)
        table.add_column("CC", width=3)
        table.add_column("Type", width=16)
        table.add_column("Message", overflow="fold")
        for event in list(self._events)[-14:]:
            ts = event.timestamp.astimezone().strftime("%H:%M:%S")
            table.add_row(
                ts,
                event.protocol.upper(),
                event.remote_ip or "-",
                event.country_code or "--",
                event.event_type,
                event.message[:90],
            )
        return Panel(table, title="Live Event Log", border_style="green")

    def _render_bottom_row(self) -> Panel:
        attackers = Table(title="Top Attackers", expand=True)
        attackers.add_column("IP")
        attackers.add_column("Events", style="bold cyan")
        for ip, count in self._ip_counter.most_common(5):
            attackers.add_row(ip, str(count))

        creds = Table(title="Top Credentials", expand=True)
        creds.add_column("User")
        creds.add_column("Pass")
        creds.add_column("Count", style="bold cyan")
        for (user, pwd), count in self._cred_counter.most_common(5):
            creds.add_row(user or "-", pwd or "-", str(count))

        countries = Table(title="Top Countries", expand=True)
        countries.add_column("CC")
        countries.add_column("Events", style="bold cyan")
        for cc, count in self._country_counter.most_common(5):
            countries.add_row(cc, str(count))

        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(attackers, creds, countries)
        return Panel(grid, title="Leaderboards", border_style="magenta")

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        seconds = int(seconds)
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"
