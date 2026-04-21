"""Textual-based TUI dashboard for HoneyTrap AI.

This module implements :class:`HoneyTrapTUI`, a full Textual application
that replaces (and coexists with) the legacy Rich Live :class:`Dashboard`.
It subscribes to the engine's event bus and renders several live panels:

* Header bar with title, uptime, counters and profile name.
* Active connections table (live sessions).
* Event log (recent events, filterable).
* Threat intel panel (top attackers, top protocols, top ATT&CK techniques,
  top IOC types).
* Resource guardian panel (connections, memory, rate-limit rejections).
* Footer with keyboard hints.

The app is wired to an :class:`DashboardEventSource` abstraction so it can
be driven by a real :class:`~honeytrap.core.engine.Engine` instance or by a
lightweight mock in the test suite.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter, deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol

from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)

from honeytrap.logging.models import Event

if TYPE_CHECKING:  # pragma: no cover
    from honeytrap.core.engine import Engine
    from honeytrap.core.session import Session

logger = logging.getLogger(__name__)


MIN_TERMINAL_WIDTH: int = 80
UPDATE_INTERVAL_SECONDS: float = 0.1  # ~10fps throttle
MAX_RECENT_EVENTS: int = 500
MAX_LOG_ROWS: int = 200
PROTOCOL_FILTERS: tuple[str, ...] = (
    "ALL",
    "HTTP",
    "SSH",
    "FTP",
    "SMB",
    "TELNET",
    "SMTP",
    "MYSQL",
)


# ---------------------------------------------------------------------------
# Shared event-source abstraction
# ---------------------------------------------------------------------------


class DashboardEventSource(Protocol):
    """Protocol both the Rich and Textual dashboards consume.

    The real implementation is :class:`EngineDashboardSource` below. Tests
    supply a :class:`MockDashboardSource` that mirrors the same shape without
    requiring a running engine.
    """

    def subscribe(self) -> asyncio.Queue[Event]:
        """Return an async queue fed by every new event."""
        ...

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        """Stop receiving events on the given queue."""
        ...

    def active_sessions(self) -> list[Session]:
        """Return currently-active sessions (live attackers)."""
        ...

    def profile_name(self) -> str:
        """Profile name for display purposes."""
        ...

    def guardian_snapshot(self) -> dict[str, Any]:
        """Return a resource-guardian stats snapshot."""
        ...

    def rate_limit_snapshot(self) -> dict[str, Any]:
        """Return a rate-limiter stats snapshot."""
        ...


@dataclass
class EngineDashboardSource:
    """Adapter that wraps an :class:`Engine` as a :class:`DashboardEventSource`.

    The Rich dashboard already reads from engine attributes directly; this
    adapter keeps the Textual UI decoupled so tests can inject a mock.
    """

    engine: Engine

    def subscribe(self) -> asyncio.Queue[Event]:
        """Proxy to :meth:`Engine.subscribe`."""
        return self.engine.subscribe()

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        """Proxy to :meth:`Engine.unsubscribe`."""
        self.engine.unsubscribe(queue)

    def active_sessions(self) -> list[Session]:
        """Return the engine session manager's active sessions."""
        return self.engine.sessions.active()

    def profile_name(self) -> str:
        """Return the loaded profile name."""
        return self.engine.profile.name

    def guardian_snapshot(self) -> dict[str, Any]:
        """Return a best-effort snapshot of guardian state."""
        guardian = getattr(self.engine, "guardian", None)
        if guardian is None:
            return {}
        stats = getattr(guardian, "_stats", None)
        if stats is None:
            return {}
        return {
            "memory_mb": stats.memory_mb,
            "memory_limit_mb": stats.memory_limit_mb,
            "connections": stats.connections,
            "connections_cap": stats.connections_cap,
            "should_refuse": stats.should_refuse,
            "refusal_reason": stats.refusal_reason,
            "log_dir_mb": stats.log_dir_bytes / (1024 * 1024),
        }

    def rate_limit_snapshot(self) -> dict[str, Any]:
        """Return rate-limiter counters."""
        limiter = getattr(self.engine, "rate_limiter", None)
        if limiter is None:
            return {}
        blocked = getattr(limiter, "_blocked_ips", {}) or {}
        buckets = getattr(limiter, "_buckets", {}) or {}
        return {
            "blocked_ips": dict(sorted(blocked.items(), key=lambda kv: kv[1], reverse=True)[:5]),
            "tracked_ips": len(buckets),
            "global_active": getattr(limiter, "_global_active", 0),
            "total_blocks": sum(blocked.values()) if blocked else 0,
        }


# ---------------------------------------------------------------------------
# Modal: session detail
# ---------------------------------------------------------------------------


class SessionDetailModal(ModalScreen[None]):
    """Modal screen showing full detail for a single session.

    Displays session metadata, every event associated with the session,
    extracted IOCs, mapped ATT&CK techniques, and a hex dump of the most
    recent event payload. ``escape`` dismisses the modal.
    """

    BINDINGS = [Binding("escape", "dismiss_modal", "Close", show=True)]
    DEFAULT_CSS = """
    SessionDetailModal {
        align: center middle;
    }
    #session-detail-container {
        width: 90%;
        height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, session_id: str, events: list[Event]) -> None:
        """Initialize the modal with session id and its events."""
        super().__init__()
        self._session_id = session_id
        self._events = events

    def compose(self) -> ComposeResult:
        """Build modal widgets."""
        with Vertical(id="session-detail-container"):
            yield Label(f"Session {self._session_id}", id="session-detail-title")
            yield Static(self._render_metadata(), id="session-metadata")
            yield Label("Events", classes="section-header")
            yield Static(self._render_events(), id="session-events")
            yield Label("ATT&CK Techniques", classes="section-header")
            yield Static(self._render_techniques(), id="session-attack")
            yield Label("IOCs", classes="section-header")
            yield Static(self._render_iocs(), id="session-iocs")
            yield Label("Payload (hex)", classes="section-header")
            yield Static(self._render_hex(), id="session-hex")

    def _render_metadata(self) -> str:
        """Render the session metadata header line."""
        if not self._events:
            return "(no events yet)"
        first = self._events[0]
        return (
            f"IP: {first.remote_ip}  Country: {first.country_code}  "
            f"Protocol: {first.protocol}  Events: {len(self._events)}"
        )

    def _render_events(self) -> str:
        """Render the event list."""
        if not self._events:
            return "(empty)"
        lines = []
        for event in self._events[-20:]:
            ts = event.timestamp.astimezone().strftime("%H:%M:%S")
            lines.append(
                f"{ts}  {event.protocol.upper():<7}  {event.event_type:<16}  "
                f"{(event.message or '')[:60]}"
            )
        return "\n".join(lines)

    def _render_techniques(self) -> str:
        """Render mapped ATT&CK techniques."""
        techniques: dict[str, str] = {}
        for event in self._events:
            for t in (event.data or {}).get("attack_techniques", []) or []:
                tid = t.get("technique_id")
                if tid:
                    techniques[tid] = t.get("technique_name") or tid
        if not techniques:
            return "(none)"
        return "\n".join(f"{tid} — {name}" for tid, name in techniques.items())

    def _render_iocs(self) -> str:
        """Render extracted IOCs."""
        iocs: list[str] = []
        for event in self._events:
            for ioc in (event.data or {}).get("iocs", []) or []:
                kind = ioc.get("type", "?")
                value = ioc.get("value", "?")
                iocs.append(f"{kind}: {value}")
        if not iocs:
            return "(none)"
        return "\n".join(iocs[:20])

    def _render_hex(self) -> str:
        """Render a hex dump of the most recent event's raw payload, if any."""
        if not self._events:
            return "(none)"
        latest = self._events[-1]
        payload = (latest.data or {}).get("raw") or (latest.data or {}).get("payload")
        if not payload:
            return (latest.message or "(no payload)")[:200]
        data: bytes
        if isinstance(payload, str):
            data = payload.encode("utf-8", "replace")
        elif isinstance(payload, bytes):
            data = payload
        else:
            data = str(payload).encode("utf-8", "replace")
        data = data[:256]
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")
        return "\n".join(lines)

    def action_dismiss_modal(self) -> None:
        """Close the modal."""
        self.dismiss(None)


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------


class HoneyTrapTUI(App[int]):
    """Textual application rendering the live honeypot dashboard.

    The app is constructed with a :class:`DashboardEventSource` (typically an
    :class:`EngineDashboardSource` in production). It subscribes to the source
    on mount, consumes events in a background task, and re-renders the panels
    on a fixed interval throttled to ~10fps.
    """

    CSS = """
    Screen {
        background: $background;
    }
    #top-row {
        height: 40%;
    }
    #mid-row {
        height: 35%;
    }
    #bottom-row {
        height: 25%;
    }
    .panel-title {
        background: $panel;
        color: $accent;
        padding: 0 1;
        text-style: bold;
    }
    #narrow-warning {
        color: $error;
        text-align: center;
        padding: 2;
    }
    #filter-label {
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("f", "cycle_filter", "Filter", show=True),
        Binding("s", "open_search", "Search", show=True),
        Binding("slash", "open_search", "Search", show=False),
        Binding("r", "generate_report", "Report", show=True),
        Binding("p", "toggle_pause", "Pause", show=True),
        Binding("tab", "focus_next", "Next", show=False),
        Binding("shift+tab", "focus_previous", "Prev", show=False),
    ]

    filter_protocol: reactive[str] = reactive("ALL")
    search_term: reactive[str] = reactive("")
    paused: reactive[bool] = reactive(False)
    total_events: reactive[int] = reactive(0)

    def __init__(
        self,
        source: DashboardEventSource,
        *,
        report_callback: Callable[[], Awaitable[str] | str] | None = None,
        update_interval: float = UPDATE_INTERVAL_SECONDS,
    ) -> None:
        """Initialize the TUI.

        Args:
            source: Event source to subscribe to.
            report_callback: Invoked when the user presses ``r``. May be a
                synchronous or async callable. Returns a human-readable
                confirmation string for the toast notification.
            update_interval: Panel refresh interval in seconds.
        """
        super().__init__()
        self._source = source
        self._report_callback = report_callback
        self._update_interval = update_interval

        self._queue: asyncio.Queue[Event] | None = None
        self._consumer_task: asyncio.Task[None] | None = None
        self._started_at: datetime = datetime.now(timezone.utc)

        self._events: deque[Event] = deque(maxlen=MAX_RECENT_EVENTS)
        self._events_by_session: dict[str, list[Event]] = {}
        self._protocol_counter: Counter[str] = Counter()
        self._ip_counter: Counter[str] = Counter()
        self._technique_counter: Counter[str] = Counter()
        self._technique_names: dict[str, str] = {}
        self._ioc_counter: Counter[str] = Counter()
        self._rendered_session_ids: set[str] = set()
        self._narrow_mode: bool = False

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        """Build the widget tree."""
        yield Header(show_clock=False)
        yield Static("", id="narrow-warning")
        yield Static("HoneyTrap AI", id="status-bar", classes="panel-title")
        with Horizontal(id="top-row"):
            with Vertical():
                yield Label("Active Connections", classes="panel-title")
                yield DataTable(id="connections-table", zebra_stripes=True)
            with Vertical():
                yield Label("Stats / Threat Intel", classes="panel-title")
                yield DataTable(id="intel-table", show_header=True)
        with Horizontal(id="mid-row"), Vertical():
            yield Label("Event Log", classes="panel-title")
            yield DataTable(id="event-table", zebra_stripes=True)
        with Horizontal(id="bottom-row"):
            with Vertical():
                yield Label("Resource Guardian", classes="panel-title")
                yield DataTable(id="guardian-table", show_header=False)
            with Vertical():
                yield Label("Activity", classes="panel-title")
                yield RichLog(id="activity-log", highlight=True, markup=False)
        yield Input(placeholder="Search events...", id="search-input")
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def on_mount(self) -> None:
        """Subscribe to the event source and configure tables."""
        # Tables
        connections: DataTable[Any] = self.query_one("#connections-table", DataTable)
        connections.add_columns("SID", "IP", "CC", "Proto", "Port", "Dur", "Events", "Last")
        connections.cursor_type = "row"

        events_table: DataTable[Any] = self.query_one("#event-table", DataTable)
        events_table.add_columns("Time", "Proto", "IP", "CC", "Type", "Summary")

        intel_table: DataTable[Any] = self.query_one("#intel-table", DataTable)
        intel_table.add_columns("Metric", "Value")

        guardian_table: DataTable[Any] = self.query_one("#guardian-table", DataTable)
        guardian_table.add_columns("Key", "Value")

        search = self.query_one("#search-input", Input)
        search.display = False

        self._update_status_bar()
        self._check_terminal_width(self.size.width)

        self._queue = self._source.subscribe()
        self._consumer_task = asyncio.create_task(self._consume_events())
        self.set_interval(self._update_interval, self._refresh_ui)

    async def on_unmount(self) -> None:
        """Release subscription and stop consumer task on exit."""
        import contextlib

        if self._consumer_task is not None:
            self._consumer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):  # noqa: BLE001
                await self._consumer_task
        if self._queue is not None:
            with contextlib.suppress(Exception):  # noqa: BLE001
                self._source.unsubscribe(self._queue)

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------
    async def _consume_events(self) -> None:
        """Background task: drain the event queue into local aggregates."""
        assert self._queue is not None
        while True:
            try:
                event = await self._queue.get()
            except asyncio.CancelledError:
                break
            try:
                self._ingest_event(event)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to ingest event in TUI: %s", exc)

    def _ingest_event(self, event: Event) -> None:
        """Update in-memory aggregates for a new event."""
        if self.paused:
            # Drop updates while paused but still increment total so the user
            # can see the paused state clearly.
            self.total_events += 1
            return
        self._events.append(event)
        self.total_events += 1
        self._protocol_counter[event.protocol.upper()] += 1
        if event.remote_ip:
            self._ip_counter[event.remote_ip] += 1
        if event.session_id:
            self._events_by_session.setdefault(event.session_id, []).append(event)
        for t in (event.data or {}).get("attack_techniques", []) or []:
            tid = t.get("technique_id")
            if tid:
                self._technique_counter[tid] += 1
                self._technique_names[tid] = t.get("technique_name") or tid
        for ioc in (event.data or {}).get("iocs", []) or []:
            kind = ioc.get("type")
            if kind:
                self._ioc_counter[kind] += 1

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def _refresh_ui(self) -> None:
        """Throttled full-UI refresh invoked by :meth:`set_interval`."""
        try:
            self._check_terminal_width(self.size.width)
            if self._narrow_mode:
                return
            self._update_status_bar()
            self._update_connections_table()
            self._update_event_log()
            self._update_intel_table()
            self._update_guardian_table()
        except Exception as exc:  # noqa: BLE001
            logger.debug("UI refresh failed: %s", exc)

    def _check_terminal_width(self, width: int) -> None:
        """Enable/disable narrow mode based on terminal size."""
        narrow_prev = self._narrow_mode
        self._narrow_mode = width > 0 and width < MIN_TERMINAL_WIDTH
        try:
            warning = self.query_one("#narrow-warning", Static)
        except Exception:  # noqa: BLE001
            return
        if self._narrow_mode:
            warning.update(
                f"Terminal too narrow ({width} cols). "
                f"Please resize to at least {MIN_TERMINAL_WIDTH} columns."
            )
            warning.display = True
        elif narrow_prev:
            warning.update("")
            warning.display = False
        else:
            warning.display = False

    def _update_status_bar(self) -> None:
        """Refresh the single-line status bar."""
        uptime = datetime.now(timezone.utc) - self._started_at
        total = uptime.total_seconds()
        hours, rem = divmod(int(total), 3600)
        minutes, secs = divmod(rem, 60)
        active = len(self._source.active_sessions())
        filter_text = self.filter_protocol
        paused_text = " [PAUSED]" if self.paused else ""
        try:
            bar = self.query_one("#status-bar", Static)
        except Exception:  # noqa: BLE001
            return
        bar.update(
            f"HoneyTrap AI  |  Profile: {self._source.profile_name()}  |  "
            f"Uptime {hours:02d}:{minutes:02d}:{secs:02d}  |  "
            f"Active: {active}  |  Events: {self.total_events}  |  "
            f"Filter: {filter_text}{paused_text}"
        )

    def _update_connections_table(self) -> None:
        """Repopulate the active connections table."""
        try:
            table: DataTable[Any] = self.query_one("#connections-table", DataTable)
        except Exception:  # noqa: BLE001
            return
        table.clear()
        self._rendered_session_ids = set()
        sessions = self._source.active_sessions()
        for sess in sessions:
            if not self._session_matches_filter(sess):
                continue
            session_events = self._events_by_session.get(sess.session_id, [])
            last_msg = session_events[-1].message[:40] if session_events else ""
            table.add_row(
                sess.session_id[:8],
                sess.remote_ip,
                sess.country_code or "--",
                sess.protocol.upper(),
                str(sess.local_port),
                f"{sess.duration_seconds:.0f}s",
                str(len(session_events)),
                last_msg,
                key=sess.session_id,
            )
            self._rendered_session_ids.add(sess.session_id)

    def _session_matches_filter(self, session: Session) -> bool:
        """Whether the given session passes the current protocol filter."""
        if self.filter_protocol == "ALL":
            return True
        return session.protocol.upper() == self.filter_protocol

    def _update_event_log(self) -> None:
        """Refresh the event log table with filter+search applied."""
        try:
            table: DataTable[Any] = self.query_one("#event-table", DataTable)
        except Exception:  # noqa: BLE001
            return
        table.clear()
        filtered = [e for e in self._events if self._event_matches(e)]
        for event in list(filtered)[-MAX_LOG_ROWS:]:
            ts = event.timestamp.astimezone().strftime("%H:%M:%S")
            summary = (event.message or event.event_type)[:80]
            table.add_row(
                ts,
                event.protocol.upper(),
                event.remote_ip or "-",
                event.country_code or "--",
                event.event_type,
                summary,
            )

    def _event_matches(self, event: Event) -> bool:
        """Check whether an event passes current filter and search."""
        if self.filter_protocol != "ALL" and event.protocol.upper() != self.filter_protocol:
            return False
        term = self.search_term.strip().lower()
        if not term:
            return True
        haystacks: Iterable[str] = (
            event.remote_ip or "",
            event.message or "",
            event.event_type or "",
            event.username or "",
            event.path or "",
            event.user_agent or "",
        )
        return any(term in (h or "").lower() for h in haystacks)

    def _update_intel_table(self) -> None:
        """Refresh the combined stats/ATT&CK/IOC panel."""
        try:
            table: DataTable[Any] = self.query_one("#intel-table", DataTable)
        except Exception:  # noqa: BLE001
            return
        table.clear()
        table.add_row("Total events", str(self.total_events))
        table.add_row("Unique IPs", str(len(self._ip_counter)))
        for ip, count in self._ip_counter.most_common(3):
            table.add_row(f"IP {ip}", str(count))
        for proto, count in self._protocol_counter.most_common(3):
            table.add_row(f"Proto {proto}", str(count))
        for tid, count in self._technique_counter.most_common(3):
            name = self._technique_names.get(tid, tid)[:25]
            table.add_row(f"ATT&CK {tid}", f"{name} ({count})")
        for kind, count in self._ioc_counter.most_common(3):
            table.add_row(f"IOC {kind}", str(count))

    def _update_guardian_table(self) -> None:
        """Refresh the resource guardian panel."""
        try:
            table: DataTable[Any] = self.query_one("#guardian-table", DataTable)
        except Exception:  # noqa: BLE001
            return
        table.clear()
        snap = self._source.guardian_snapshot()
        if snap:
            cap = snap.get("connections_cap", 0)
            cur = snap.get("connections", 0)
            table.add_row("Connections", f"{cur} / {cap}")
            mem = snap.get("memory_mb", 0.0)
            mem_cap = snap.get("memory_limit_mb", 0.0)
            table.add_row("Memory", f"{mem:.0f} / {mem_cap:.0f} MB")
            if snap.get("should_refuse"):
                table.add_row("Status", "REFUSING")
                if snap.get("refusal_reason"):
                    table.add_row("Reason", str(snap["refusal_reason"])[:40])
            else:
                table.add_row("Status", "accepting")
        rl = self._source.rate_limit_snapshot()
        if rl:
            table.add_row("Tracked IPs", str(rl.get("tracked_ips", 0)))
            table.add_row("Global active", str(rl.get("global_active", 0)))
            table.add_row("Total blocks", str(rl.get("total_blocks", 0)))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def action_cycle_filter(self) -> None:
        """Cycle the protocol filter through the known choices."""
        idx = PROTOCOL_FILTERS.index(self.filter_protocol)
        self.filter_protocol = PROTOCOL_FILTERS[(idx + 1) % len(PROTOCOL_FILTERS)]
        self._append_activity(f"Filter: {self.filter_protocol}")

    def action_open_search(self) -> None:
        """Reveal and focus the search input."""
        search = self.query_one("#search-input", Input)
        search.display = True
        search.focus()

    async def action_generate_report(self) -> None:
        """Trigger the report callback and show a toast."""
        if self._report_callback is None:
            self._append_activity("Report requested (no callback wired)")
            return
        try:
            result = self._report_callback()
            if asyncio.iscoroutine(result):
                result = await result  # type: ignore[assignment]
        except Exception as exc:  # noqa: BLE001
            self._append_activity(f"Report failed: {exc}")
            return
        self._append_activity(f"Report: {result}")

    def action_toggle_pause(self) -> None:
        """Toggle the paused reactive."""
        self.paused = not self.paused
        self._append_activity("Paused" if self.paused else "Resumed")

    # ------------------------------------------------------------------
    # Input handlers
    # ------------------------------------------------------------------
    def on_input_submitted(self, message: Input.Submitted) -> None:
        """Handle search input submission."""
        if message.input.id == "search-input":
            self.search_term = message.value
            message.input.display = False
            message.input.value = ""
            self._append_activity(f"Search: {self.search_term or '(cleared)'}")

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        """Open session detail when a row in the connections table is chosen."""
        if message.data_table.id != "connections-table":
            return
        key = message.row_key.value if message.row_key else None
        if not key:
            return
        session_events = self._events_by_session.get(str(key), [])
        self.push_screen(SessionDetailModal(str(key), session_events))

    def on_key(self, event: events.Key) -> None:
        """Catch ``enter`` on the connections table as a fallback for older tests."""
        if event.key == "escape":
            try:
                search = self.query_one("#search-input", Input)
            except Exception:  # noqa: BLE001
                return
            if search.display:
                search.display = False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _append_activity(self, line: str) -> None:
        """Write a line to the scrolling activity log, if mounted."""
        try:
            log = self.query_one("#activity-log", RichLog)
        except Exception:  # noqa: BLE001
            return
        ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        log.write(f"{ts}  {line}")

    # ------------------------------------------------------------------
    # Test helpers
    # ------------------------------------------------------------------
    def _test_push_event(self, event: Event) -> None:
        """Ingest a single event synchronously (for tests).

        The test harness drives the app without a real engine; this bypasses
        the queue so assertions do not have to race against the consumer.
        """
        self._ingest_event(event)

    def open_session_detail(self, session_id: str) -> None:
        """Programmatically open the session detail modal (for tests)."""
        session_events = self._events_by_session.get(session_id, [])
        self.push_screen(SessionDetailModal(session_id, session_events))
