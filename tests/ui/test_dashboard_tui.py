"""Tests for the Textual TUI dashboard (``honeytrap.ui.dashboard_tui``).

The tests drive :class:`HoneyTrapTUI` through Textual's ``App.run_test()``
async harness with a mock :class:`DashboardEventSource` so no real engine
is needed.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from honeytrap.core.session import Session
from honeytrap.logging.models import Event
from honeytrap.ui.dashboard_tui import (
    PROTOCOL_FILTERS,
    DashboardEventSource,
    HoneyTrapTUI,
    SessionDetailModal,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockDashboardSource:
    """Minimal in-memory source satisfying :class:`DashboardEventSource`."""

    def __init__(self) -> None:
        self.queues: list[asyncio.Queue[Event]] = []
        self.sessions: list[Session] = []
        self.profile = "test_profile"
        self.guardian: dict[str, Any] = {}
        self.rate_limit: dict[str, Any] = {}
        self.unsubscribed: list[asyncio.Queue[Event]] = []

    def subscribe(self) -> asyncio.Queue[Event]:
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=1000)
        self.queues.append(q)
        return q

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        self.unsubscribed.append(queue)

    def active_sessions(self) -> list[Session]:
        return list(self.sessions)

    def profile_name(self) -> str:
        return self.profile

    def guardian_snapshot(self) -> dict[str, Any]:
        return dict(self.guardian)

    def rate_limit_snapshot(self) -> dict[str, Any]:
        return dict(self.rate_limit)


def _make_event(
    protocol: str = "http",
    remote_ip: str = "1.2.3.4",
    event_type: str = "connection",
    message: str = "hello",
    session_id: str = "sess-a",
    data: dict[str, Any] | None = None,
) -> Event:
    """Build a synthetic :class:`Event` for tests."""
    return Event(
        protocol=protocol,
        event_type=event_type,
        remote_ip=remote_ip,
        message=message,
        session_id=session_id,
        timestamp=datetime.now(timezone.utc),
        data=data or {},
    )


def _make_session(
    session_id: str = "sess-a",
    remote_ip: str = "1.2.3.4",
    protocol: str = "http",
) -> Session:
    """Build a synthetic :class:`Session` for tests."""
    return Session(
        session_id=session_id,
        remote_ip=remote_ip,
        remote_port=45000,
        protocol=protocol,
        local_port=80,
        country_code="US",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_app_mounts_without_errors() -> None:
    """The app mounts cleanly when driven by a mock source."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert source.queues, "subscribe() should have been called on mount"


@pytest.mark.asyncio
async def test_panels_present_after_mount() -> None:
    """Each required panel widget is mounted."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        for widget_id in (
            "#status-bar",
            "#connections-table",
            "#event-table",
            "#intel-table",
            "#guardian-table",
            "#activity-log",
            "#search-input",
        ):
            assert app.query(widget_id), f"missing widget {widget_id}"


@pytest.mark.asyncio
async def test_event_log_updates_on_push() -> None:
    """Pushing a new event makes the event log render a row for it."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app._test_push_event(_make_event(message="probe"))
        await pilot.pause(0.05)
        table = app.query_one("#event-table")
        assert table.row_count >= 1


@pytest.mark.asyncio
async def test_connections_table_add_and_remove() -> None:
    """Connection rows appear on new session and vanish on session close."""
    source = MockDashboardSource()
    sess = _make_session()
    source.sessions.append(sess)
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.05)
        table = app.query_one("#connections-table")
        assert table.row_count == 1
        source.sessions.clear()
        await pilot.pause(0.1)
        assert table.row_count == 0


@pytest.mark.asyncio
async def test_filter_cycle_narrows_events() -> None:
    """``f`` cycles the filter and narrows the event log accordingly."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app._test_push_event(_make_event(protocol="http", session_id="h"))
        app._test_push_event(_make_event(protocol="ssh", session_id="s"))
        await pilot.pause(0.05)
        total_rows = app.query_one("#event-table").row_count
        assert total_rows == 2

        app.action_cycle_filter()  # ALL -> HTTP
        await pilot.pause(0.05)
        assert app.filter_protocol == "HTTP"
        assert app.query_one("#event-table").row_count == 1


@pytest.mark.asyncio
async def test_search_filters_events_by_substring() -> None:
    """Submitting a search term filters the event log."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app._test_push_event(_make_event(message="needle alpha", session_id="a"))
        app._test_push_event(_make_event(message="haystack beta", session_id="b"))
        app.search_term = "needle"
        await pilot.pause(0.05)
        table = app.query_one("#event-table")
        assert table.row_count == 1


@pytest.mark.asyncio
async def test_pause_toggles_update() -> None:
    """Pressing ``p`` toggles the paused reactive and freezes ingestion."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app._test_push_event(_make_event(message="first"))
        await pilot.pause(0.05)
        baseline = app.query_one("#event-table").row_count
        app.action_toggle_pause()
        await pilot.pause(0.05)
        assert app.paused
        app._test_push_event(_make_event(message="should-be-ignored"))
        await pilot.pause(0.05)
        assert app.query_one("#event-table").row_count == baseline
        app.action_toggle_pause()
        await pilot.pause(0.05)
        assert not app.paused


@pytest.mark.asyncio
async def test_enter_opens_session_detail_modal() -> None:
    """Selecting a connection row opens the session-detail modal."""
    source = MockDashboardSource()
    sess = _make_session()
    source.sessions.append(sess)
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.05)
        app.open_session_detail(sess.session_id)
        await pilot.pause(0.05)
        assert isinstance(app.screen, SessionDetailModal)


@pytest.mark.asyncio
async def test_session_detail_shows_attack_and_iocs() -> None:
    """The modal shows ATT&CK techniques and IOCs extracted from events."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        evt = _make_event(
            session_id="sess-x",
            data={
                "attack_techniques": [{"technique_id": "T1110", "technique_name": "Brute Force"}],
                "iocs": [{"type": "ip", "value": "9.9.9.9"}],
            },
        )
        app._test_push_event(evt)
        app.open_session_detail("sess-x")
        await pilot.pause(0.05)
        modal = app.screen
        assert isinstance(modal, SessionDetailModal)
        attack = modal.query_one("#session-attack").render()  # type: ignore[attr-defined]
        iocs = modal.query_one("#session-iocs").render()  # type: ignore[attr-defined]
        assert "T1110" in str(attack)
        assert "9.9.9.9" in str(iocs)


@pytest.mark.asyncio
async def test_escape_closes_modal() -> None:
    """Escape dismisses the session detail modal."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.open_session_detail("sess-y")
        await pilot.pause(0.05)
        assert isinstance(app.screen, SessionDetailModal)
        await pilot.press("escape")
        await pilot.pause(0.05)
        assert not isinstance(app.screen, SessionDetailModal)


@pytest.mark.asyncio
async def test_quit_exits_cleanly() -> None:
    """``q`` cleanly exits and unsubscribes from the source."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.press("q")
        await pilot.pause(0.05)
    # After shutdown the mock should have seen unsubscribe.
    assert source.unsubscribed, "unsubscribe() should be called on exit"


@pytest.mark.asyncio
async def test_report_shortcut_invokes_callback() -> None:
    """``r`` invokes the report callback exactly once."""
    source = MockDashboardSource()
    report = MagicMock(return_value="report ok")
    app = HoneyTrapTUI(source, report_callback=report, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await app.action_generate_report()
        await pilot.pause(0.05)
    report.assert_called_once()


@pytest.mark.asyncio
async def test_narrow_terminal_shows_warning() -> None:
    """A terminal < 80 cols shows the narrow-mode warning."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(60, 30)) as pilot:
        await pilot.pause(0.1)
        warning = app.query_one("#narrow-warning")
        assert warning.display is True
        assert "too narrow" in str(warning.render()).lower()


@pytest.mark.asyncio
async def test_high_throughput_does_not_drop_app() -> None:
    """Pushing 500 events in quick succession must not destabilize the app."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        for i in range(500):
            app._test_push_event(
                _make_event(
                    message=f"burst-{i}",
                    session_id=f"s{i % 10}",
                    protocol="http",
                )
            )
        await pilot.pause(0.1)
        assert app.total_events >= 500
        # Event log is capped; app still responsive
        assert app.query_one("#event-table") is not None


@pytest.mark.asyncio
async def test_cycle_filter_iterates_all_protocols() -> None:
    """Cycling filter visits every configured protocol and wraps around."""
    source = MockDashboardSource()
    app = HoneyTrapTUI(source, update_interval=0.01)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        seen = [app.filter_protocol]
        for _ in range(len(PROTOCOL_FILTERS) - 1):
            app.action_cycle_filter()
            await pilot.pause(0.01)
            seen.append(app.filter_protocol)
        assert set(seen) == set(PROTOCOL_FILTERS)


def test_dashboard_event_source_protocol_has_expected_methods() -> None:
    """The Protocol class lists every method the app relies on."""
    for method in (
        "subscribe",
        "unsubscribe",
        "active_sessions",
        "profile_name",
        "guardian_snapshot",
        "rate_limit_snapshot",
    ):
        assert hasattr(DashboardEventSource, method)


def test_cli_none_mode_does_not_import_textual() -> None:
    """Launching the CLI in ``--dashboard-mode none`` does not load textual.

    We verify by importing the CLI module and calling ``_resolve_dashboard_mode``
    in a subprocess that blocks the textual import — the result should still
    be ``"none"`` without raising.
    """
    script = textwrap.dedent(
        """
        import sys
        # Block textual from being importable to prove none-mode doesn't need it.
        class _Blocker:
            def find_module(self, name, path=None):
                if name == "textual" or name.startswith("textual."):
                    return self
                return None
            def load_module(self, name):
                raise ImportError(f"blocked: {name}")
        sys.meta_path.insert(0, _Blocker())

        from honeytrap.cli import _resolve_dashboard_mode
        mode = _resolve_dashboard_mode("none")
        assert mode == "none", mode
        assert "textual" not in sys.modules, list(sys.modules)
        print("OK")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_cli_rich_mode_launches_legacy_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    """``--dashboard-mode rich`` routes through :func:`_run_rich_dashboard`."""
    from honeytrap import cli

    called: dict[str, int] = {"rich": 0, "textual": 0}

    async def _fake_rich(engine: Any, shutdown_event: asyncio.Event) -> None:
        called["rich"] += 1
        shutdown_event.set()

    async def _fake_textual(engine: Any, shutdown_event: asyncio.Event) -> None:
        called["textual"] += 1
        shutdown_event.set()

    monkeypatch.setattr(cli, "_run_rich_dashboard", _fake_rich)
    monkeypatch.setattr(cli, "_run_textual_dashboard", _fake_textual)

    engine = MagicMock()

    async def _fake_start() -> None:
        return None

    async def _fake_stop() -> None:
        return None

    engine.start.side_effect = _fake_start
    engine.stop.side_effect = _fake_stop
    engine.profile.name = "test"
    engine.active_ports = []
    engine.skipped_ports = []

    monkeypatch.setattr(cli, "Engine", lambda *a, **kw: engine)

    fake_profile = MagicMock()
    fake_profile.name = "test"
    monkeypatch.setattr(cli, "load_profile", lambda *_a, **_kw: fake_profile)

    cfg = MagicMock()
    cfg.general.dashboard = True
    cfg.general.log_directory = "/tmp/honeytrap-test"
    cfg.ai.enabled = False

    asyncio.run(cli._run_engine(cfg, "web_server", use_dashboard=True, dashboard_mode="rich"))
    assert called["rich"] == 1
    assert called["textual"] == 0
