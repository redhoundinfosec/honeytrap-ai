"""UI layer: Rich Live and Textual TUI dashboards.

The legacy :class:`Dashboard` (Rich Live) is always importable. The Textual
app is imported lazily via :func:`load_textual_app` so the heavy dependency
is only pulled in when a user actually selects ``textual`` dashboard mode.
"""

from __future__ import annotations

from honeytrap.ui.dashboard import Dashboard

__all__ = ["Dashboard", "load_textual_app"]


def load_textual_app() -> tuple[type, type, type]:
    """Lazily import and return Textual dashboard classes.

    Returns:
        A 3-tuple ``(HoneyTrapTUI, EngineDashboardSource, DashboardEventSource)``.
    """
    from honeytrap.ui.dashboard_tui import (
        DashboardEventSource,
        EngineDashboardSource,
        HoneyTrapTUI,
    )

    return HoneyTrapTUI, EngineDashboardSource, DashboardEventSource
