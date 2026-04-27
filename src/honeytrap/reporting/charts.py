"""Chart generation for HoneyTrap reports.

Each public function takes a list of dicts (or matrix) of data and returns a
base64-encoded PNG image suitable for embedding in HTML via
``<img src="data:image/png;base64,..." />``. Empty inputs return an empty
string so the template can skip the image gracefully.

All charts follow a consistent dark security-console palette:

* Background        #1a1a2e
* Panel             #16213e
* Primary accent    #0f3460 (blue)
* Highlight         #53d2dc (teal)
* Danger            #e94560 (red)
* Text              #e0e0e0
"""

from __future__ import annotations

import base64
import io
import logging
from collections.abc import Iterable
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Palette / theme
# ---------------------------------------------------------------------------
BG = "#1a1a2e"
PANEL = "#16213e"
ACCENT = "#0f3460"
HIGHLIGHT = "#53d2dc"
DANGER = "#e94560"
TEXT = "#e0e0e0"
GRID = "#2a2a4a"

PROTOCOL_COLORS: dict[str, str] = {
    "http": "#53d2dc",
    "https": "#3fb8c4",
    "ssh": "#e94560",
    "ftp": "#f5a742",
    "smtp": "#9c5fbf",
    "mysql": "#4a90d4",
    "smb": "#6fcf97",
    "telnet": "#d46a8f",
}

_DEFAULT_DPI = 100
_DEFAULT_SIZE = (8.0, 4.0)  # 800 x 400 @ 100dpi


def _apply_theme(fig: Figure, ax: Any) -> None:
    """Apply the dark SOC theme to a matplotlib figure/axes."""
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(PANEL)
    for spine in ax.spines.values():
        spine.set_color(GRID)
    ax.tick_params(colors=TEXT, which="both")
    ax.xaxis.label.set_color(TEXT)
    ax.yaxis.label.set_color(TEXT)
    if ax.get_title():
        ax.title.set_color(TEXT)
    ax.grid(True, color=GRID, linestyle="--", linewidth=0.5, alpha=0.6)


def _fig_to_base64(fig: Figure) -> str:
    """Render a figure into a base64-encoded PNG string."""
    buf = io.BytesIO()
    try:
        fig.savefig(
            buf,
            format="png",
            facecolor=fig.get_facecolor(),
            bbox_inches="tight",
            dpi=_DEFAULT_DPI,
        )
    finally:
        plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")


def _empty(message: str = "No data available") -> str:
    """Return a placeholder PNG with a centered message."""
    fig, ax = plt.subplots(figsize=_DEFAULT_SIZE, dpi=_DEFAULT_DPI)
    _apply_theme(fig, ax)
    ax.text(
        0.5,
        0.5,
        message,
        ha="center",
        va="center",
        fontsize=16,
        color=TEXT,
        transform=ax.transAxes,
    )
    ax.set_xticks([])
    ax.set_yticks([])
    return _fig_to_base64(fig)


def _is_empty(data: Iterable[Any] | None) -> bool:
    """Return True if ``data`` has no usable rows."""
    if data is None:
        return True
    try:
        return len(list(data)) == 0  # type: ignore[arg-type]
    except TypeError:
        return True


# ---------------------------------------------------------------------------
# Public chart functions
# ---------------------------------------------------------------------------
def attack_timeline_chart(events_by_hour: list[dict[str, Any]]) -> str:
    """Line chart of event volume per hourly bucket.

    Each dict in ``events_by_hour`` should have ``hour`` (ISO timestamp or
    label string) and ``events`` (int).
    """
    if _is_empty(events_by_hour):
        return _empty("No events recorded yet")

    try:
        labels = [str(row.get("hour", "")) for row in events_by_hour]
        counts = [int(row.get("events", 0)) for row in events_by_hour]
        fig, ax = plt.subplots(figsize=_DEFAULT_SIZE, dpi=_DEFAULT_DPI)
        _apply_theme(fig, ax)
        ax.plot(
            range(len(counts)),
            counts,
            color=HIGHLIGHT,
            linewidth=2.0,
            marker="o",
            markersize=4,
            markerfacecolor=DANGER,
            markeredgecolor=DANGER,
        )
        ax.fill_between(range(len(counts)), counts, color=HIGHLIGHT, alpha=0.15)
        ax.set_title("Attack Volume Over Time", fontsize=14, pad=12)
        ax.set_xlabel("Time")
        ax.set_ylabel("Events")
        step = max(1, len(labels) // 12)
        ax.set_xticks(range(0, len(labels), step))
        ax.set_xticklabels(
            [labels[i] for i in range(0, len(labels), step)],
            rotation=45,
            ha="right",
            fontsize=8,
        )
        return _fig_to_base64(fig)
    except Exception as exc:  # noqa: BLE001
        logger.warning("attack_timeline_chart failed: %s", exc)
        return ""


def protocol_distribution_chart(events_by_protocol: list[dict[str, Any]]) -> str:
    """Horizontal bar chart of events per protocol."""
    if _is_empty(events_by_protocol):
        return _empty("No protocol activity")

    try:
        labels = [str(row.get("protocol", "")).lower() for row in events_by_protocol]
        counts = [int(row.get("events", 0)) for row in events_by_protocol]
        colors = [PROTOCOL_COLORS.get(p, HIGHLIGHT) for p in labels]
        fig, ax = plt.subplots(figsize=_DEFAULT_SIZE, dpi=_DEFAULT_DPI)
        _apply_theme(fig, ax)
        y_pos = range(len(labels))
        ax.barh(y_pos, counts, color=colors, edgecolor=GRID)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels([p.upper() for p in labels])
        ax.invert_yaxis()
        ax.set_title("Events by Protocol", fontsize=14, pad=12)
        ax.set_xlabel("Events")
        return _fig_to_base64(fig)
    except Exception as exc:  # noqa: BLE001
        logger.warning("protocol_distribution_chart failed: %s", exc)
        return ""


def country_distribution_chart(country_data: list[dict[str, Any]], top_n: int = 15) -> str:
    """Horizontal bar chart of the top attacking countries."""
    if _is_empty(country_data):
        return _empty("No geographic data")

    try:
        rows = sorted(country_data, key=lambda r: int(r.get("events", 0)), reverse=True)[:top_n]
        labels = [
            f"{row.get('country_code', '??')} {row.get('country_name', '')}".strip() for row in rows
        ]
        counts = [int(row.get("events", 0)) for row in rows]
        fig, ax = plt.subplots(figsize=_DEFAULT_SIZE, dpi=_DEFAULT_DPI)
        _apply_theme(fig, ax)
        y_pos = range(len(labels))
        ax.barh(y_pos, counts, color=HIGHLIGHT, edgecolor=GRID)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(labels, fontsize=9)
        ax.invert_yaxis()
        ax.set_title(f"Top {len(labels)} Attacking Countries", fontsize=14, pad=12)
        ax.set_xlabel("Events")
        return _fig_to_base64(fig)
    except Exception as exc:  # noqa: BLE001
        logger.warning("country_distribution_chart failed: %s", exc)
        return ""


def attack_technique_chart(techniques: list[dict[str, Any]], top_n: int = 10) -> str:
    """Horizontal bar chart of the most-observed MITRE ATT&CK techniques."""
    if _is_empty(techniques):
        return _empty("No ATT&CK techniques observed")

    try:
        rows = sorted(techniques, key=lambda r: int(r.get("events", 0)), reverse=True)[:top_n]
        labels = [f"{row.get('technique_id', '')} {row.get('technique_name', '')}" for row in rows]
        counts = [int(row.get("events", 0)) for row in rows]
        fig, ax = plt.subplots(figsize=_DEFAULT_SIZE, dpi=_DEFAULT_DPI)
        _apply_theme(fig, ax)
        y_pos = range(len(labels))
        ax.barh(y_pos, counts, color=DANGER, edgecolor=GRID)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(labels, fontsize=9)
        ax.invert_yaxis()
        ax.set_title(f"Top {len(labels)} MITRE ATT&CK Techniques", fontsize=14, pad=12)
        ax.set_xlabel("Events")
        return _fig_to_base64(fig)
    except Exception as exc:  # noqa: BLE001
        logger.warning("attack_technique_chart failed: %s", exc)
        return ""


def tactic_heatmap(tactic_data: list[dict[str, Any]]) -> str:
    """Horizontal heat bar across ATT&CK tactics colored by event volume."""
    if _is_empty(tactic_data):
        return _empty("No ATT&CK tactic coverage")

    try:
        rows = sorted(tactic_data, key=lambda r: int(r.get("events", 0)), reverse=True)
        labels = [str(row.get("tactic", "unknown")) for row in rows]
        counts = [int(row.get("events", 0)) for row in rows]
        max_count = max(counts) if counts else 1
        fig, ax = plt.subplots(figsize=_DEFAULT_SIZE, dpi=_DEFAULT_DPI)
        _apply_theme(fig, ax)
        cmap = plt.get_cmap("plasma")
        colors = [cmap(c / max_count) for c in counts]
        bars = ax.barh(range(len(labels)), counts, color=colors, edgecolor=GRID)
        ax.set_yticks(list(range(len(labels))))
        ax.set_yticklabels(labels, fontsize=9)
        ax.invert_yaxis()
        ax.set_title("ATT&CK Tactic Coverage", fontsize=14, pad=12)
        ax.set_xlabel("Events")
        for bar, count in zip(bars, counts, strict=False):
            ax.text(
                bar.get_width(),
                bar.get_y() + bar.get_height() / 2,
                f" {count}",
                va="center",
                color=TEXT,
                fontsize=8,
            )
        return _fig_to_base64(fig)
    except Exception as exc:  # noqa: BLE001
        logger.warning("tactic_heatmap failed: %s", exc)
        return ""


def credential_chart(top_credentials: list[dict[str, Any]], top_n: int = 10) -> str:
    """Bar chart of the most-tried username:password combinations."""
    if _is_empty(top_credentials):
        return _empty("No credential attempts logged")

    try:
        rows = top_credentials[:top_n]
        labels = [f"{(row.get('username') or '-')}:{(row.get('password') or '-')}" for row in rows]
        counts = [int(row.get("attempts", 0)) for row in rows]
        fig, ax = plt.subplots(figsize=_DEFAULT_SIZE, dpi=_DEFAULT_DPI)
        _apply_theme(fig, ax)
        y_pos = range(len(labels))
        ax.barh(y_pos, counts, color=ACCENT, edgecolor=HIGHLIGHT)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(labels, fontsize=9, family="monospace")
        ax.invert_yaxis()
        ax.set_title(f"Top {len(labels)} Credential Attempts", fontsize=14, pad=12)
        ax.set_xlabel("Attempts")
        return _fig_to_base64(fig)
    except Exception as exc:  # noqa: BLE001
        logger.warning("credential_chart failed: %s", exc)
        return ""


def hourly_heatmap(matrix: list[list[int]] | list[dict[str, Any]]) -> str:
    """7x24 heatmap: rows are weekdays (Mon-Sun), cols are hours of day.

    Accepts either a 7x24 list-of-lists of ints or a list of
    ``{"day": 0..6, "hour": 0..23, "events": int}`` dicts.
    """
    if _is_empty(matrix):
        return _empty("No hourly pattern data")

    try:
        grid = [[0] * 24 for _ in range(7)]
        if matrix and isinstance(matrix[0], dict):
            for row in matrix:  # type: ignore[assignment]
                d = int(row.get("day", 0))  # type: ignore[union-attr]
                h = int(row.get("hour", 0))  # type: ignore[union-attr]
                if 0 <= d < 7 and 0 <= h < 24:
                    grid[d][h] = int(row.get("events", 0))  # type: ignore[union-attr]
        else:
            for d in range(min(7, len(matrix))):
                row = matrix[d]  # type: ignore[index]
                for h in range(min(24, len(row))):  # type: ignore[arg-type]
                    grid[d][h] = int(row[h])  # type: ignore[index]

        if not any(any(row) for row in grid):
            return _empty("No hourly pattern data")

        fig, ax = plt.subplots(figsize=_DEFAULT_SIZE, dpi=_DEFAULT_DPI)
        _apply_theme(fig, ax)
        im = ax.imshow(grid, aspect="auto", cmap="magma", interpolation="nearest")
        ax.set_xticks(range(0, 24, 2))
        ax.set_xticklabels([f"{h:02d}" for h in range(0, 24, 2)], fontsize=8)
        ax.set_yticks(range(7))
        ax.set_yticklabels(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], fontsize=9)
        ax.set_title("Attack Activity — Day of Week × Hour of Day", fontsize=13, pad=12)
        ax.set_xlabel("Hour (UTC)")
        cbar = fig.colorbar(im, ax=ax)
        cbar.ax.yaxis.set_tick_params(color=TEXT)
        for label in cbar.ax.yaxis.get_ticklabels():
            label.set_color(TEXT)
        cbar.outline.set_edgecolor(GRID)
        ax.grid(False)
        return _fig_to_base64(fig)
    except Exception as exc:  # noqa: BLE001
        logger.warning("hourly_heatmap failed: %s", exc)
        return ""


__all__ = [
    "attack_timeline_chart",
    "protocol_distribution_chart",
    "country_distribution_chart",
    "attack_technique_chart",
    "tactic_heatmap",
    "credential_chart",
    "hourly_heatmap",
]
