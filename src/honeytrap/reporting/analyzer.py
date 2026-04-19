"""Aggregate-level attack pattern analysis.

Everything here reads from the SQLite store. The analyzer is stateless:
call it when you need a snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from honeytrap.logging.database import AttackDatabase


@dataclass
class AnalysisSnapshot:
    """Bundle returned by :meth:`Analyzer.snapshot`."""

    total_events: int
    unique_ips: int
    top_attackers: list[dict[str, Any]]
    country_distribution: list[dict[str, Any]]
    top_credentials: list[dict[str, Any]]
    top_paths: list[dict[str, Any]]
    events_by_protocol: list[dict[str, Any]]
    events_by_type: list[dict[str, Any]]
    geo_behavior: list[dict[str, Any]]
    novel_patterns: list[dict[str, Any]]


class Analyzer:
    """Produce aggregate snapshots of honeypot activity."""

    def __init__(self, database: AttackDatabase) -> None:
        """Initialize the attack analyzer with the attack database."""
        self.database = database

    def snapshot(self, *, top_n: int = 20) -> AnalysisSnapshot:
        """Build a single analysis snapshot."""
        return AnalysisSnapshot(
            total_events=self.database.count(),
            unique_ips=self.database.unique_ip_count(),
            top_attackers=self.database.top_attackers(top_n),
            country_distribution=self.database.country_distribution(),
            top_credentials=self.database.top_credentials(top_n),
            top_paths=self.database.top_paths(top_n),
            events_by_protocol=self.database.events_by_protocol(),
            events_by_type=self.database.events_by_type(),
            geo_behavior=self.database.geo_behavior(),
            novel_patterns=self._novel_patterns(top_n),
        )

    # ------------------------------------------------------------------
    # Novel pattern detection
    # ------------------------------------------------------------------
    def _novel_patterns(self, limit: int) -> list[dict[str, Any]]:
        """Return recent events that don't match any known rule tag.

        The heuristic: look at recent events with ``event_type`` of
        ``http_request`` that hit paths we haven't classified yet, or
        ``shell_command`` entries that contain unusual patterns. In a larger
        deployment we'd feed these through an LLM for tagging; for the MVP
        we flag entries with uncommon paths / commands.
        """
        recent = self.database.recent_events(limit * 5)
        seen_paths: dict[str, int] = {}
        seen_cmds: dict[str, int] = {}
        for row in recent:
            path = (row.get("path") or "").strip()
            if path and path != "/":
                seen_paths[path] = seen_paths.get(path, 0) + 1
            msg = row.get("message") or ""
            if msg.startswith("Command:"):
                cmd = msg.removeprefix("Command:").strip()
                if cmd:
                    seen_cmds[cmd] = seen_cmds.get(cmd, 0) + 1

        flagged: list[dict[str, Any]] = []
        for path, count in sorted(seen_paths.items(), key=lambda kv: kv[1])[:limit]:
            if count <= 2:
                flagged.append({"kind": "path", "value": path, "count": count})
        for cmd, count in sorted(seen_cmds.items(), key=lambda kv: kv[1])[:limit]:
            if count <= 2:
                flagged.append({"kind": "command", "value": cmd, "count": count})
        return flagged[:limit]
