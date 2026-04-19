"""Geo-response comparison analysis.

Compares attacker behavior segmented by country to answer the research
question: *do attackers behave differently when they see a server with
their own locale vs. a "foreign" one?*

Key output metrics per country:

* average commands per session
* average distinct paths hit
* fraction of sessions that escalated beyond a single probe
* credential-attempt count
"""

from __future__ import annotations

from typing import Any

from honeytrap.logging.database import AttackDatabase


class GeoComparator:
    """Compute per-country attacker-behavior summaries."""

    def __init__(self, database: AttackDatabase) -> None:
        """Initialize the geo-comparison analyzer with the attack database."""
        self.database = database

    def compare(self) -> list[dict[str, Any]]:
        """Return a list of per-country rows sorted by event volume."""
        rows = self.database.geo_behavior()
        results: list[dict[str, Any]] = []
        for row in rows:
            total = row.get("events", 0) or 0
            sessions = row.get("sessions", 0) or 0
            auth = row.get("auth_attempts", 0) or 0
            exploits = row.get("exploits", 0) or 0
            unique_ips = row.get("unique_ips", 0) or 0
            results.append(
                {
                    "country_code": row.get("country_code") or "XX",
                    "country_name": row.get("country_name") or "Unknown",
                    "total_events": total,
                    "unique_ips": unique_ips,
                    "sessions": sessions,
                    "auth_attempts": auth,
                    "exploit_attempts": exploits,
                    "auth_ratio": round(auth / total, 3) if total else 0.0,
                    "exploit_ratio": round(exploits / total, 3) if total else 0.0,
                    "events_per_ip": round(total / unique_ips, 2) if unique_ips else 0.0,
                    "events_per_session": round(total / sessions, 2) if sessions else 0.0,
                }
            )
        return results
