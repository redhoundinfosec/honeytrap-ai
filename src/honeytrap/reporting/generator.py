"""Report generator: terminal and HTML output.

Typical usage::

    gen = ReportGenerator(config, database)
    gen.render_terminal()           # prints a Rich-formatted report
    gen.render_html(Path("out.html"))  # writes a standalone HTML file
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from honeytrap.core.config import Config
from honeytrap.logging.database import AttackDatabase
from honeytrap.reporting.analyzer import AnalysisSnapshot, Analyzer
from honeytrap.reporting.geo_comparison import GeoComparator

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class ReportGenerator:
    """Compile and render honeypot reports."""

    def __init__(self, config: Config, database: AttackDatabase) -> None:
        """Initialize the report generator with database and analyzer references."""
        self.config = config
        self.database = database
        self.analyzer = Analyzer(database)
        self.geo_compare = GeoComparator(database)
        self._jinja = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    # ------------------------------------------------------------------
    # Terminal
    # ------------------------------------------------------------------
    def render_terminal(self, console: Console | None = None) -> None:
        """Print the report to the terminal via Rich."""
        con = console or Console()
        snap = self.analyzer.snapshot(top_n=self.config.reporting.top_n_attackers)
        geo_rows = self.geo_compare.compare()

        con.rule("[bold yellow]🍯 HoneyTrap AI — Attack Report")
        con.print(
            Panel.fit(
                f"Generated at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
                f"Total events: {snap.total_events}\n"
                f"Unique attacker IPs: {snap.unique_ips}",
                title="Executive Summary",
            )
        )

        def _table(title: str, cols: list[str], rows: list[list[Any]]) -> Table:
            table = Table(title=title)
            for col in cols:
                table.add_column(col)
            for r in rows:
                table.add_row(*[str(v) for v in r])
            return table

        con.print(
            _table(
                "Top Attackers",
                ["IP", "Country", "Events", "Protocols"],
                [
                    [
                        a["remote_ip"],
                        f"{a['country_code']} {a['country_name']}",
                        a["events"],
                        a.get("protocol_list", ""),
                    ]
                    for a in snap.top_attackers
                ],
            )
        )
        con.print(
            _table(
                "Top Credentials",
                ["Username", "Password", "Attempts"],
                [
                    [c["username"] or "-", c["password"] or "-", c["attempts"]]
                    for c in snap.top_credentials
                ],
            )
        )
        con.print(
            _table(
                "Country Distribution",
                ["Country", "Events", "Unique IPs"],
                [
                    [f"{c['country_code']} {c['country_name']}", c["events"], c["unique_ips"]]
                    for c in snap.country_distribution
                ],
            )
        )
        con.print(
            _table(
                "Events by Protocol",
                ["Protocol", "Events"],
                [[p["protocol"], p["events"]] for p in snap.events_by_protocol],
            )
        )
        con.print(
            _table(
                "Top Requested Paths",
                ["Path", "Hits"],
                [[p["path"], p["hits"]] for p in snap.top_paths],
            )
        )
        con.print(
            _table(
                "Geo-Response Comparison",
                [
                    "Country",
                    "Events",
                    "Sessions",
                    "Unique IPs",
                    "Auth",
                    "Exploit",
                    "Events/IP",
                    "Events/Session",
                ],
                [
                    [
                        f"{g['country_code']} {g['country_name']}",
                        g["total_events"],
                        g["sessions"],
                        g["unique_ips"],
                        g["auth_attempts"],
                        g["exploit_attempts"],
                        g["events_per_ip"],
                        g["events_per_session"],
                    ]
                    for g in geo_rows
                ],
            )
        )
        con.print(
            _table(
                "Novel Patterns",
                ["Kind", "Value", "Count"],
                [
                    [n["kind"], n["value"], n["count"]]
                    for n in snap.novel_patterns
                ],
            )
        )
        con.print(
            _table(
                "MITRE ATT&CK — Observed Techniques",
                ["ID", "Name", "Tactic", "Events", "Unique IPs"],
                [
                    [
                        t["technique_id"],
                        t["technique_name"],
                        t["tactic"],
                        t["events"],
                        t["unique_ips"],
                    ]
                    for t in snap.top_techniques
                ],
            )
        )
        con.print(
            _table(
                "ATT&CK Tactic Distribution",
                ["Tactic", "Events", "Techniques"],
                [
                    [t["tactic"], t["events"], t["techniques"]]
                    for t in snap.tactic_distribution
                ],
            )
        )
        con.print(
            _table(
                "Indicators of Compromise — Summary",
                ["Type", "Unique Values", "Sightings"],
                [
                    [i["type"], i["unique_values"], i["sightings"]]
                    for i in snap.ioc_summary
                ],
            )
        )
        con.print(
            _table(
                "Top IOCs",
                ["Type", "Value", "Sightings"],
                [
                    [i["type"], i["value"][:80], i["sightings"]]
                    for i in snap.top_iocs
                ],
            )
        )

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def render_html(self, output_path: Path | str) -> Path:
        """Write a standalone HTML report. Returns the output path."""
        snap = self.analyzer.snapshot(top_n=self.config.reporting.top_n_attackers)
        geo_rows = self.geo_compare.compare()

        context = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "total_events": snap.total_events,
            "unique_ips": snap.unique_ips,
            "top_attackers": snap.top_attackers,
            "top_credentials": snap.top_credentials,
            "country_distribution": snap.country_distribution,
            "top_paths": snap.top_paths,
            "events_by_protocol": snap.events_by_protocol,
            "events_by_type": snap.events_by_type,
            "geo_rows": geo_rows,
            "novel_patterns": snap.novel_patterns,
            "top_techniques": snap.top_techniques,
            "tactic_distribution": snap.tactic_distribution,
            "technique_to_attacker": snap.technique_to_attacker,
            "ioc_summary": snap.ioc_summary,
            "top_iocs": snap.top_iocs,
            "iocs_by_type": snap.iocs_by_type,
        }

        try:
            template = self._jinja.get_template("report.html")
            html = template.render(**context)
        except Exception as exc:  # noqa: BLE001
            logger.warning("HTML template render failed: %s", exc)
            html = self._minimal_html(context)

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        return out

    @staticmethod
    def _minimal_html(context: dict[str, Any]) -> str:
        """Fallback if the Jinja template can't load."""
        return (
            "<html><head><title>HoneyTrap Report</title></head><body>"
            f"<h1>HoneyTrap Report</h1><p>Generated {context['generated_at']}</p>"
            f"<p>Total events: {context['total_events']}</p>"
            f"<p>Unique IPs: {context['unique_ips']}</p>"
            "</body></html>"
        )

    def snapshot(self) -> AnalysisSnapshot:
        """Convenience passthrough for tests."""
        return self.analyzer.snapshot(top_n=self.config.reporting.top_n_attackers)
