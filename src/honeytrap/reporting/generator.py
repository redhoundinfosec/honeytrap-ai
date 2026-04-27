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
from honeytrap.reporting import charts as charts_mod
from honeytrap.reporting.analyzer import AnalysisSnapshot, Analyzer
from honeytrap.reporting.geo_comparison import GeoComparator

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

try:
    from honeytrap import __version__ as _HONEYTRAP_VERSION  # noqa: N812
except Exception:  # noqa: BLE001
    _HONEYTRAP_VERSION = "0.1.0"


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
                [[n["kind"], n["value"], n["count"]] for n in snap.novel_patterns],
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
                [[t["tactic"], t["events"], t["techniques"]] for t in snap.tactic_distribution],
            )
        )
        con.print(
            _table(
                "Indicators of Compromise — Summary",
                ["Type", "Unique Values", "Sightings"],
                [[i["type"], i["unique_values"], i["sightings"]] for i in snap.ioc_summary],
            )
        )
        con.print(
            _table(
                "Top IOCs",
                ["Type", "Value", "Sightings"],
                [[i["type"], i["value"][:80], i["sightings"]] for i in snap.top_iocs],
            )
        )

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def _build_charts(self, snap: AnalysisSnapshot) -> dict[str, str]:
        """Render every chart from a snapshot, returning base64 PNG strings.

        Any chart that raises is logged and swapped for an empty string so the
        rest of the report renders regardless.
        """
        specs = [
            ("timeline", charts_mod.attack_timeline_chart, (snap.events_by_hour,)),
            ("protocol", charts_mod.protocol_distribution_chart, (snap.events_by_protocol,)),
            ("country", charts_mod.country_distribution_chart, (snap.country_distribution,)),
            ("technique", charts_mod.attack_technique_chart, (snap.top_techniques,)),
            ("tactic", charts_mod.tactic_heatmap, (snap.tactic_distribution,)),
            ("credentials", charts_mod.credential_chart, (snap.top_credentials,)),
            ("hourly", charts_mod.hourly_heatmap, (snap.hourly_heatmap,)),
        ]
        out: dict[str, str] = {}
        for name, fn, args in specs:
            try:
                out[name] = fn(*args)
            except Exception as exc:  # noqa: BLE001
                logger.warning("chart %s failed: %s", name, exc)
                out[name] = ""
        return out

    def _build_html(self) -> tuple[str, dict[str, Any]]:
        """Build the full HTML report string and return (html, context)."""
        snap = self.analyzer.snapshot(top_n=self.config.reporting.top_n_attackers)
        geo_rows = self.geo_compare.compare()
        chart_images = self._build_charts(snap)

        context: dict[str, Any] = {
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
            "events_by_hour": snap.events_by_hour,
            "time_range": snap.time_range,
            "charts": chart_images,
            "version": _HONEYTRAP_VERSION,
        }

        try:
            template = self._jinja.get_template("report.html")
            html = template.render(**context)
        except Exception as exc:  # noqa: BLE001
            logger.warning("HTML template render failed: %s", exc)
            html = self._minimal_html(context)
        return html, context

    def render_html(self, output_path: Path | str) -> Path:
        """Write a standalone HTML report. Returns the output path."""
        html, _ = self._build_html()
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        return out

    def render_html_with_sessions(
        self,
        output_path: Path | str,
        session_store: Any,
        *,
        top_n: int = 10,
        redact: bool = True,
    ) -> Path:
        """Render the main report alongside per-session forensic pages.

        Materializes a ``sessions/`` subdirectory next to the report
        with one ``<session_id>.html`` page, a ``<session_id>.pcap``
        export, and a ``<session_id>.jsonl.gz`` JSONL export per
        session. Links are appended to the main report at the end.

        Args:
            output_path: Path for the main report HTML file.
            session_store: Any :class:`SessionStore` implementation.
            top_n: Number of most-recent sessions to materialize.
            redact: Redact credentials in timeline descriptions.
        """
        from honeytrap.forensics.pcap import PcapWriter, SessionFlow
        from honeytrap.forensics.recorder import serialize_jsonl
        from honeytrap.forensics.timeline import Timeline

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        sessions_dir = out.parent / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)

        sessions = session_store.list_sessions()[:top_n]
        session_links: list[dict[str, str]] = []
        for meta in sessions:
            frames = session_store.load_frames(meta.session_id)
            timeline = Timeline.for_session(session_store, meta.session_id, redact=redact)
            page = timeline.to_html(title=f"Session {meta.session_id}")
            page_path = sessions_dir / f"{meta.session_id}.html"
            page_path.write_text(page, encoding="utf-8")
            pcap_path = sessions_dir / f"{meta.session_id}.pcap"
            with pcap_path.open("wb") as fh:
                writer = PcapWriter(fh)
                writer.write_session(SessionFlow(metadata=meta, frames=frames))
            jsonl_path = sessions_dir / f"{meta.session_id}.jsonl.gz"
            jsonl_path.write_bytes(serialize_jsonl(meta, frames))
            session_links.append(
                {
                    "session_id": meta.session_id,
                    "ip": meta.remote_ip,
                    "protocol": meta.protocol,
                    "frames": str(meta.frame_count),
                    "page": f"sessions/{meta.session_id}.html",
                    "pcap": f"sessions/{meta.session_id}.pcap",
                    "jsonl": f"sessions/{meta.session_id}.jsonl.gz",
                }
            )

        html, _ = self._build_html()
        if session_links:
            html = html.replace(
                "</body>",
                _build_sessions_section(session_links) + "\n</body>",
            )
        out.write_text(html, encoding="utf-8")
        return out

    # ------------------------------------------------------------------
    # PDF
    # ------------------------------------------------------------------
    def render_pdf(self, output_path: Path | str) -> Path:
        """Render the HTML report to a PDF file.

        Requires the ``[pdf]`` extra (``weasyprint``). Raises
        :class:`honeytrap.reporting.pdf_export.PDFExportError` if the
        dependency is missing or conversion fails.
        """
        from honeytrap.reporting.pdf_export import export_pdf

        html, _ = self._build_html()
        out = Path(output_path)
        return export_pdf(html, out)

    @staticmethod
    def _build_sessions_section_html(session_links: list[dict[str, str]]) -> str:
        """Public test hook -- return the HTML section for session links."""
        return _build_sessions_section(session_links)

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


def _build_sessions_section(session_links: list[dict[str, str]]) -> str:
    """Render the session-index section appended to the main HTML report."""
    from html import escape

    rows = []
    for link in session_links:
        rows.append(
            "<tr>"
            f"<td><a href='{escape(link['page'])}'>{escape(link['session_id'])}</a></td>"
            f"<td>{escape(link['ip'])}</td>"
            f"<td>{escape(link['protocol'])}</td>"
            f"<td>{escape(link['frames'])}</td>"
            f"<td><a href='{escape(link['pcap'])}'>PCAP</a></td>"
            f"<td><a href='{escape(link['jsonl'])}'>JSONL</a></td>"
            "</tr>"
        )
    table_body = "\n".join(rows)
    return (
        "<section id='forensic-sessions' style='margin-top:2rem;'>"
        "<h2>Forensic Session Replays</h2>"
        "<table style='width:100%;border-collapse:collapse;'>"
        "<thead><tr style='text-align:left;border-bottom:1px solid #444;'>"
        "<th>Session</th><th>IP</th><th>Protocol</th><th>Frames</th>"
        "<th>PCAP</th><th>JSONL</th></tr></thead>"
        f"<tbody>{table_body}</tbody></table></section>"
    )
