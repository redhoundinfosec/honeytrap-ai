"""Command-line interface for HoneyTrap AI.

Running ``honeytrap`` with no arguments drops the user into an interactive
selection menu: pick a device profile, pick an AI backend, confirm, and the
engine starts. Running ``honeytrap report`` generates a report from the
existing SQLite database.

Every branch wraps its work in broad exception handlers so a misconfigured
host never produces an opaque traceback at the user.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from honeytrap import __version__
from honeytrap.core.config import Config, load_config
from honeytrap.core.engine import Engine
from honeytrap.core.profile import list_bundled_profiles, load_profile
from honeytrap.exceptions import ConfigError, ProfileError
from honeytrap.logging.database import AttackDatabase
from honeytrap.reporting.generator import ReportGenerator
from honeytrap.ui.dashboard import Dashboard

logger = logging.getLogger("honeytrap")


_BUILTIN_PROFILE_INFO: dict[str, tuple[str, str]] = {
    "web_server": ("🌐 Web Server", "Apache with exposed admin panels (HTTP/SSH)"),
    "file_share": ("📁 File Share", "NAS with open SMB shares (SMB/FTP)"),
    "iot_camera": ("📷 IoT Camera", "IP camera with default credentials (HTTP/Telnet)"),
    "database_server": ("🗄️  Database Server", "Exposed MySQL with phpMyAdmin (MySQL/HTTP)"),
    "mail_server": ("📧 Mail Server", "Open relay mail server (SMTP)"),
}


def _configure_logging(verbosity: int) -> None:
    """Set up stderr logging. ``-v`` enables INFO, ``-vv`` enables DEBUG."""
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="honeytrap",
        description="AI-powered cross-platform honeypot framework.",
    )
    parser.add_argument("--version", action="version", version=f"honeytrap {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity.")
    parser.add_argument("--config", help="Path to an alternate honeytrap.yaml file.")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable the live dashboard.")
    parser.add_argument(
        "--dashboard-mode",
        choices=["textual", "rich", "none"],
        default=None,
        help=(
            "Dashboard flavor. 'textual' (default if available) launches the full TUI; "
            "'rich' uses the legacy Rich Live dashboard; 'none' is headless."
        ),
    )
    parser.add_argument(
        "--profile",
        help="Profile to load (bundled name or path). Skips the interactive menu if given.",
    )
    parser.add_argument(
        "--ai",
        choices=["off", "openai", "ollama", "custom"],
        help="AI backend; skips the interactive AI menu if given.",
    )
    parser.add_argument(
        "--health-host",
        default="127.0.0.1",
        help="Bind address for the /healthz, /readyz, /metrics server (default 127.0.0.1).",
    )
    parser.add_argument(
        "--health-port",
        type=int,
        default=9200,
        help="Port for the health/metrics HTTP server (default 9200).",
    )
    parser.add_argument(
        "--health-disabled",
        action="store_true",
        help="Do not start the health/metrics HTTP server.",
    )
    alerts_group = parser.add_mutually_exclusive_group()
    alerts_group.add_argument(
        "--alerts-enabled",
        dest="alerts_enabled",
        action="store_true",
        default=None,
        help="Enable the alerts subsystem (overrides the profile).",
    )
    alerts_group.add_argument(
        "--no-alerts",
        dest="alerts_enabled",
        action="store_false",
        default=None,
        help="Disable the alerts subsystem (overrides the profile).",
    )
    parser.add_argument(
        "--alerts-min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Global minimum severity for alert dispatch.",
    )
    parser.add_argument(
        "--alerts-dry-run",
        action="store_true",
        help="Run alert rules and formatting but do not actually send to channels.",
    )

    parser.add_argument(
        "--ai-enabled",
        dest="ai_enabled",
        action="store_true",
        default=None,
        help="Force-enable the adaptive AI response layer.",
    )
    parser.add_argument(
        "--no-ai",
        dest="ai_enabled",
        action="store_false",
        default=None,
        help="Disable the adaptive AI response layer for this run.",
    )
    parser.add_argument(
        "--ai-backend",
        choices=["template", "openai", "anthropic", "ollama"],
        default=None,
        help="Pin the adaptive responder to a single backend for debugging.",
    )
    parser.add_argument(
        "--ai-dry-run",
        dest="ai_dry_run",
        action="store_true",
        default=False,
        help="Classify and generate but do not send to the attacker; log output only.",
    )

    parser.add_argument(
        "--tls-fingerprint-db",
        dest="tls_fingerprint_db",
        default=None,
        help="Override the bundled JA3/JA4 fingerprint YAML with a custom path.",
    )
    parser.add_argument(
        "--disable-tls-fingerprinting",
        dest="tls_fingerprint_enabled",
        action="store_false",
        default=None,
        help="Disable JA3/JA4 TLS client fingerprinting (enabled by default).",
    )

    sub = parser.add_subparsers(dest="command")

    report_cmd = sub.add_parser("report", help="Generate an attack report from the database.")
    report_cmd.add_argument(
        "--format",
        choices=["terminal", "html", "pdf"],
        default="terminal",
        help="Output format.",
    )
    report_cmd.add_argument("--out", help="Output path for HTML/PDF formats.")

    list_cmd = sub.add_parser("list-profiles", help="List bundled device profiles.")
    _ = list_cmd

    from honeytrap.forensics.cli import build_export_parser

    build_export_parser(sub)

    ai_parser = sub.add_parser("ai", help="Adaptive AI inspection and test tools.")
    ai_sub = ai_parser.add_subparsers(dest="ai_command")
    ai_test = ai_sub.add_parser("test", help="One-shot generator CLI for backend evaluation.")
    ai_test.add_argument(
        "--protocol",
        required=True,
        choices=["ssh", "http", "smtp", "telnet", "ftp", "mysql"],
        help="Target protocol for the generated response.",
    )
    ai_test.add_argument(
        "--input",
        dest="ai_input",
        required=True,
        help="Inbound text. Prefix with @ to read from a file path.",
    )
    ai_test.add_argument(
        "--backend",
        choices=["template", "openai", "anthropic", "ollama"],
        default="template",
        help="Which backend to exercise (default: template).",
    )

    from honeytrap.api.cli import build_api_parser

    build_api_parser(sub)

    from honeytrap.sinks.cli import build_sinks_parser

    build_sinks_parser(sub)

    parser.add_argument(
        "--api-enabled",
        action="store_true",
        help="Start the management REST API alongside the honeypot.",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=9300,
        help="Port for the management API when --api-enabled (default: 9300).",
    )
    parser.add_argument(
        "--api-bind",
        default="127.0.0.1",
        help="Bind address for the management API (default: 127.0.0.1).",
    )

    return parser.parse_args(argv)


def _interactive_profile(console: Console) -> str:
    """Prompt the user for a device profile selection."""
    console.print()
    console.rule("[bold yellow]🍯 HoneyTrap AI")
    console.print(f"[dim]v{__version__}[/dim]")
    console.print()
    console.print("[bold]What device would you like to simulate?[/bold]")

    bundled = list_bundled_profiles()
    rows: list[tuple[str, str, str]] = []
    for idx, path in enumerate(bundled, 1):
        name = path.stem
        label, desc = _BUILTIN_PROFILE_INFO.get(name, (name.replace("_", " ").title(), ""))
        if not desc:
            try:
                desc = load_profile(path).description
            except ProfileError:
                desc = ""
        rows.append((str(idx), label, desc))
    custom_idx = str(len(rows) + 1)
    rows.append((custom_idx, "🔧 Custom", "Load a custom profile YAML"))

    table = Table(show_header=False, box=None)
    table.add_column(style="bold cyan", width=4)
    table.add_column(style="bold")
    table.add_column(style="dim")
    for r in rows:
        table.add_row(f"[{r[0]}]", r[1], r[2])
    console.print(table)
    console.print()

    choices = [r[0] for r in rows]
    selected = Prompt.ask("Select", choices=choices, default=choices[0])
    if selected == custom_idx:
        path_str = Prompt.ask("Path to profile YAML")
        return path_str
    return bundled[int(selected) - 1].stem


def _interactive_ai(console: Console, cfg: Config) -> None:
    """Ask the user which AI backend to use and mutate the config in place."""
    console.print()
    console.print("[bold]AI Response Engine[/bold]")
    table = Table(show_header=False, box=None)
    table.add_column(style="bold cyan", width=4)
    table.add_column(style="bold")
    table.add_column(style="dim")
    table.add_row("[1]", "Offline", "Rule-based only (no API key required)")
    table.add_row("[2]", "OpenAI API", "Provide your API key")
    table.add_row("[3]", "Ollama", "Local LLM at localhost:11434")
    table.add_row("[4]", "Custom endpoint", "OpenAI-compatible API URL")
    console.print(table)
    console.print()
    choice = Prompt.ask("Select", choices=["1", "2", "3", "4"], default="1")
    if choice == "1":
        cfg.ai.enabled = False
        return
    cfg.ai.enabled = True
    if choice == "2":
        cfg.ai.provider = "openai"
        if not cfg.ai.api_key:
            cfg.ai.api_key = Prompt.ask("OpenAI API key", password=True)
        cfg.ai.model = Prompt.ask("Model", default=cfg.ai.model or "gpt-4o-mini")
    elif choice == "3":
        cfg.ai.provider = "ollama"
        cfg.ai.endpoint = Prompt.ask(
            "Ollama endpoint", default=cfg.ai.endpoint or "http://localhost:11434/v1"
        )
        cfg.ai.model = Prompt.ask("Model", default=cfg.ai.model or "llama3.2")
    else:
        cfg.ai.provider = "custom"
        cfg.ai.endpoint = Prompt.ask("API endpoint URL", default=cfg.ai.endpoint)
        cfg.ai.api_key = Prompt.ask(
            "API key (blank if unauthenticated)", default=cfg.ai.api_key, password=True
        )
        cfg.ai.model = Prompt.ask("Model", default=cfg.ai.model or "gpt-4o-mini")


def _apply_ai_shortcut(cfg: Config, value: str) -> None:
    """Apply non-interactive ``--ai`` override."""
    if value == "off":
        cfg.ai.enabled = False
        return
    cfg.ai.enabled = True
    cfg.ai.provider = value if value != "custom" else "custom"
    if value == "openai":
        cfg.ai.api_key = cfg.ai.api_key or os.environ.get("HONEYTRAP_AI_KEY", "")
    if value == "ollama" and not cfg.ai.endpoint:
        cfg.ai.endpoint = "http://localhost:11434/v1"


def _resolve_dashboard_mode(requested: str | None) -> str:
    """Decide which dashboard flavor to launch.

    Args:
        requested: The explicit CLI value (``textual`` / ``rich`` / ``none``)
            or ``None`` when the user did not pass ``--dashboard-mode``.

    Returns:
        One of ``"textual"``, ``"rich"`` or ``"none"``. Defaults to
        ``"textual"`` when Textual is importable, otherwise ``"rich"``.
    """
    if requested in ("textual", "rich", "none"):
        if requested == "textual":
            try:
                import textual  # noqa: F401
            except ImportError:
                logger.warning("textual not available, falling back to rich dashboard")
                return "rich"
        return requested
    try:
        import textual  # noqa: F401

        return "textual"
    except ImportError:
        return "rich"


async def _run_textual_dashboard(engine: Engine, shutdown_event: asyncio.Event) -> None:
    """Launch the Textual TUI bound to the given engine."""
    import contextlib

    from honeytrap.ui import load_textual_app

    tui_cls, source_cls, _ = load_textual_app()
    source = source_cls(engine)
    app = tui_cls(source)

    def _tui_notify(alert: object) -> None:
        title = getattr(alert, "title", "Alert")
        severity = getattr(getattr(alert, "severity", None), "name", "HIGH")
        notify = getattr(app, "notify", None)
        if callable(notify):
            with contextlib.suppress(Exception):  # noqa: BLE001
                notify(f"[{severity}] {title}", title="HoneyTrap alert", severity="error")

    engine.set_tui_notify_hook(_tui_notify)
    app_task = asyncio.create_task(app.run_async())
    wait_task = asyncio.create_task(shutdown_event.wait())
    try:
        await asyncio.wait([app_task, wait_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        with contextlib.suppress(Exception):  # noqa: BLE001
            app.exit()
        for t in (app_task, wait_task):
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):  # noqa: BLE001
                await t


async def _run_rich_dashboard(engine: Engine, shutdown_event: asyncio.Event) -> None:
    """Launch the legacy Rich Live dashboard bound to the given engine."""
    import contextlib

    dashboard = Dashboard(engine)
    dashboard_task = asyncio.create_task(dashboard.run())
    wait_task = asyncio.create_task(shutdown_event.wait())
    try:
        await asyncio.wait([dashboard_task, wait_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        dashboard.stop()
        for t in (dashboard_task, wait_task):
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):  # noqa: BLE001
                await t


async def _run_engine(
    cfg: Config,
    profile_name: str,
    use_dashboard: bool,
    dashboard_mode: str | None = None,
    *,
    health_enabled: bool = True,
    health_host: str = "127.0.0.1",
    health_port: int = 9200,
) -> None:
    """Start the engine (and optional dashboard) and wait for shutdown."""
    console = Console()
    try:
        profile = load_profile(profile_name)
    except ProfileError as exc:
        console.print(f"[red]Failed to load profile:[/red] {exc}")
        return

    engine = Engine(cfg, profile)
    health_server = None
    if health_enabled:
        from honeytrap.ops.health import HealthServer

        def _guardian_ready() -> tuple[bool, str]:
            stats = engine.guardian._stats  # noqa: SLF001 — cheap snapshot
            if stats.should_refuse:
                return False, stats.refusal_reason or "resource pressure"
            return True, ""

        def _active_sessions() -> int:
            return len(getattr(engine.sessions, "_sessions", {}))

        health_server = HealthServer(
            engine.metrics,
            host=health_host,
            port=health_port,
            guardian_ready=_guardian_ready,
            active_sessions=_active_sessions,
        )
        try:
            health_server.start()
        except OSError as exc:
            console.print(
                f"[yellow]![/yellow] Health server failed to bind "
                f"{health_host}:{health_port}: {exc}"
            )
            health_server = None

    shutdown_event = asyncio.Event()

    def _signal_handler(*_args: object) -> None:
        if not shutdown_event.is_set():
            shutdown_event.set()

    for sig_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, sig_name):
            try:
                asyncio.get_running_loop().add_signal_handler(
                    getattr(signal, sig_name), _signal_handler
                )
            except (NotImplementedError, RuntimeError):
                # Windows: signal handlers on the loop aren't supported; KeyboardInterrupt still works.
                signal.signal(getattr(signal, sig_name), lambda *_: _signal_handler())

    try:
        await engine.start()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Engine failed to start: {exc}[/red]")
        await engine.stop()
        return

    console.print()
    console.print(f"[green]✓[/green] Profile loaded: [bold]{profile.name}[/bold]")
    for proto, requested, bound in engine.active_ports:
        console.print(
            f"[green]✓[/green] {proto.upper()} listener on :{bound} (requested :{requested})"
        )
    for proto, port, reason in engine.skipped_ports:
        console.print(f"[yellow]![/yellow] Skipped {proto.upper()}:{port} — {reason}")
    console.print(f"[green]✓[/green] Log directory: {cfg.general.log_directory}")
    if cfg.ai.enabled:
        console.print(f"[green]✓[/green] AI backend: {cfg.ai.provider} ({cfg.ai.model})")
    else:
        console.print("[green]✓[/green] AI backend: rule-based only")
    if health_server is not None:
        console.print(
            f"[green]✓[/green] Health/metrics on http://{health_server.bound_host}:"
            f"{health_server.bound_port}/healthz"
        )

    mode = _resolve_dashboard_mode(dashboard_mode)
    if not use_dashboard or not cfg.general.dashboard:
        mode = "none"

    try:
        if mode == "textual":
            await _run_textual_dashboard(engine, shutdown_event)
        elif mode == "rich":
            await _run_rich_dashboard(engine, shutdown_event)
        else:
            console.print("[dim]Running headless. Press Ctrl+C to stop.[/dim]")
            await shutdown_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        console.print()
        console.print("[yellow]Shutting down…[/yellow]")
        if health_server is not None:
            health_server.stop()
        await engine.stop()
        console.print("[green]Goodbye.[/green]")


def _cmd_report(args: argparse.Namespace, cfg: Config) -> int:
    """Generate a report from an existing attacks.db."""
    console = Console()
    db_path = Path(cfg.general.log_directory) / "attacks.db"
    if not db_path.exists():
        console.print(f"[red]No database found at {db_path}. Run the honeypot first.[/red]")
        return 1
    database = AttackDatabase(db_path)
    try:
        generator = ReportGenerator(cfg, database)
        if args.format == "html":
            out = Path(args.out or Path(cfg.reporting.output_directory) / "report.html")
            written = generator.render_html(out)
            console.print(f"[green]HTML report written to {written}[/green]")
        elif args.format == "pdf":
            from honeytrap.reporting.pdf_export import PDFExportError

            out = Path(args.out or Path(cfg.reporting.output_directory) / "report.pdf")
            try:
                written = generator.render_pdf(out)
                console.print(f"[green]PDF report written to {written}[/green]")
            except PDFExportError as exc:
                console.print(f"[red]PDF export failed: {exc}[/red]")
                console.print(
                    "[yellow]Install the optional PDF extra: pip install honeytrap-ai[pdf][/yellow]"
                )
                return 1
        else:
            generator.render_terminal(console)
        return 0
    finally:
        database.close()


def _cmd_list_profiles() -> int:
    console = Console()
    table = Table(title="Bundled device profiles")
    table.add_column("Name", style="bold cyan")
    table.add_column("Category")
    table.add_column("Services")
    table.add_column("Description", overflow="fold")
    for path in list_bundled_profiles():
        try:
            prof = load_profile(path)
        except ProfileError:
            continue
        services = ", ".join(f"{s.protocol}:{s.port}" for s in prof.services)
        table.add_row(path.stem, prof.category, services, prof.description)
    console.print(table)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)
    _configure_logging(args.verbose)

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    if args.command == "report":
        return _cmd_report(args, cfg)
    if args.command == "list-profiles":
        return _cmd_list_profiles()
    if args.command == "export":
        from honeytrap.forensics.cli import run_export

        return run_export(args, cfg)
    if args.command == "api":
        from honeytrap.api.cli import run_api_command

        return run_api_command(args, cfg)
    if args.command == "ai":
        from honeytrap.ai.cli import run_ai_command

        return run_ai_command(args, cfg)
    if args.command == "sinks":
        from honeytrap.sinks.cli import run_sinks_command

        return run_sinks_command(args, cfg)

    # Apply adaptive-AI CLI overrides before the engine reads config.
    if getattr(args, "ai_enabled", None) is not None:
        cfg.ai.adaptive_enabled = bool(args.ai_enabled)
    if getattr(args, "ai_backend", None):
        cfg.ai.force_backend = args.ai_backend
    if getattr(args, "ai_dry_run", False):
        cfg.ai.dry_run = True

    # Default: interactive start
    console = Console()
    try:
        profile_name = args.profile or _interactive_profile(console)
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Aborted.[/yellow]")
        return 130

    if args.ai:
        _apply_ai_shortcut(cfg, args.ai)
    else:
        try:
            _interactive_ai(console, cfg)
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Aborted.[/yellow]")
            return 130

    if args.no_dashboard:
        cfg.general.dashboard = False

    if args.alerts_enabled is not None:
        cfg.alerts.enabled = bool(args.alerts_enabled)
    if args.alerts_min_severity is not None:
        cfg.alerts.min_severity = args.alerts_min_severity
    if args.alerts_dry_run:
        cfg.alerts.dry_run = True

    if args.tls_fingerprint_enabled is False:
        cfg.tls_fingerprint.enabled = False
    if args.tls_fingerprint_db is not None:
        cfg.tls_fingerprint.database_path = args.tls_fingerprint_db

    dashboard_mode = args.dashboard_mode
    if args.no_dashboard:
        dashboard_mode = "none"

    try:
        asyncio.run(
            _run_engine(
                cfg,
                profile_name,
                cfg.general.dashboard,
                dashboard_mode=dashboard_mode,
                health_enabled=not args.health_disabled,
                health_host=args.health_host,
                health_port=args.health_port,
            )
        )
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled engine error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
