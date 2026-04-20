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
        "--profile",
        help="Profile to load (bundled name or path). Skips the interactive menu if given.",
    )
    parser.add_argument(
        "--ai",
        choices=["off", "openai", "ollama", "custom"],
        help="AI backend; skips the interactive AI menu if given.",
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


async def _run_engine(cfg: Config, profile_name: str, use_dashboard: bool) -> None:
    """Start the engine (and optional dashboard) and wait for shutdown."""
    console = Console()
    try:
        profile = load_profile(profile_name)
    except ProfileError as exc:
        console.print(f"[red]Failed to load profile:[/red] {exc}")
        return

    engine = Engine(cfg, profile)
    dashboard: Dashboard | None = None

    shutdown_event = asyncio.Event()

    def _signal_handler(*_args: object) -> None:
        if not shutdown_event.is_set():
            shutdown_event.set()
            if dashboard is not None:
                dashboard.stop()

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
        console.print(f"[green]✓[/green] {proto.upper()} listener on :{bound} (requested :{requested})")
    for proto, port, reason in engine.skipped_ports:
        console.print(f"[yellow]![/yellow] Skipped {proto.upper()}:{port} — {reason}")
    console.print(f"[green]✓[/green] Log directory: {cfg.general.log_directory}")
    if cfg.ai.enabled:
        console.print(f"[green]✓[/green] AI backend: {cfg.ai.provider} ({cfg.ai.model})")
    else:
        console.print("[green]✓[/green] AI backend: rule-based only")

    try:
        if use_dashboard and cfg.general.dashboard:
            dashboard = Dashboard(engine)
            dashboard_task = asyncio.create_task(dashboard.run())
            wait_task = asyncio.create_task(shutdown_event.wait())
            done, _ = await asyncio.wait(
                [dashboard_task, wait_task], return_when=asyncio.FIRST_COMPLETED
            )
            dashboard.stop()
            for t in (dashboard_task, wait_task):
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
        else:
            console.print("[dim]Running headless. Press Ctrl+C to stop.[/dim]")
            await shutdown_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        console.print()
        console.print("[yellow]Shutting down…[/yellow]")
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
                    "[yellow]Install the optional PDF extra: "
                    "pip install honeytrap-ai[pdf][/yellow]"
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

    try:
        asyncio.run(_run_engine(cfg, profile_name, cfg.general.dashboard))
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled engine error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
