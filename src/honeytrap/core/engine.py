"""Main honeypot engine.

The :class:`Engine` wires together the log manager, session manager, AI
responder, geo resolver, and all protocol handlers derived from the loaded
:class:`DeviceProfile`. It owns the asyncio event loop for the application.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from honeytrap.ai.geo_personality import GeoPersonalitySelector
from honeytrap.ai.responder import AIResponder
from honeytrap.ai.rule_engine import RuleEngine
from honeytrap.core.config import Config
from honeytrap.core.guardian import ResourceGuardian
from honeytrap.core.profile import DeviceProfile, ServiceSpec
from honeytrap.core.rate_limiter import RateLimiter
from honeytrap.core.sanitizer import InputSanitizer
from honeytrap.core.session import SessionManager
from honeytrap.exceptions import PortBindError
from honeytrap.geo.resolver import GeoResolver
from honeytrap.intel.attack_mapper import ATTACKMapper
from honeytrap.intel.ioc_extractor import IOCExtractor
from honeytrap.logging.database import AttackDatabase
from honeytrap.logging.manager import LogManager
from honeytrap.logging.models import Event

if TYPE_CHECKING:
    from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


HIGH_PORT_FALLBACK = {
    21: 2121,
    22: 2222,
    23: 2323,
    25: 2525,
    80: 8080,
    110: 1110,
    143: 1143,
    443: 8443,
    445: 4450,
    554: 5540,
    3306: 33060,
}


class Engine:
    """Primary orchestrator for HoneyTrap AI."""

    def __init__(self, config: Config, profile: DeviceProfile) -> None:
        """Initialize the honeypot engine with the given configuration."""
        self.config = config
        self.profile = profile

        log_dir = Path(config.general.log_directory)
        log_dir.mkdir(parents=True, exist_ok=True)

        self.database = AttackDatabase(log_dir / "attacks.db")
        self.log_manager = LogManager(
            log_dir,
            max_size_mb=config.general.max_log_size_mb,
            retention_days=config.general.log_retention_days,
        )
        self.sessions = SessionManager()
        self.geo = GeoResolver(config.geo)
        self.rules = RuleEngine(profile)
        self.ai = AIResponder(config.ai, self.rules)
        self.personalities = GeoPersonalitySelector(enabled=config.geo.vary_responses)

        # Security layer — each of these is engine-global so every handler
        # gets consistent limits without the caller having to wire it in.
        self.rate_limiter = RateLimiter(
            enabled=config.rate_limiter.enabled,
            max_per_minute=config.rate_limiter.max_per_minute,
            burst=config.rate_limiter.burst,
            global_concurrent=config.rate_limiter.global_concurrent,
            per_ip_concurrent=config.rate_limiter.per_ip_concurrent,
            stale_after_seconds=config.rate_limiter.stale_after_seconds,
            tarpit_on_limit=config.rate_limiter.tarpit_on_limit,
            tarpit_seconds=config.rate_limiter.tarpit_seconds,
        )
        self.sanitizer = InputSanitizer(
            enabled=config.sanitizer.enabled,
            http_body_max=config.sanitizer.http_body_max,
            other_body_max=config.sanitizer.other_body_max,
            http_header_count_max=config.sanitizer.http_header_count_max,
            http_header_size_max=config.sanitizer.http_header_size_max,
            command_max=config.sanitizer.command_max,
            reject_null_bytes=config.sanitizer.reject_null_bytes,
        )
        self.guardian = ResourceGuardian(
            log_directory=log_dir,
            memory_limit_mb=config.guardian.memory_limit_mb,
            check_interval_seconds=config.guardian.check_interval_seconds,
            log_dir_warn_mb=config.guardian.log_dir_warn_mb,
            rate_limiter=self.rate_limiter,
            enabled=config.guardian.enabled,
        )

        # Threat intelligence layer — shared across every event.
        self.attack_mapper = ATTACKMapper()
        self.ioc_extractor = IOCExtractor()

        self.handlers: list[ProtocolHandler] = []
        self.active_ports: list[tuple[str, int, int]] = []
        self.skipped_ports: list[tuple[str, int, str]] = []

        self._listeners: list[asyncio.Task[Any]] = []
        self._stopping = asyncio.Event()
        self._event_subscribers: list[asyncio.Queue[Event]] = []

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def _build_handlers(self) -> list[ProtocolHandler]:
        """Instantiate a protocol handler for each service in the profile."""
        # Local import avoids circular imports.
        from honeytrap.protocols.ftp_handler import FTPHandler
        from honeytrap.protocols.http_handler import HTTPHandler
        from honeytrap.protocols.mysql_handler import MySQLHandler
        from honeytrap.protocols.smb_handler import SMBHandler
        from honeytrap.protocols.smtp_handler import SMTPHandler
        from honeytrap.protocols.ssh_handler import SSHHandler
        from honeytrap.protocols.telnet_handler import TelnetHandler

        registry: dict[str, type[ProtocolHandler]] = {
            "http": HTTPHandler,
            "https": HTTPHandler,
            "ssh": SSHHandler,
            "ftp": FTPHandler,
            "smb": SMBHandler,
            "telnet": TelnetHandler,
            "smtp": SMTPHandler,
            "mysql": MySQLHandler,
        }

        handlers: list[ProtocolHandler] = []
        for svc in self.profile.services:
            cls = registry.get(svc.protocol.lower())
            if cls is None:
                logger.warning("No handler registered for protocol %s — skipping", svc.protocol)
                continue
            handlers.append(cls(service=svc, engine=self))
        return handlers

    def _port_for(self, svc: ServiceSpec) -> int:
        """Resolve the port to bind for a service, with high-port fallback on Windows-nonadmin/Linux-nonroot."""
        port = svc.port
        os_name = platform.system()
        low_port = port < 1024
        needs_elevation = False
        if low_port and os_name == "Windows":
            try:
                import ctypes

                if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
                    needs_elevation = True
            except Exception:  # noqa: BLE001 — best effort
                needs_elevation = True
        elif low_port and os_name in {"Linux", "Darwin"}:
            import os as _os

            if hasattr(_os, "geteuid") and _os.geteuid() != 0:
                needs_elevation = True

        if needs_elevation and port in HIGH_PORT_FALLBACK:
            fallback = HIGH_PORT_FALLBACK[port]
            logger.warning(
                "Insufficient privileges to bind port %d; falling back to %d", port, fallback
            )
            return fallback
        return port

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start all configured protocol handlers and background tasks."""
        logger.info("Starting HoneyTrap engine: profile=%s", self.profile.name)
        self.handlers = self._build_handlers()
        bind_address = self.config.general.bind_address

        for handler in self.handlers:
            port = self._port_for(handler.service)
            try:
                await handler.start(bind_address, port)
                self.active_ports.append((handler.service.protocol, handler.service.port, port))
                logger.info(
                    "Listener active: %s on %s:%d (requested %d)",
                    handler.service.protocol,
                    bind_address,
                    port,
                    handler.service.port,
                )
            except PortBindError as exc:
                self.skipped_ports.append((handler.service.protocol, port, str(exc)))
                logger.warning("Skipping %s:%d — %s", handler.service.protocol, port, exc)
            except Exception as exc:  # noqa: BLE001 — never crash
                self.skipped_ports.append((handler.service.protocol, port, str(exc)))
                logger.exception("Unexpected failure starting %s: %s", handler.service.protocol, exc)

        # Start background log management + periodic reports
        self._listeners.append(asyncio.create_task(self.log_manager.monitor()))
        # Guardian runs as its own long-lived task; it self-registers so we
        # don't need to add it to _listeners.
        await self.guardian.start()
        await self.emit_event(
            Event(
                protocol="engine",
                event_type="startup",
                remote_ip="",
                message=f"HoneyTrap AI started with profile {self.profile.name!r}",
                data={
                    "active_ports": [list(row) for row in self.active_ports],
                    "skipped_ports": [list(row) for row in self.skipped_ports],
                    "platform": f"{platform.system()} {platform.release()}",
                    "python": sys.version.split()[0],
                },
            )
        )

    async def stop(self) -> None:
        """Shut down every listener and flush buffers."""
        logger.info("Stopping HoneyTrap engine")
        self._stopping.set()
        await self.guardian.stop()
        for handler in self.handlers:
            try:
                await handler.stop()
            except Exception as exc:  # noqa: BLE001
                logger.exception("Error stopping %s: %s", handler.service.protocol, exc)
        for task in self._listeners:
            task.cancel()
        for task in self._listeners:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        await self.log_manager.close()
        self.database.close()

    async def run_forever(self) -> None:
        """Run until Ctrl+C. The dashboard, if enabled, is started separately."""
        try:
            await self._stopping.wait()
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Event bus
    # ------------------------------------------------------------------
    def subscribe(self) -> asyncio.Queue[Event]:
        """Return an async queue that receives every :class:`Event`."""
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=1000)
        self._event_subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        """Remove a previously-subscribed queue."""
        try:
            self._event_subscribers.remove(queue)
        except ValueError:
            pass

    async def emit_event(self, event: Event) -> None:
        """Persist an event everywhere it needs to go (DB, JSONL, UI).

        Side effects performed (in order):

        1. Classify the event against MITRE ATT&CK and attach results to the
           event's ``data`` dict so downstream consumers can see the
           classification without re-running it.
        2. Extract IOCs from the event body.
        3. Write to the JSONL log and the SQLite event table.
        4. Persist the ATT&CK mappings and IOCs to their own tables.
        5. Fan out to live UI subscribers.
        """
        event_dict = event.to_dict()

        # ---- Intel classification (best-effort; never block event emit) ----
        try:
            mappings = self.attack_mapper.map_event(event_dict)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ATT&CK mapping failed: %s", exc)
            mappings = []
        try:
            iocs = self.ioc_extractor.extract_from_event(event_dict)
        except Exception as exc:  # noqa: BLE001
            logger.debug("IOC extraction failed: %s", exc)
            iocs = []

        if mappings:
            event.data.setdefault("attack_techniques", [m.to_dict() for m in mappings])
        if iocs:
            event.data.setdefault("iocs", [i.to_dict() for i in iocs])

        try:
            await self.log_manager.write_event(event)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to persist event: %s", exc)

        event_id: int | None = None
        try:
            event_id = self.database.record_event(event)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to record event in DB: %s", exc)

        if event_id is not None and mappings:
            ts = event.timestamp.isoformat()
            for m in mappings:
                try:
                    self.database.record_attack_mapping(
                        event_id, m, timestamp=ts, remote_ip=event.remote_ip
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Failed to record ATT&CK mapping: %s", exc)

        for ioc in iocs:
            try:
                self.database.record_ioc(ioc)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to record IOC: %s", exc)

        for queue in list(self._event_subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.debug("Dropping event for slow subscriber")

    # ------------------------------------------------------------------
    # Helpers used by handlers
    # ------------------------------------------------------------------
    async def resolve_geo(self, ip: str) -> dict[str, str]:
        """Resolve an IP to country info; falls back to Unknown on error."""
        try:
            return await self.geo.resolve(ip)
        except Exception as exc:  # noqa: BLE001
            logger.debug("GeoIP failed for %s: %s", ip, exc)
            return {"country_code": "XX", "country_name": "Unknown", "asn": ""}
