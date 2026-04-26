"""Main honeypot engine.

The :class:`Engine` wires together the log manager, session manager, AI
responder, geo resolver, and all protocol handlers derived from the loaded
:class:`DeviceProfile`. It owns the asyncio event loop for the application.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import platform
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from honeytrap.ai.geo_personality import GeoPersonalitySelector
from honeytrap.ai.responder import AIResponder
from honeytrap.ai.rule_engine import RuleEngine
from honeytrap.alerts import AlertManager, parse_alerts_config
from honeytrap.core.config import Config
from honeytrap.core.guardian import ResourceGuardian
from honeytrap.core.profile import DeviceProfile, ServiceSpec
from honeytrap.core.rate_limiter import RateLimiter
from honeytrap.core.sanitizer import InputSanitizer
from honeytrap.core.session import SessionManager
from honeytrap.exceptions import PortBindError
from honeytrap.forensics.recorder import (
    Direction,
    ForensicsConfig,
    JsonlSessionStore,
    SessionRecorder,
    SessionStore,
    SqliteSessionStore,
    _MetricSink,
)
from honeytrap.geo.resolver import GeoResolver
from honeytrap.intel.attack_mapper import ATTACKMapper
from honeytrap.intel.ioc_extractor import IOCExtractor
from honeytrap.logging.database import AttackDatabase
from honeytrap.logging.manager import LogManager
from honeytrap.logging.models import Event
from honeytrap.ops.health import MetricsRegistry, build_default_registry

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
    993: 9930,
    1883: 18830,
    3306: 33060,
    3389: 33890,
    5683: 56830,
    5684: 56840,
    8883: 88830,
}


PROTOCOL_NAMES: tuple[str, ...] = (
    "http",
    "https",
    "ssh",
    "ftp",
    "smb",
    "telnet",
    "smtp",
    "mysql",
    "imap",
    "rdp",
    "mqtt",
    "coap",
)


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

        # Adaptive AI layer (Cycle 11). Components lazy-built so the
        # engine boots even when the adaptive path is disabled.
        from honeytrap.ai.adapter import ProtocolResponder as _AdaptiveResponder
        from honeytrap.ai.backends import build_backend as _build_backend
        from honeytrap.ai.backends import instantiate as _instantiate_backend
        from honeytrap.ai.cache import ResponseCache as _AiCache
        from honeytrap.ai.memory import build_store as _build_memory_store

        self.ai_memory = _build_memory_store(
            config.ai.memory_store,
            state_dir=log_dir,
            cap_ips=config.ai.memory_cap_ips,
            cap_sessions_per_ip=config.ai.memory_cap_sessions_per_ip,
        )
        ai_cache = (
            _AiCache(
                capacity=config.ai.cache_capacity,
                ttl_seconds=config.ai.cache_ttl_seconds,
            )
            if config.ai.cache_enabled
            else None
        )
        backend_specs = config.ai.backends or {}
        if config.ai.force_backend:
            forced = _instantiate_backend(
                {"type": config.ai.force_backend, **backend_specs.get(config.ai.force_backend, {})}
            )
            self.ai_backends = _build_backend(
                [{"type": config.ai.force_backend}] if forced is None else [],
                prompts_dir=config.ai.prompts_dir,
            )
            if forced is not None:
                self.ai_backends.backends = [forced, *self.ai_backends.backends[-1:]]
        else:
            ordered = [
                backend_specs.get("primary"),
                backend_specs.get("secondary"),
                backend_specs.get("tertiary"),
            ]
            self.ai_backends = _build_backend(ordered, prompts_dir=config.ai.prompts_dir)
        self.ai_cache = ai_cache
        self.ai_responder = _AdaptiveResponder(
            chain=self.ai_backends,
            cache=ai_cache,
            metrics=None,  # wired later when the health server hooks are up
            enabled=config.ai.adaptive_enabled,
            redact_secrets=config.ai.redact_secrets_in_prompts,
        )

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

        # Metrics registry is always live, regardless of whether a health
        # server is attached. Handlers poke counters through emit_event.
        self.metrics: MetricsRegistry = build_default_registry()

        self.handlers: list[ProtocolHandler] = []
        self.active_ports: list[tuple[str, int, int]] = []
        self.skipped_ports: list[tuple[str, int, str]] = []

        self._listeners: list[asyncio.Task[Any]] = []
        self._stopping = asyncio.Event()
        self._event_subscribers: list[asyncio.Queue[Event]] = []

        # Alerting subsystem (may stay disabled; parsing is cheap).
        self.alerts_config = parse_alerts_config(config.alerts.as_dict())
        if self.alerts_config.warnings:
            for warning in self.alerts_config.warnings:
                logger.warning("alerts config: %s", warning)
        self.alert_manager: AlertManager | None = None
        if self.alerts_config.enabled:
            self.alert_manager = AlertManager(
                channels=list(self.alerts_config.channels),
                min_severity=self.alerts_config.min_severity,
                dry_run=self.alerts_config.dry_run,
                metric_sent=lambda channel, labels: self.metrics.inc_counter(
                    "honeytrap_alerts_sent_total",
                    labels={"channel": channel, **(labels or {})},
                ),
                metric_dropped=lambda reason, labels: self.metrics.inc_counter(
                    "honeytrap_alerts_dropped_total",
                    labels={"reason": reason, **(labels or {})},
                ),
                tui_notify=self._tui_notify,
            )
        self._tui_notify_hook: Any = None
        self._alert_queue: asyncio.Queue[Event] | None = None

        # Forensic recorder. The store path is rooted under the log
        # directory by default so existing operators get a sensible
        # location without touching their config.
        self.forensics_config = ForensicsConfig(
            enabled=config.forensics.enabled,
            store=config.forensics.store,
            path=config.forensics.path,
            max_session_bytes=config.forensics.max_session_bytes,
            max_daily_bytes=config.forensics.max_daily_bytes,
            retention_days=config.forensics.retention_days,
            record_tls_handshake=config.forensics.record_tls_handshake,
        )
        self.session_store: SessionStore | None = None
        self.recorder: SessionRecorder | None = None
        if self.forensics_config.enabled:
            try:
                forensics_root = Path(self.forensics_config.path)
                if not forensics_root.is_absolute():
                    forensics_root = log_dir / forensics_root.name
                forensics_root.mkdir(parents=True, exist_ok=True)
                if self.forensics_config.store == "sqlite":
                    self.session_store = SqliteSessionStore(forensics_root / "sessions.db")
                else:
                    self.session_store = JsonlSessionStore(forensics_root)
                self.recorder = SessionRecorder(
                    self.session_store,
                    self.forensics_config,
                    guardian=self.guardian,
                    metrics=_MetricSink(
                        on_recorded=lambda proto: self.metrics.inc_counter(
                            "honeytrap_sessions_recorded_total",
                            labels={"protocol": proto or "unknown"},
                        ),
                        on_truncated=lambda reason: self.metrics.inc_counter(
                            "honeytrap_sessions_truncated_total",
                            labels={"reason": reason or "unknown"},
                        ),
                        on_bytes=lambda proto, direction, size: self.metrics.inc_counter(
                            "honeytrap_session_bytes_total",
                            value=float(size),
                            labels={
                                "protocol": proto or "unknown",
                                "direction": direction,
                            },
                        ),
                        on_duration=lambda seconds: self.metrics.observe_histogram(
                            "honeytrap_session_duration_seconds",
                            float(seconds),
                        ),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Forensic recorder init failed: %s", exc)
                self.session_store = None
                self.recorder = None
        self._retention_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Alerting hooks
    # ------------------------------------------------------------------
    def set_tui_notify_hook(self, hook: Any) -> None:
        """Install a coroutine (``async def hook(alert)``) used for toasts.

        The hook is invoked by the alert manager for alerts at severity
        HIGH or higher so the Textual dashboard can surface them as
        in-app notifications.
        """
        self._tui_notify_hook = hook

    async def _tui_notify(self, alert: Any) -> None:
        """Internal wrapper that forwards alerts to the registered hook."""
        hook = self._tui_notify_hook
        if hook is None:
            return
        try:
            result = hook(alert)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:  # noqa: BLE001
            logger.debug("TUI notify hook raised: %s", exc)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def _build_handlers(self) -> list[ProtocolHandler]:
        """Instantiate a protocol handler for each service in the profile."""
        # Local import avoids circular imports.
        from honeytrap.protocols.coap_handler import CoAPHandler
        from honeytrap.protocols.ftp_handler import FTPHandler
        from honeytrap.protocols.http_handler import HTTPHandler
        from honeytrap.protocols.imap_handler import IMAPHandler
        from honeytrap.protocols.mqtt_handler import MQTTHandler
        from honeytrap.protocols.mysql_handler import MySQLHandler
        from honeytrap.protocols.rdp_handler import RDPHandler
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
            "imap": IMAPHandler,
            "rdp": RDPHandler,
            "mqtt": MQTTHandler,
            "coap": CoAPHandler,
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
                logger.exception(
                    "Unexpected failure starting %s: %s", handler.service.protocol, exc
                )

        # Start background log management + periodic reports
        self._listeners.append(asyncio.create_task(self.log_manager.monitor()))

        if self.recorder is not None:
            self._retention_task = asyncio.create_task(self._retention_loop())
            self._listeners.append(self._retention_task)

        # Wire the alert manager to the event bus if enabled.
        if self.alert_manager is not None:
            self._alert_queue = self.subscribe()
            self._listeners.append(
                asyncio.create_task(self.alert_manager.run_subscriber(self._alert_queue))
            )
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
        if self.alert_manager is not None:
            try:
                await self.alert_manager.shutdown()
            except Exception as exc:  # noqa: BLE001
                logger.debug("AlertManager shutdown failed: %s", exc)
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
        if self.session_store is not None:
            try:
                self.session_store.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("session_store close failed: %s", exc)

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

        try:
            self.metrics.inc_counter(
                "honeytrap_events_total",
                labels={
                    "protocol": event.protocol or "unknown",
                    "event_type": event.event_type or "unknown",
                },
            )
            if event.event_type in {"connect", "connection", "session_start"}:
                self.metrics.inc_counter(
                    "honeytrap_connections_total",
                    labels={"protocol": event.protocol or "unknown"},
                )
            if event.event_type == "rate_limited":
                self.metrics.inc_counter("honeytrap_rate_limited_total")
            if event.event_type == "resource_rejected":
                self.metrics.inc_counter("honeytrap_resource_rejections_total")
        except Exception as exc:  # noqa: BLE001
            logger.debug("Metrics update failed: %s", exc)

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

    # ------------------------------------------------------------------
    # Forensic recording helpers
    # ------------------------------------------------------------------
    def record_session_open(
        self,
        *,
        session_id: str,
        protocol: str,
        remote_ip: str,
        remote_port: int,
        local_ip: str = "",
        local_port: int = 0,
    ) -> None:
        """Open a forensic session if recording is configured."""
        if self.recorder is None:
            return
        try:
            self.recorder.open_session(
                session_id=session_id,
                protocol=protocol,
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_ip=local_ip,
                local_port=local_port,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("record_session_open failed: %s", exc)

    def record_frame(
        self,
        *,
        session_id: str,
        direction: Direction,
        payload: bytes,
        source_ip: str,
        source_port: int,
        dest_ip: str,
        dest_port: int,
        protocol: str = "",
        is_tls_handshake: bool = False,
    ) -> None:
        """Record a single inbound or outbound frame for replay."""
        if self.recorder is None or not payload:
            return
        try:
            self.recorder.record_frame(
                session_id=session_id,
                direction=direction,
                payload=payload,
                source_ip=source_ip,
                source_port=source_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                protocol=protocol,
                is_tls_handshake=is_tls_handshake,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("record_frame failed: %s", exc)

    def record_session_close(self, session_id: str) -> None:
        """Mark a forensic session closed."""
        if self.recorder is None:
            return
        try:
            self.recorder.close_session(session_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("record_session_close failed: %s", exc)

    async def _retention_loop(self) -> None:
        """Run a retention sweep at startup and then once per 24h."""
        if self.recorder is None:
            return
        try:
            self.recorder.sweep_retention()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Initial forensic sweep failed: %s", exc)
        while not self._stopping.is_set():
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), timeout=24 * 3600)
            if self._stopping.is_set():
                return
            try:
                self.recorder.sweep_retention()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Periodic forensic sweep failed: %s", exc)
