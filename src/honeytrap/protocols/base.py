"""Abstract base class for protocol handlers.

Every concrete handler subclasses :class:`ProtocolHandler` and overrides
:meth:`start` and :meth:`stop`. The base class wires access to the engine,
session manager, database, and emit helpers so concrete handlers stay
small.

Shared security primitives live here so every protocol gets them for
free: :meth:`check_connection_allowed` consults the rate limiter and
resource guardian before a handler commits to processing a connection,
and :meth:`idle_timeout` resolves the per-protocol idle timeout from
config.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from honeytrap.core.profile import ServiceSpec
from honeytrap.core.rate_limiter import RateLimitDecision
from honeytrap.logging.models import Event

if TYPE_CHECKING:  # pragma: no cover
    from honeytrap.core.engine import Engine

logger = logging.getLogger(__name__)


class ProtocolHandler(ABC):
    """Shared surface for every protocol handler."""

    name: str = "base"

    def __init__(self, service: ServiceSpec, engine: Engine) -> None:
        """Initialize the protocol handler.

        Args:
            service: Service definition from the loaded device profile.
            engine: The owning engine — provides logging, rate limiting,
                sanitization, and geo resolution.
        """
        self.service = service
        self.engine = engine
        self.bind_address: str = ""
        self.bound_port: int = 0

    # ------------------------------------------------------------------
    # Lifecycle (subclasses must implement)
    # ------------------------------------------------------------------
    @abstractmethod
    async def start(self, bind_address: str, port: int) -> None:
        """Begin listening on ``bind_address:port``."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop listening and clean up."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def emit(self, event: Event) -> None:
        """Dispatch an event through the engine."""
        event.local_port = event.local_port or self.bound_port
        await self.engine.emit_event(event)

    async def resolve_geo(self, ip: str) -> dict[str, str]:
        """Proxy to the engine's geo resolver."""
        return await self.engine.resolve_geo(ip)

    # ------------------------------------------------------------------
    # Security primitives shared across protocols
    # ------------------------------------------------------------------
    async def check_connection_allowed(
        self, remote_ip: str
    ) -> tuple[bool, RateLimitDecision, str]:
        """Run rate-limit + guardian checks for a new connection.

        Returns ``(allow, decision, guardian_reason)`` so the caller can
        emit distinct security events for each failure mode. The rate
        limiter is consulted first because it's usually cheaper and
        more specific than the guardian's broad resource-pressure check.
        """
        decision = await self.engine.rate_limiter.check(remote_ip)
        if not decision.allowed:
            return False, decision, ""
        allow, reason = await self.engine.guardian.should_accept_connection()
        if not allow:
            return False, RateLimitDecision(False, reason=reason), reason
        return True, decision, ""

    async def log_rate_limit_event(
        self, remote_ip: str, remote_port: int, decision: RateLimitDecision
    ) -> None:
        """Emit a security event describing a rate-limit rejection."""
        await self.emit(
            Event(
                protocol=self.name,
                event_type="rate_limited",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                message=f"Connection rejected: {decision.reason}",
                data={
                    "reason": decision.reason,
                    "retry_after": decision.retry_after,
                    "tarpit_seconds": decision.tarpit_seconds,
                },
            )
        )

    async def log_sanitizer_event(
        self, remote_ip: str, remote_port: int, reason: str, hex_preview: str = ""
    ) -> None:
        """Emit a security event for a sanitizer rejection."""
        await self.emit(
            Event(
                protocol=self.name,
                event_type="sanitizer_violation",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                message=f"Input rejected: {reason}",
                data={"reason": reason, "hex": hex_preview},
            )
        )

    async def log_timeout_event(
        self, remote_ip: str, remote_port: int, idle_seconds: float
    ) -> None:
        """Emit a security event when a connection is closed for being idle."""
        await self.emit(
            Event(
                protocol=self.name,
                event_type="idle_timeout",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                message=f"Connection closed after {idle_seconds:.0f}s idle",
                data={"idle_seconds": idle_seconds},
            )
        )

    async def apply_tarpit(self, decision: RateLimitDecision) -> None:
        """Sleep for the tarpit duration if the limiter asked us to.

        Tarpitting is a defensive trade: we burn an asyncio sleep (cheap)
        to hold an attacker's socket slot (expensive for them), throttling
        the overall scan rate without spending CPU cycles on a real
        response. Only triggered when ``tarpit_on_limit`` is on.
        """
        if decision.tarpit_seconds > 0:
            try:
                await asyncio.sleep(decision.tarpit_seconds)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                pass

    def idle_timeout(self) -> float:
        """Return the idle-timeout (seconds) configured for this protocol."""
        timeouts = self.engine.config.timeouts
        mapping = {
            "http": timeouts.http_idle,
            "https": timeouts.http_idle,
            "ssh": timeouts.ssh_idle,
            "telnet": timeouts.telnet_idle,
            "ftp": timeouts.ftp_idle,
            "smb": timeouts.smb_idle,
            "smtp": timeouts.smtp_idle,
            "mysql": timeouts.mysql_idle,
        }
        return float(mapping.get(self.name, 120.0))
