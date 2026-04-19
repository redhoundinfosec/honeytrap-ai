"""Abstract base class for protocol handlers.

Every concrete handler subclasses :class:`ProtocolHandler` and overrides
:meth:`start` and :meth:`stop`. The base class wires access to the engine,
session manager, database, and emit helpers so concrete handlers stay
small.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from honeytrap.core.profile import ServiceSpec
from honeytrap.logging.models import Event

if TYPE_CHECKING:  # pragma: no cover
    from honeytrap.core.engine import Engine


class ProtocolHandler(ABC):
    """Shared surface for every protocol handler."""

    name: str = "base"

    def __init__(self, service: ServiceSpec, engine: Engine) -> None:
        """Initialize the protocol handler.
        
                Args:
                    config: Global honeytrap configuration.
                    profile_service: Service definition from the loaded device profile.
                    log_manager: Shared log manager instance.
                    session_manager: Shared session manager.
                    geo_resolver: Optional geo-IP resolver.
                    ai_responder: Optional AI response engine.
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
