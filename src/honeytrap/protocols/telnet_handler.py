"""Telnet honeypot (used by iot_camera profile).

Minimal Telnet negotiation + fake login prompt + fake shell. Just enough to
catch IoT-targeted credential brute-forcers (Mirai, etc).
"""

from __future__ import annotations

import asyncio
import logging

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)

IAC = 255
DO, DONT, WILL, WONT = 253, 254, 251, 252


class TelnetHandler(ProtocolHandler):
    """Custom asyncio Telnet honeypot."""

    name = "telnet"

    def __init__(self, service: ServiceSpec, engine) -> None:  # noqa: ANN001
        """Initialize the Telnet honeypot handler."""
        super().__init__(service, engine)
        self._server: asyncio.base_events.Server | None = None
        self.banner = service.banner or ""

    async def start(self, bind_address: str, port: int) -> None:
        """Start the Telnet listener on the configured port."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            self._server = await asyncio.start_server(self._handle, bind_address, port)
        except OSError as exc:
            raise PortBindError(f"Could not bind Telnet on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop the Telnet listener and close all sessions."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        remote_ip, remote_port = peer[0], peer[1]

        # Security gate before we begin negotiation.
        allowed, decision, _reason = await self.check_connection_allowed(remote_ip)
        if not allowed:
            await self.log_rate_limit_event(remote_ip, remote_port, decision)
            await self.apply_tarpit(decision)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            return
        await self.engine.rate_limiter.acquire(remote_ip)
        try:
            await self._handle_session(reader, writer, remote_ip, remote_port)
        finally:
            await self.engine.rate_limiter.release(remote_ip)

    async def _handle_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_ip: str,
        remote_port: int,
    ) -> None:
        geo = await self.resolve_geo(remote_ip)
        personality = self.engine.personalities.for_country(geo["country_code"])
        session = self.engine.sessions.create(remote_ip, remote_port, "telnet", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")

        await self.emit(
            Event(
                protocol="telnet",
                event_type="connection_open",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                country_code=session.country_code,
                country_name=session.country_name,
                message="Telnet client connected",
            )
        )

        try:
            # Minimal negotiation: WILL ECHO, WILL SUPPRESS-GO-AHEAD
            writer.write(bytes([IAC, WILL, 1, IAC, WILL, 3]))
            if self.banner:
                writer.write(f"{self.banner}\r\n".encode())
            writer.write(b"login: ")
            await writer.drain()
            username = await self._readline(reader)
            writer.write(b"Password: ")
            await writer.drain()
            password = await self._readline(reader)

            session.record_credentials(username, password)
            match = self.engine.rules.match_auth(
                protocol="telnet", username=username, password=password, remote_ip=remote_ip
            )
            await self.emit(
                Event(
                    protocol="telnet",
                    event_type="auth_attempt",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    country_code=session.country_code,
                    country_name=session.country_name,
                    username=username,
                    password=password,
                    message=f"Telnet login attempt for {username}",
                    data={"tags": match.tags, "granted": match.metadata.get("granted")},
                )
            )

            if not match.metadata.get("granted"):
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
                return

            writer.write(f"\r\n{personality.welcome_banner}\r\n".encode())
            writer.write(b"# ")
            await writer.drain()
            idle_timeout = self.idle_timeout()
            while not reader.at_eof():
                try:
                    line = await asyncio.wait_for(self._readline(reader), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    await self.log_timeout_event(remote_ip, remote_port, idle_timeout)
                    break
                if not line:
                    break
                sanitizer_result = self.engine.sanitizer.check_command(line)
                if not sanitizer_result.ok:
                    await self.log_sanitizer_event(
                        remote_ip,
                        remote_port,
                        sanitizer_result.reason,
                        sanitizer_result.offending_hex,
                    )
                    break
                session.record_command(line)
                await self.emit(
                    Event(
                        protocol="telnet",
                        event_type="shell_command",
                        remote_ip=remote_ip,
                        session_id=session.session_id,
                        country_code=session.country_code,
                        country_name=session.country_name,
                        message=f"Command: {line}",
                        data={"command": line},
                    )
                )
                if line.strip() in {"exit", "logout", "quit"}:
                    break
                out = self.engine.rules.shell_response(line)
                if not out and self.engine.ai.available:
                    out = await self.engine.ai.generate(
                        system=f"You are a telnet shell on {personality.company}. Keep responses terse.",
                        prompt=f"Command: {line}",
                        max_tokens=120,
                    )
                writer.write((out.rstrip("\n") + "\r\n").encode() if out else b"")
                writer.write(b"# ")
                try:
                    await writer.drain()
                except ConnectionError:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.exception("Telnet handler error: %s", exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.emit(
                Event(
                    protocol="telnet",
                    event_type="connection_close",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    message="Telnet session closed",
                )
            )

    async def _readline(self, reader: asyncio.StreamReader) -> str:
        """Read a CRLF line, stripping Telnet IAC negotiations."""
        buf = bytearray()
        while True:
            try:
                ch = await asyncio.wait_for(reader.read(1), timeout=120)
            except asyncio.TimeoutError:
                return ""
            if not ch:
                return ""
            if ch[0] == IAC:
                try:
                    _ = await asyncio.wait_for(reader.read(2), timeout=5)
                except asyncio.TimeoutError:
                    return ""
                continue
            if ch in (b"\r", b"\n"):
                # consume paired byte if any
                try:
                    nxt = await asyncio.wait_for(reader.read(1), timeout=0.1)
                    if nxt and nxt not in (b"\r", b"\n"):
                        buf.extend(nxt)
                except asyncio.TimeoutError:
                    pass
                break
            buf.extend(ch)
        return buf.decode("latin-1", errors="replace")
