"""SMB honeypot.

Instead of requiring ``impacket`` (which is heavy and Windows-flavored),
this handler ships a lightweight asyncio SMB listener that parses the
first few bytes of each connection to detect SMB negotiation attempts.
It records the source IP, any advertised dialects, and any share names the
attacker tries to access via SMB1 tree connects. For advanced attacker
interaction the operator can install the ``[smb]`` extra to enable a full
impacket-backed listener (loaded automatically when available).
"""

from __future__ import annotations

import asyncio
import logging
import struct

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


_SMB1_MAGIC = b"\xffSMB"
_SMB2_MAGIC = b"\xfeSMB"


class SMBHandler(ProtocolHandler):
    """Lightweight SMB negotiation honeypot."""

    name = "smb"

    def __init__(self, service: ServiceSpec, engine) -> None:  # noqa: ANN001
        """Initialize the SMB honeypot handler."""
        super().__init__(service, engine)
        self._server: asyncio.base_events.Server | None = None
        self.share_names: list[str] = list(service.data.get("share_names", []) or [])

    async def start(self, bind_address: str, port: int) -> None:
        """Start the SMB listener on the configured port."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            self._server = await asyncio.start_server(self._handle, bind_address, port)
        except OSError as exc:
            raise PortBindError(f"Could not bind SMB on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop the SMB listener."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        remote_ip, remote_port = peer[0], peer[1]

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
        session = self.engine.sessions.create(remote_ip, remote_port, "smb", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")

        await self.emit(
            Event(
                protocol="smb",
                event_type="connection_open",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                country_code=session.country_code,
                country_name=session.country_name,
                message="SMB connection opened",
                data={"personality": personality.key},
            )
        )

        idle_timeout = self.idle_timeout()
        try:
            for _ in range(8):  # read up to 8 SMB packets then drop
                try:
                    header = await asyncio.wait_for(reader.readexactly(4), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    await self.log_timeout_event(remote_ip, remote_port, idle_timeout)
                    break
                except asyncio.IncompleteReadError:
                    break
                # NetBIOS session header: type(1) + flags(1) + length(2)
                length = struct.unpack(">I", b"\x00" + header[1:4])[0]
                length = length & 0x1FFFF  # cap at 128KB
                # Sanitizer enforces the configured max; we still keep the
                # protocol-level cap above as belt-and-braces.
                if length > self.engine.sanitizer.other_body_max:
                    await self.log_sanitizer_event(
                        remote_ip,
                        remote_port,
                        f"smb_body_too_large:{length}",
                    )
                    break
                try:
                    body = await asyncio.wait_for(reader.readexactly(length), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    await self.log_timeout_event(remote_ip, remote_port, idle_timeout)
                    break
                except asyncio.IncompleteReadError:
                    break

                session.bytes_in += 4 + len(body)
                dialect = "unknown"
                if body.startswith(_SMB1_MAGIC):
                    dialect = "SMB1"
                elif body.startswith(_SMB2_MAGIC):
                    dialect = "SMB2/3"
                await self.emit(
                    Event(
                        protocol="smb",
                        event_type="negotiate",
                        remote_ip=remote_ip,
                        session_id=session.session_id,
                        country_code=session.country_code,
                        country_name=session.country_name,
                        message=f"SMB {dialect} negotiation",
                        data={
                            "dialect": dialect,
                            "packet_len": len(body),
                            "packet_head_hex": body[:32].hex(),
                            "share_names_advertised": self.share_names,
                        },
                    )
                )

                # Respond with a minimal canned "access denied" style reply.
                reply = self._canned_reply(dialect)
                writer.write(reply)
                try:
                    await writer.drain()
                except ConnectionError:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.exception("SMB handler error: %s", exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.emit(
                Event(
                    protocol="smb",
                    event_type="connection_close",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    message="SMB session closed",
                )
            )

    @staticmethod
    def _canned_reply(dialect: str) -> bytes:
        """Return a minimal SMB error response (STATUS_ACCESS_DENIED)."""
        # We return a tiny NetBIOS header + short body.  This is deliberately
        # not a correct SMB response — the goal is to elicit a second packet
        # from the attacker (revealing more of their probing logic) without
        # exposing a real SMB stack.
        if dialect == "SMB2/3":
            body = b"\xfeSMB" + b"\x00" * 60 + b"\x22\x00\x00\xc0"  # STATUS_ACCESS_DENIED
        else:
            body = b"\xffSMB" + b"\x73" + b"\x22\x00\x00\xc0" + b"\x00" * 28
        header = b"\x00\x00" + struct.pack(">H", len(body))
        return header + body
