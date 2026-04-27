"""SMTP honeypot.

A custom asyncio implementation that mimics a misconfigured Postfix open
relay. It speaks enough of RFC 5321 to keep spam engines and credential
sprayers engaged while logging everything they try:

* ``HELO`` / ``EHLO`` — capability advertisement (SIZE, 8BITMIME,
  PIPELINING, AUTH PLAIN LOGIN)
* ``AUTH PLAIN`` / ``AUTH LOGIN`` — fake authentication that always
  succeeds after decoding and logging the submitted credentials
* ``MAIL FROM`` / ``RCPT TO`` — accept any address (open-relay behaviour)
* ``DATA`` — read the message body up to a configurable size, extract the
  ``Subject``, ``From`` and ``To`` headers, but never persist the raw body
* ``VRFY`` — ``252`` (cannot VRFY but will accept)
* ``EXPN`` — ``502`` (not implemented)
* ``RSET`` / ``NOOP`` / ``QUIT``

The handler emits :class:`~honeytrap.logging.models.Event` objects that
flow through the ATT&CK mapper (``T1110`` for AUTH attempts and
``T1071.003`` for open-relay abuse) and the IOC extractor.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


_CRLF = b"\r\n"
_DEFAULT_MAX_DATA = 10 * 1024 * 1024  # 10 MB, per spec
_DEFAULT_BANNER = "220 mail.example.com ESMTP Postfix (Ubuntu)"
_DEFAULT_CAPS = (
    "SIZE 52428800",
    "8BITMIME",
    "PIPELINING",
    "AUTH PLAIN LOGIN",
    "ENHANCEDSTATUSCODES",
)

_HEADER_RE = re.compile(rb"^(?P<name>[A-Za-z][A-Za-z0-9\-]*):\s*(?P<value>.*)$")


class SMTPHandler(ProtocolHandler):
    """Custom asyncio SMTP honeypot impersonating an open relay."""

    name = "smtp"

    def __init__(self, service: ServiceSpec, engine) -> None:  # noqa: ANN001
        """Initialize the SMTP honeypot handler."""
        super().__init__(service, engine)
        self._server: asyncio.base_events.Server | None = None
        self.banner = service.banner or _DEFAULT_BANNER
        self.hostname = str(service.data.get("hostname", "mail.example.com"))
        self.max_data_bytes = int(service.data.get("max_data_bytes", _DEFAULT_MAX_DATA))
        self.capabilities: list[str] = list(service.data.get("capabilities", _DEFAULT_CAPS))

    async def start(self, bind_address: str, port: int) -> None:
        """Start the SMTP listener on the configured port."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            self._server = await asyncio.start_server(self._handle, bind_address, port)
        except OSError as exc:
            raise PortBindError(f"Could not bind SMTP on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop the SMTP listener and disconnect clients."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Gate a new connection and dispatch to the session loop."""
        peer = writer.get_extra_info("peername") or ("", 0)
        remote_ip, remote_port = peer[0], peer[1]

        allowed, decision, _reason = await self.check_connection_allowed(remote_ip)
        if not allowed:
            await self.log_rate_limit_event(remote_ip, remote_port, decision)
            await self.apply_tarpit(decision)
            try:
                writer.write(b"421 4.7.0 Service not available\r\n")
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
            writer.close()
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
        """Run the SMTP command dialogue for a single client."""
        geo = await self.resolve_geo(remote_ip)
        session = self.engine.sessions.create(remote_ip, remote_port, "smtp", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")

        await self.emit(
            Event(
                protocol="smtp",
                event_type="connection_open",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                session_id=session.session_id,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                message="SMTP client connected",
            )
        )

        mail_from = ""
        rcpt_to: list[str] = []
        greeted = False
        idle_timeout = self.idle_timeout()

        try:
            writer.write(f"{self.banner}\r\n".encode())
            await writer.drain()

            while not reader.at_eof():
                try:
                    raw = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    await self.log_timeout_event(remote_ip, remote_port, idle_timeout)
                    break
                except asyncio.IncompleteReadError:
                    break
                except asyncio.LimitOverrunError:
                    await self.log_sanitizer_event(remote_ip, remote_port, "smtp_line_overrun")
                    break

                if not raw:
                    break

                sanitizer_result = self.engine.sanitizer.check_command(raw)
                if not sanitizer_result.ok:
                    await self.log_sanitizer_event(
                        remote_ip,
                        remote_port,
                        sanitizer_result.reason,
                        sanitizer_result.offending_hex,
                    )
                    try:
                        writer.write(b"500 5.5.2 Syntax error, command unrecognized\r\n")
                        await writer.drain()
                    except Exception:  # noqa: BLE001
                        pass
                    continue

                line = raw.rstrip(b"\r\n").decode("latin-1", errors="replace")
                if not line:
                    continue
                session.record_command(line)

                cmd_upper = line[:4].upper().strip()
                arg = line[len(cmd_upper) :].strip() if len(line) > len(cmd_upper) else ""
                # VRFY/EXPN/HELO/EHLO/AUTH/MAIL/RCPT/DATA/RSET/NOOP/QUIT are all 4 chars
                # except for AUTH sub-keywords; we also dispatch on the full verb below.
                full_verb = line.split(" ", 1)[0].upper()

                if full_verb in {"HELO", "EHLO"}:
                    greeted = True
                    client_hostname = arg or "unknown"
                    await self.emit(
                        Event(
                            protocol="smtp",
                            event_type="greeting",
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            session_id=session.session_id,
                            message=f"{full_verb} {client_hostname}",
                            data={"verb": full_verb, "client_hostname": client_hostname},
                        )
                    )
                    if full_verb == "HELO":
                        writer.write(f"250 {self.hostname}\r\n".encode())
                    else:
                        self._write_ehlo(writer, client_hostname)
                elif full_verb == "AUTH":
                    await self._handle_auth(reader, writer, arg, remote_ip, remote_port, session)
                elif full_verb == "MAIL":
                    if not greeted:
                        writer.write(b"503 5.5.1 EHLO/HELO first\r\n")
                    else:
                        mail_from = self._extract_address(arg, prefix="FROM:")
                        rcpt_to = []
                        await self.emit(
                            Event(
                                protocol="smtp",
                                event_type="mail_from",
                                remote_ip=remote_ip,
                                remote_port=remote_port,
                                session_id=session.session_id,
                                message=f"MAIL FROM: {mail_from}",
                                data={"from": mail_from},
                            )
                        )
                        writer.write(b"250 2.1.0 Sender OK\r\n")
                elif full_verb == "RCPT":
                    if not mail_from:
                        writer.write(b"503 5.5.1 MAIL first\r\n")
                    else:
                        rcpt = self._extract_address(arg, prefix="TO:")
                        rcpt_to.append(rcpt)
                        await self.emit(
                            Event(
                                protocol="smtp",
                                event_type="rcpt_to",
                                remote_ip=remote_ip,
                                remote_port=remote_port,
                                session_id=session.session_id,
                                message=f"RCPT TO: {rcpt}",
                                data={"to": rcpt, "from": mail_from},
                            )
                        )
                        writer.write(b"250 2.1.5 Recipient OK\r\n")
                elif full_verb == "DATA":
                    if not (mail_from and rcpt_to):
                        writer.write(b"503 5.5.1 RCPT first\r\n")
                        continue
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()
                    await self._consume_data(
                        reader,
                        writer,
                        remote_ip,
                        remote_port,
                        session,
                        mail_from,
                        rcpt_to,
                        idle_timeout,
                    )
                    mail_from = ""
                    rcpt_to = []
                elif full_verb == "RSET":
                    mail_from = ""
                    rcpt_to = []
                    writer.write(b"250 2.0.0 Reset OK\r\n")
                elif full_verb == "NOOP":
                    writer.write(b"250 2.0.0 OK\r\n")
                elif full_verb == "VRFY":
                    writer.write(b"252 2.0.0 Cannot VRFY user, but will accept message\r\n")
                    await self.emit(
                        Event(
                            protocol="smtp",
                            event_type="vrfy",
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            session_id=session.session_id,
                            message=f"VRFY {arg}",
                            data={"target": arg},
                        )
                    )
                elif full_verb == "EXPN":
                    writer.write(b"502 5.5.1 EXPN command not implemented\r\n")
                elif full_verb == "HELP":
                    writer.write(b"214 2.0.0 See https://www.postfix.org/\r\n")
                elif full_verb == "QUIT":
                    writer.write(f"221 2.0.0 {self.hostname} closing connection\r\n".encode())
                    await self.emit(
                        Event(
                            protocol="smtp",
                            event_type="quit",
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            session_id=session.session_id,
                            message="QUIT",
                        )
                    )
                    try:
                        await writer.drain()
                    except ConnectionError:
                        pass
                    break
                else:
                    writer.write(b"500 5.5.2 Syntax error, command unrecognized\r\n")
                    await self.emit(
                        Event(
                            protocol="smtp",
                            event_type="unknown_command",
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            session_id=session.session_id,
                            message=f"unknown: {line[:64]}",
                            data={"raw": line[:256]},
                        )
                    )

                try:
                    await writer.drain()
                except ConnectionError:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.exception("SMTP handler exception for %s: %s", remote_ip, exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.emit(
                Event(
                    protocol="smtp",
                    event_type="connection_close",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    message="SMTP session closed",
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _write_ehlo(self, writer: asyncio.StreamWriter, client_hostname: str) -> None:
        """Write the multi-line EHLO response advertising capabilities."""
        lines = [f"250-{self.hostname} Hello {client_hostname}"]
        for i, cap in enumerate(self.capabilities):
            sep = "-" if i < len(self.capabilities) - 1 else " "
            lines.append(f"250{sep}{cap}")
        writer.write(("\r\n".join(lines) + "\r\n").encode())

    @staticmethod
    def _extract_address(arg: str, *, prefix: str) -> str:
        """Pull the address portion out of ``MAIL FROM:<x>`` / ``RCPT TO:<x>``."""
        text = arg.strip()
        upper = text.upper()
        if upper.startswith(prefix):
            text = text[len(prefix) :].strip()
        if text.startswith("<") and text.endswith(">"):
            text = text[1:-1]
        return text.strip()

    async def _handle_auth(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        arg: str,
        remote_ip: str,
        remote_port: int,
        session,  # noqa: ANN001
    ) -> None:
        """Handle ``AUTH PLAIN`` and ``AUTH LOGIN`` sub-dialogues."""
        parts = arg.split(" ", 1)
        mechanism = parts[0].upper() if parts else ""
        payload = parts[1] if len(parts) > 1 else ""
        username = ""
        password = ""

        if mechanism == "PLAIN":
            if not payload:
                writer.write(b"334 \r\n")
                await writer.drain()
                try:
                    raw = await asyncio.wait_for(
                        reader.readuntil(b"\n"), timeout=self.idle_timeout()
                    )
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    writer.write(b"501 5.5.2 Cancelled\r\n")
                    return
                payload = raw.rstrip(b"\r\n").decode("latin-1", errors="replace")
            username, password = self._decode_auth_plain(payload)
        elif mechanism == "LOGIN":
            # RFC 4616 style: server asks for Username/Password as base64 prompts
            writer.write(b"334 VXNlcm5hbWU6\r\n")  # base64("Username:")
            await writer.drain()
            try:
                raw_user = await asyncio.wait_for(
                    reader.readuntil(b"\n"), timeout=self.idle_timeout()
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                writer.write(b"501 5.5.2 Cancelled\r\n")
                return
            username = self._b64_decode(raw_user.rstrip(b"\r\n"))
            writer.write(b"334 UGFzc3dvcmQ6\r\n")  # base64("Password:")
            await writer.drain()
            try:
                raw_pass = await asyncio.wait_for(
                    reader.readuntil(b"\n"), timeout=self.idle_timeout()
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                writer.write(b"501 5.5.2 Cancelled\r\n")
                return
            password = self._b64_decode(raw_pass.rstrip(b"\r\n"))
        else:
            writer.write(b"504 5.5.4 Unrecognized authentication type\r\n")
            return

        session.record_credentials(username, password)
        match = self.engine.rules.match_auth(
            protocol="smtp", username=username, password=password, remote_ip=remote_ip
        )
        await self.emit(
            Event(
                protocol="smtp",
                event_type="auth_attempt",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                username=username,
                password=password,
                message=f"SMTP AUTH {mechanism} for {username}",
                data={"mechanism": mechanism, "tags": match.tags},
            )
        )
        # Open relay: pretend authentication always succeeds.
        writer.write(b"235 2.7.0 Authentication successful\r\n")

    @staticmethod
    def _decode_auth_plain(payload: str) -> tuple[str, str]:
        """Decode a SASL PLAIN payload into ``(username, password)``.

        The RFC 4616 format is ``\\0authzid\\0authcid\\0password``; in practice
        clients commonly send ``\\0username\\0password``. We tolerate both.
        """
        try:
            decoded = base64.b64decode(payload.encode("latin-1"), validate=False)
        except Exception:  # noqa: BLE001
            return "", ""
        parts = decoded.split(b"\x00")
        if len(parts) >= 3:
            return parts[1].decode("latin-1", errors="replace"), parts[2].decode(
                "latin-1", errors="replace"
            )
        if len(parts) == 2:
            return parts[0].decode("latin-1", errors="replace"), parts[1].decode(
                "latin-1", errors="replace"
            )
        return decoded.decode("latin-1", errors="replace"), ""

    @staticmethod
    def _b64_decode(value: bytes) -> str:
        """Best-effort base64 decode of a LOGIN challenge response."""
        try:
            return base64.b64decode(value, validate=False).decode("latin-1", errors="replace")
        except Exception:  # noqa: BLE001
            return value.decode("latin-1", errors="replace")

    async def _consume_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_ip: str,
        remote_port: int,
        session,  # noqa: ANN001
        mail_from: str,
        rcpt_to: list[str],
        idle_timeout: float,
    ) -> None:
        """Read the DATA body until ``<CRLF>.<CRLF>`` or the size limit."""
        total = 0
        headers_done = False
        header_buf = bytearray()
        subject = ""
        from_hdr = ""
        to_hdr = ""
        oversized = False

        while True:
            try:
                line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=idle_timeout)
            except asyncio.TimeoutError:
                await self.log_timeout_event(remote_ip, remote_port, idle_timeout)
                return
            except asyncio.IncompleteReadError:
                return
            except asyncio.LimitOverrunError:
                await self.log_sanitizer_event(remote_ip, remote_port, "smtp_data_line_overrun")
                oversized = True
                break

            if line in (b".\r\n", b".\n"):
                break
            # Dot-stuffing: leading '..' -> '.'
            if line.startswith(b".."):
                line = line[1:]

            total += len(line)
            if total > self.max_data_bytes:
                oversized = True
                # Drain the rest of the body defensively.
                try:
                    while True:
                        chunk = await asyncio.wait_for(
                            reader.readuntil(b"\n"), timeout=idle_timeout
                        )
                        if chunk in (b".\r\n", b".\n"):
                            break
                except Exception:  # noqa: BLE001
                    pass
                break

            if not headers_done:
                stripped = line.rstrip(b"\r\n")
                if not stripped:
                    headers_done = True
                    subject, from_hdr, to_hdr = self._parse_headers(bytes(header_buf))
                else:
                    header_buf += line

        if oversized:
            writer.write(b"552 5.3.4 Message too big\r\n")
            await self.emit(
                Event(
                    protocol="smtp",
                    event_type="data_rejected",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    session_id=session.session_id,
                    message="DATA rejected: oversized message",
                    data={
                        "bytes": total,
                        "limit": self.max_data_bytes,
                        "from": mail_from,
                        "rcpts": rcpt_to,
                    },
                )
            )
            return

        # If body ended before a blank line, parse what we have.
        if not headers_done and header_buf:
            subject, from_hdr, to_hdr = self._parse_headers(bytes(header_buf))

        await self.emit(
            Event(
                protocol="smtp",
                event_type="data_received",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                message=f"DATA from {mail_from} to {','.join(rcpt_to)}",
                data={
                    "from": mail_from,
                    "rcpts": rcpt_to,
                    "subject": subject,
                    "header_from": from_hdr,
                    "header_to": to_hdr,
                    "body_size": total,
                },
            )
        )
        # Open-relay marker for the ATT&CK mapper.
        if rcpt_to and any("@" in r for r in rcpt_to):
            await self.emit(
                Event(
                    protocol="smtp",
                    event_type="open_relay",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    session_id=session.session_id,
                    message=f"Open-relay accepted {len(rcpt_to)} recipients",
                    data={"rcpts": rcpt_to, "from": mail_from},
                )
            )
        writer.write(b"250 2.0.0 Ok: queued as 0DEADBEEF\r\n")

    @staticmethod
    def _parse_headers(blob: bytes) -> tuple[str, str, str]:
        """Extract ``Subject``, ``From`` and ``To`` header values."""
        subject = ""
        from_hdr = ""
        to_hdr = ""
        for raw_line in blob.split(b"\n"):
            m = _HEADER_RE.match(raw_line.rstrip(b"\r"))
            if not m:
                continue
            name = m.group("name").decode("ascii", "replace").lower()
            value = m.group("value").decode("latin-1", "replace").strip()
            if name == "subject" and not subject:
                subject = value
            elif name == "from" and not from_hdr:
                from_hdr = value
            elif name == "to" and not to_hdr:
                to_hdr = value
        return subject, from_hdr, to_hdr


__all__ = ["SMTPHandler"]
