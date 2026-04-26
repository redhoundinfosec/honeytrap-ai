"""IMAP4rev1 honeypot.

A custom asyncio implementation that speaks just enough of RFC 3501
(IMAP4rev1) and RFC 2595 (STARTTLS) to keep credential-spraying tooling
and email-collection scrapers engaged. The handler logs every captured
artifact through the standard event bus so the ATT&CK mapper, IOC
extractor, alert rules, and forensic recorder all light up
automatically.

Implemented commands
~~~~~~~~~~~~~~~~~~~~

* ``CAPABILITY``
* ``NOOP``
* ``LOGOUT``
* ``STARTTLS`` (advertises ready, leaves the cipher upgrade to a fresh
  TLS handshake captured via the existing :mod:`honeytrap.protocols.tls_peek`)
* ``LOGIN`` and ``AUTHENTICATE PLAIN`` (RFC 4616 SASL)
* ``LIST``, ``LSUB``, ``STATUS``, ``SELECT``, ``EXAMINE``, ``CLOSE``,
  ``EXPUNGE``, ``SEARCH``
* ``FETCH N BODY[HEADER]`` and ``FETCH N RFC822``

Anything we do not recognize gets a tagged ``BAD Unknown command`` so
the connection stays alive long enough for an analyst to see what the
attacker tried next.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


_CRLF = b"\r\n"
_DEFAULT_GREETING = (
    "* OK [CAPABILITY IMAP4rev1 STARTTLS LOGIN-REFERRALS ID ENABLE IDLE "
    "LITERAL+ AUTH=PLAIN AUTH=LOGIN] HoneyTrap IMAP ready"
)
_DEFAULT_CAPABILITIES = (
    "IMAP4rev1",
    "STARTTLS",
    "LOGIN-REFERRALS",
    "ID",
    "ENABLE",
    "IDLE",
    "LITERAL+",
    "AUTH=PLAIN",
    "AUTH=LOGIN",
)
_BUFFER_CAP_BYTES = 256 * 1024
_DEFAULT_MAILBOXES: tuple[str, ...] = (
    "INBOX",
    "Sent",
    "Drafts",
    "Trash",
    "Reports/2026-Q1",
)


class ProtocolParseError(Exception):
    """Raised when a binary parser refuses to interpret attacker input."""


def _parse_imap_command(raw: bytes) -> tuple[str, str, str]:
    """Split a raw IMAP line into ``(tag, command, args)``.

    The IMAP grammar lets a tag be any printable ASCII apart from a few
    reserved characters; we cap the tag at 32 chars to keep bizarre
    inputs from blowing up the dialogue. ``args`` is the rest of the
    line, stripped of trailing CRLF.
    """
    if len(raw) > _BUFFER_CAP_BYTES:
        raise ProtocolParseError("imap line too long")
    text = raw.rstrip(b"\r\n").decode("latin-1", errors="replace")
    if not text:
        return "", "", ""
    parts = text.split(" ", 2)
    if len(parts) < 2:
        return parts[0][:32], "", ""
    tag = parts[0][:32]
    command = parts[1].upper()
    args = parts[2] if len(parts) > 2 else ""
    return tag, command, args


def _utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601, timezone-aware."""
    return datetime.now(timezone.utc).isoformat()


class IMAPHandler(ProtocolHandler):
    """IMAP4rev1 honeypot speaker."""

    name = "imap"

    def __init__(self, service: ServiceSpec, engine: Any) -> None:
        """Initialize the IMAP honeypot from its service spec."""
        super().__init__(service, engine)
        self._server: asyncio.base_events.Server | None = None
        self.greeting = str(service.data.get("greeting", _DEFAULT_GREETING))
        self.capabilities: tuple[str, ...] = tuple(
            service.data.get("capabilities", _DEFAULT_CAPABILITIES)
        )
        self.hostname = str(service.data.get("hostname", "mail.example.com"))
        self.mailboxes: tuple[str, ...] = tuple(service.data.get("mailboxes", _DEFAULT_MAILBOXES))
        self.adaptive_ai_enabled: bool = bool(service.data.get("adaptive_ai_enabled", False))
        self.fixture_path: str = str(service.data.get("mailbox_fixture", ""))
        self._messages: list[dict[str, Any]] = self._load_fixtures()

    # ------------------------------------------------------------------
    # Fixture loading
    # ------------------------------------------------------------------
    def _load_fixtures(self) -> list[dict[str, Any]]:
        """Load the honeypot's fake mailbox content from disk.

        The ``mailbox_fixture`` profile field can point at either a YAML
        file (relative to the bundled ``profiles`` tree) or be left
        empty, in which case we fall back to a small in-memory set.
        """
        inline = self.service.data.get("messages")
        if isinstance(inline, list) and inline:
            return [m for m in inline if isinstance(m, dict)]
        if self.fixture_path:
            for root in self._candidate_fixture_roots():
                target = root / self.fixture_path
                if target.exists():
                    try:
                        with target.open("r", encoding="utf-8") as fh:
                            data = yaml.safe_load(fh) or {}
                        msgs = data.get("messages") if isinstance(data, dict) else None
                        if isinstance(msgs, list):
                            return [m for m in msgs if isinstance(m, dict)]
                    except (OSError, yaml.YAMLError) as exc:
                        logger.warning("IMAP fixture load failed (%s): %s", target, exc)
                        break
        return [
            {
                "uid": 1,
                "from": "hr@example.com",
                "to": "ops@example.com",
                "subject": "Quarterly review reminder",
                "date": "Mon, 13 Apr 2026 09:01:11 +0000",
                "body": "Reminder: please complete your Q2 self-assessment by Friday.",
            },
            {
                "uid": 2,
                "from": "finance@example.com",
                "to": "ops@example.com",
                "subject": "Invoice #20260412 attached",
                "date": "Tue, 14 Apr 2026 14:23:09 +0000",
                "body": "Invoice attached. Please remit within 30 days.",
            },
            {
                "uid": 3,
                "from": "helpdesk@example.com",
                "to": "ops@example.com",
                "subject": "Scheduled maintenance window",
                "date": "Wed, 15 Apr 2026 02:00:00 +0000",
                "body": "Maintenance scheduled for Saturday 2026-04-25 02:00 UTC.",
            },
        ]

    @staticmethod
    def _candidate_fixture_roots() -> list[Path]:
        """Return possible roots that contain ``profiles/mailboxes/<...>.yaml``."""
        here = Path(__file__).resolve()
        candidates: list[Path] = [
            here.parent.parent.parent.parent / "profiles",
            Path.cwd() / "profiles",
        ]
        return [c for c in candidates if c.exists()]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self, bind_address: str, port: int) -> None:
        """Start the IMAP listener on ``bind_address:port``."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            self._server = await asyncio.start_server(self._handle, bind_address, port)
        except OSError as exc:
            raise PortBindError(f"Could not bind IMAP on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop accepting new IMAP connections and shut the listener down."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Gate a new connection and dispatch into the IMAP dialogue."""
        peer = writer.get_extra_info("peername") or ("", 0)
        remote_ip, remote_port = peer[0], peer[1]
        allowed, decision, _reason = await self.check_connection_allowed(remote_ip)
        if not allowed:
            await self.log_rate_limit_event(remote_ip, remote_port, decision)
            await self.apply_tarpit(decision)
            try:
                writer.write(b"* BYE Service unavailable\r\n")
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
            writer.close()
            return
        await self.engine.rate_limiter.acquire(remote_ip)
        try:
            await self._dialogue(reader, writer, remote_ip, remote_port)
        finally:
            await self.engine.rate_limiter.release(remote_ip)

    async def _dialogue(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_ip: str,
        remote_port: int,
    ) -> None:
        """Drive the line-oriented IMAP4rev1 conversation."""
        geo = await self.resolve_geo(remote_ip)
        session = self.engine.sessions.create(remote_ip, remote_port, "imap", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")
        await self.emit(
            Event(
                protocol="imap",
                event_type="connection_open",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                session_id=session.session_id,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                message="IMAP client connected",
            )
        )

        idle_timeout = self.idle_timeout()
        authenticated_user: str = ""
        selected_mailbox: str = ""
        bytes_read = 0

        try:
            writer.write(f"{self.greeting}\r\n".encode())
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
                    await self.log_sanitizer_event(remote_ip, remote_port, "imap_line_overrun")
                    break

                if not raw:
                    break

                bytes_read += len(raw)
                if bytes_read > _BUFFER_CAP_BYTES:
                    await self.log_sanitizer_event(remote_ip, remote_port, "imap_session_cap")
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
                        writer.write(b"* BAD line rejected\r\n")
                        await writer.drain()
                    except Exception:  # noqa: BLE001
                        pass
                    continue

                try:
                    tag, command, args = _parse_imap_command(raw)
                except ProtocolParseError as exc:
                    logger.debug("IMAP parse error from %s: %s", remote_ip, exc)
                    break
                if not command:
                    continue

                session.record_command(f"{tag} {command} {args}".strip())

                stop = await self._dispatch(
                    writer,
                    reader,
                    tag=tag,
                    command=command,
                    args=args,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    session=session,
                    state={
                        "user": authenticated_user,
                        "selected": selected_mailbox,
                    },
                )
                if stop is None:
                    continue
                authenticated_user, selected_mailbox, should_break = stop
                if should_break:
                    break
                try:
                    await writer.drain()
                except ConnectionError:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.exception("IMAP handler exception for %s: %s", remote_ip, exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.emit(
                Event(
                    protocol="imap",
                    event_type="connection_close",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    message="IMAP session closed",
                )
            )

    async def _dispatch(
        self,
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
        *,
        tag: str,
        command: str,
        args: str,
        remote_ip: str,
        remote_port: int,
        session: Any,
        state: dict[str, str],
    ) -> tuple[str, str, bool] | None:
        """Dispatch a single tagged IMAP command and return updated state.

        Returns a tuple ``(authenticated_user, selected_mailbox,
        should_break)`` for the dialogue loop to absorb. Returning
        ``None`` is shorthand for "no state changes, keep looping."
        """
        user = state["user"]
        selected = state["selected"]

        if command == "CAPABILITY":
            writer.write(f"* CAPABILITY {' '.join(self.capabilities)}\r\n".encode())
            writer.write(f"{tag} OK CAPABILITY completed\r\n".encode())
        elif command == "NOOP":
            writer.write(f"{tag} OK NOOP completed\r\n".encode())
        elif command == "LOGOUT":
            writer.write(b"* BYE HoneyTrap IMAP server signing off\r\n")
            writer.write(f"{tag} OK LOGOUT completed\r\n".encode())
            return user, selected, True
        elif command == "STARTTLS":
            writer.write(f"{tag} OK Begin TLS negotiation now\r\n".encode())
            await writer.drain()
            await self._capture_tls_handshake(reader, remote_ip, remote_port, session)
            return user, selected, True
        elif command == "LOGIN":
            user = await self._handle_login(
                writer,
                args=args,
                tag=tag,
                remote_ip=remote_ip,
                remote_port=remote_port,
                session=session,
            )
        elif command == "AUTHENTICATE":
            user = await self._handle_authenticate(
                writer,
                reader,
                args=args,
                tag=tag,
                remote_ip=remote_ip,
                remote_port=remote_port,
                session=session,
            )
        elif command in {"LIST", "LSUB"}:
            await self._handle_list(writer, tag=tag, command=command, args=args)
        elif command == "STATUS":
            await self._handle_status(writer, tag=tag, args=args)
        elif command in {"SELECT", "EXAMINE"}:
            selected = await self._handle_select(
                writer,
                tag=tag,
                args=args,
                command=command,
                remote_ip=remote_ip,
                remote_port=remote_port,
                session=session,
            )
        elif command == "FETCH":
            await self._handle_fetch(
                writer,
                tag=tag,
                args=args,
                remote_ip=remote_ip,
                remote_port=remote_port,
                session=session,
            )
        elif command == "SEARCH":
            await self._handle_search(writer, tag=tag, args=args)
        elif command == "CLOSE":
            selected = ""
            writer.write(f"{tag} OK CLOSE completed\r\n".encode())
        elif command == "EXPUNGE":
            writer.write(f"{tag} OK EXPUNGE completed\r\n".encode())
        elif command == "ID":
            writer.write(b"* ID NIL\r\n")
            writer.write(f"{tag} OK ID completed\r\n".encode())
        elif command == "ENABLE":
            writer.write(b"* ENABLED\r\n")
            writer.write(f"{tag} OK ENABLE completed\r\n".encode())
        else:
            await self.emit(
                Event(
                    protocol="imap",
                    event_type="unknown_command",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    session_id=session.session_id,
                    message=f"unknown: {command}",
                    data={"command": command, "args": args[:256]},
                )
            )
            writer.write(f"{tag} BAD Unknown command\r\n".encode())
        return user, selected, False

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------
    async def _handle_login(
        self,
        writer: asyncio.StreamWriter,
        *,
        args: str,
        tag: str,
        remote_ip: str,
        remote_port: int,
        session: Any,
    ) -> str:
        """Handle ``LOGIN <user> <pass>`` and emit an auth event."""
        username, password = self._split_login_args(args)
        session.record_credentials(username, password)
        match = self.engine.rules.match_auth(
            protocol="imap", username=username, password=password, remote_ip=remote_ip
        )
        await self.emit(
            Event(
                protocol="imap",
                event_type="auth_attempt",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                username=username,
                password=password,
                message=f"IMAP LOGIN {username}",
                data={"mechanism": "LOGIN", "tags": match.tags, "success": True},
            )
        )
        writer.write(f"{tag} OK LOGIN completed\r\n".encode())
        return username

    async def _handle_authenticate(
        self,
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
        *,
        args: str,
        tag: str,
        remote_ip: str,
        remote_port: int,
        session: Any,
    ) -> str:
        """Handle ``AUTHENTICATE PLAIN`` and decode the SASL payload."""
        mechanism = args.strip().upper().split(" ", 1)[0]
        if mechanism != "PLAIN":
            writer.write(f"{tag} NO Unsupported AUTH mechanism\r\n".encode())
            return ""
        writer.write(b"+ \r\n")
        await writer.drain()
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=self.idle_timeout())
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            writer.write(f"{tag} NO Authentication cancelled\r\n".encode())
            return ""
        username, password = self._decode_sasl_plain(raw.rstrip(b"\r\n"))
        session.record_credentials(username, password)
        match = self.engine.rules.match_auth(
            protocol="imap", username=username, password=password, remote_ip=remote_ip
        )
        await self.emit(
            Event(
                protocol="imap",
                event_type="auth_attempt",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                username=username,
                password=password,
                message=f"IMAP AUTHENTICATE PLAIN {username}",
                data={"mechanism": "PLAIN", "tags": match.tags, "success": True},
            )
        )
        writer.write(f"{tag} OK AUTHENTICATE completed\r\n".encode())
        return username

    @staticmethod
    def _split_login_args(args: str) -> tuple[str, str]:
        """Pull the username and password out of an IMAP LOGIN line.

        Both fields may be quoted strings or bare atoms — we honour quotes
        if present and otherwise split on whitespace.
        """
        text = args.strip()
        if not text:
            return "", ""
        if text.startswith('"'):
            quoted = re.match(r'"((?:[^"\\]|\\.)*)"\s+(.*)', text)
            if quoted:
                user = quoted.group(1).replace('\\"', '"').replace("\\\\", "\\")
                rest = quoted.group(2).strip()
                if rest.startswith('"'):
                    quoted2 = re.match(r'"((?:[^"\\]|\\.)*)"', rest)
                    if quoted2:
                        return user, quoted2.group(1).replace('\\"', '"').replace("\\\\", "\\")
                return user, rest
        parts = text.split(None, 1)
        if len(parts) == 1:
            return parts[0].strip('"'), ""
        return parts[0].strip('"'), parts[1].strip().strip('"')

    @staticmethod
    def _decode_sasl_plain(payload: bytes) -> tuple[str, str]:
        """Decode an RFC 4616 SASL PLAIN payload.

        Layout: ``\\0authzid\\0authcid\\0password``. We tolerate the common
        two-field variant ``\\0username\\0password`` as well.
        """
        try:
            decoded = base64.b64decode(payload, validate=False)
        except Exception:  # noqa: BLE001
            return "", ""
        parts = decoded.split(b"\x00")
        if len(parts) >= 3:
            return (
                parts[1].decode("latin-1", errors="replace"),
                parts[2].decode("latin-1", errors="replace"),
            )
        if len(parts) == 2:
            return (
                parts[0].decode("latin-1", errors="replace"),
                parts[1].decode("latin-1", errors="replace"),
            )
        return decoded.decode("latin-1", errors="replace"), ""

    # ------------------------------------------------------------------
    # Mailbox helpers
    # ------------------------------------------------------------------
    async def _handle_list(
        self,
        writer: asyncio.StreamWriter,
        *,
        tag: str,
        command: str,
        args: str,
    ) -> None:
        """Reply to ``LIST``/``LSUB`` with the configured mailbox tree."""
        for mbox in self.mailboxes:
            writer.write(f'* {command} (\\HasNoChildren) "/" "{mbox}"\r\n'.encode())
        writer.write(f"{tag} OK {command} completed\r\n".encode())

    async def _handle_status(
        self,
        writer: asyncio.StreamWriter,
        *,
        tag: str,
        args: str,
    ) -> None:
        """Reply to ``STATUS`` with synthetic counters for the mailbox."""
        match = re.match(r'\s*"?([^"\s]+)"?\s+\(([^)]+)\)', args)
        mailbox = match.group(1) if match else "INBOX"
        items = match.group(2).split() if match else ["MESSAGES", "RECENT", "UIDNEXT"]
        values: list[str] = []
        msg_count = len(self._messages)
        for item in items:
            upper = item.upper()
            if upper == "MESSAGES":
                values.append(f"MESSAGES {msg_count}")
            elif upper == "RECENT":
                values.append(f"RECENT {min(msg_count, 1)}")
            elif upper == "UIDNEXT":
                values.append(f"UIDNEXT {msg_count + 1}")
            elif upper == "UIDVALIDITY":
                values.append("UIDVALIDITY 1714000000")
            elif upper == "UNSEEN":
                values.append("UNSEEN 0")
        writer.write(f'* STATUS "{mailbox}" ({" ".join(values)})\r\n'.encode())
        writer.write(f"{tag} OK STATUS completed\r\n".encode())

    async def _handle_select(
        self,
        writer: asyncio.StreamWriter,
        *,
        tag: str,
        args: str,
        command: str,
        remote_ip: str,
        remote_port: int,
        session: Any,
    ) -> str:
        """Reply to ``SELECT INBOX`` (or any mailbox) with realistic counters."""
        mailbox = args.strip().strip('"') or "INBOX"
        msg_count = len(self._messages)
        writer.write(rb"* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)" + _CRLF)
        writer.write(
            rb"* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft)] Limited" + _CRLF
        )
        writer.write(f"* {msg_count} EXISTS\r\n".encode())
        writer.write(b"* 0 RECENT\r\n")
        writer.write(b"* OK [UIDVALIDITY 1714000000] UIDs valid\r\n")
        writer.write(f"* OK [UIDNEXT {msg_count + 1}] Predicted next UID\r\n".encode())
        writer.write(f"{tag} OK [READ-WRITE] {command} completed\r\n".encode())
        await self.emit(
            Event(
                protocol="imap",
                event_type="select",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                message=f"{command} {mailbox}",
                data={"mailbox": mailbox, "exists": msg_count},
            )
        )
        return mailbox

    async def _handle_fetch(
        self,
        writer: asyncio.StreamWriter,
        *,
        tag: str,
        args: str,
        remote_ip: str,
        remote_port: int,
        session: Any,
    ) -> None:
        """Reply to ``FETCH N BODY[HEADER]`` and ``FETCH N RFC822``."""
        match = re.match(r"\s*(\d+)\s+(.+)", args)
        if not match:
            writer.write(f"{tag} BAD FETCH syntax\r\n".encode())
            return
        try:
            seq = int(match.group(1))
        except ValueError:
            writer.write(f"{tag} BAD FETCH syntax\r\n".encode())
            return
        spec = match.group(2).strip().upper()
        if not 1 <= seq <= len(self._messages):
            writer.write(f"{tag} OK FETCH completed\r\n".encode())
            return
        message = self._messages[seq - 1]
        await self.emit(
            Event(
                protocol="imap",
                event_type="fetch",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                message=f"FETCH {seq} {spec}",
                data={"seq": seq, "spec": spec},
            )
        )
        if "RFC822" in spec or "BODY[]" in spec:
            payload = self._render_message(message)
            writer.write(
                f"* {seq} FETCH (RFC822 {{{len(payload)}}}\r\n".encode() + payload + b")\r\n"
            )
        elif "HEADER" in spec:
            payload = self._render_headers(message)
            writer.write(
                f"* {seq} FETCH (BODY[HEADER] {{{len(payload)}}}\r\n".encode() + payload + b")\r\n"
            )
        else:
            writer.write(
                f'* {seq} FETCH (FLAGS (\\Seen) ENVELOPE ("{message.get("date", "")}" '
                f'"{message.get("subject", "")}" "{message.get("from", "")}"))\r\n'.encode()
            )
        writer.write(f"{tag} OK FETCH completed\r\n".encode())

    async def _handle_search(
        self,
        writer: asyncio.StreamWriter,
        *,
        tag: str,
        args: str,
    ) -> None:
        """Reply to ``SEARCH`` with the full sequence range we have."""
        ids = " ".join(str(i + 1) for i in range(len(self._messages)))
        writer.write(f"* SEARCH {ids}\r\n".encode())
        writer.write(f"{tag} OK SEARCH completed\r\n".encode())

    @staticmethod
    def _render_headers(message: dict[str, Any]) -> bytes:
        """Render a single message's headers as RFC 5322 header bytes."""
        date = str(message.get("date", "Mon, 01 Jan 2026 00:00:00 +0000"))
        subject = str(message.get("subject", "(no subject)"))
        sender = str(message.get("from", "noreply@example.com"))
        rcpt = str(message.get("to", "ops@example.com"))
        msg_id = f"<{message.get('uid', 1)}@mail.example.com>"
        headers = (
            f"Date: {date}\r\n"
            f"From: {sender}\r\n"
            f"To: {rcpt}\r\n"
            f"Subject: {subject}\r\n"
            f"Message-ID: {msg_id}\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "\r\n"
        )
        return headers.encode("utf-8")

    def _render_message(self, message: dict[str, Any]) -> bytes:
        """Render headers + body as a single RFC 822-style message blob."""
        body = str(message.get("body", "")).encode("utf-8")
        return self._render_headers(message) + body + b"\r\n"

    # ------------------------------------------------------------------
    # STARTTLS handshake capture
    # ------------------------------------------------------------------
    async def _capture_tls_handshake(
        self,
        reader: asyncio.StreamReader,
        remote_ip: str,
        remote_port: int,
        session: Any,
    ) -> None:
        """Peek at the post-STARTTLS bytes for JA3/JA4 fingerprinting.

        We never complete the TLS upgrade — the goal is just to capture
        the ClientHello so the fingerprinter can attribute the tooling.
        """
        try:
            from honeytrap.intel.tls.fingerprinter import TLSFingerprinter
            from honeytrap.protocols.tls_peek import peek_tls_client_hello
        except Exception as exc:  # noqa: BLE001
            logger.debug("STARTTLS peek skipped: %s", exc)
            return
        try:
            result = await peek_tls_client_hello(reader, TLSFingerprinter())
        except Exception as exc:  # noqa: BLE001
            logger.debug("STARTTLS peek raised: %s", exc)
            return
        fp = result.fingerprint
        tls_fingerprint = fp.to_dict() if fp is not None else {}
        await self.emit(
            Event(
                protocol="imap",
                event_type="starttls",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                message="STARTTLS handshake captured",
                data={
                    "tls_fingerprint": tls_fingerprint,
                    "is_tls": result.is_tls,
                    "captured_bytes": len(result.consumed_bytes),
                    "captured_at": _utc_now_iso(),
                },
            )
        )


__all__ = ["IMAPHandler", "ProtocolParseError"]


def _smoke_self_test() -> str:
    """Tiny self-test for the offline helpers — exercised by unit tests."""
    user, pwd = IMAPHandler._decode_sasl_plain(base64.b64encode(b"\x00alice\x00s3cret"))
    return json.dumps({"user": user, "pwd": pwd})
