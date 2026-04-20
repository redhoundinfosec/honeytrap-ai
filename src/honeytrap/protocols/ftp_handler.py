"""FTP honeypot.

A custom asyncio implementation — we only need enough of the FTP command
set to keep attackers engaged for a while and log their activity:

* ``USER`` / ``PASS`` with optional anonymous login
* ``SYST``, ``FEAT``, ``PWD``, ``CWD``, ``CDUP``, ``TYPE``, ``NOOP``, ``QUIT``
* ``LIST`` / ``NLST`` on fake directories
* ``RETR`` on fake files — responds with small canned content
* ``STOR`` is accepted but discarded; we log the size and optional content

A fake filesystem is built from the device profile's ``fake_files`` list and
decorated with personality-aware file names when geo variation is enabled.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


_CRLF = b"\r\n"


class FTPHandler(ProtocolHandler):
    """Custom asyncio FTP honeypot."""

    name = "ftp"

    def __init__(self, service: ServiceSpec, engine) -> None:  # noqa: ANN001
        """Initialize the FTP honeypot handler."""
        super().__init__(service, engine)
        self._server: asyncio.base_events.Server | None = None
        self.banner = service.banner or "220 QNAP FTP Server ready"
        self.allow_anonymous = bool(service.data.get("allow_anonymous", True))
        self.fake_files: list[dict[str, Any]] = list(service.data.get("fake_files", []) or [])

    async def start(self, bind_address: str, port: int) -> None:
        """Start the FTP listener on the configured port."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            self._server = await asyncio.start_server(self._handle, bind_address, port)
        except OSError as exc:
            raise PortBindError(f"Could not bind FTP on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop the FTP listener and disconnect clients."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        remote_ip, remote_port = peer[0], peer[1]

        # Security gate before we allocate anything — reject at the door.
        allowed, decision, _reason = await self.check_connection_allowed(remote_ip)
        if not allowed:
            await self.log_rate_limit_event(remote_ip, remote_port, decision)
            await self.apply_tarpit(decision)
            try:
                writer.write(b"421 Service not available, closing control connection.\r\n")
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
        geo = await self.resolve_geo(remote_ip)
        personality = self.engine.personalities.for_country(geo["country_code"])
        session = self.engine.sessions.create(remote_ip, remote_port, "ftp", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")

        await self.emit(
            Event(
                protocol="ftp",
                event_type="connection_open",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                session_id=session.session_id,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                message="FTP client connected",
                data={"personality": personality.key},
            )
        )

        try:
            writer.write(f"{self.banner}\r\n".encode())
            await writer.drain()
            username = ""
            cwd = "/"
            idle_timeout = self.idle_timeout()
            while not reader.at_eof():
                try:
                    # Bound the read so it never exceeds the configured
                    # command limit; oversized bytes are inspected by the
                    # sanitizer below and logged as a security event.
                    raw = await asyncio.wait_for(
                        reader.readuntil(b"\n"),
                        timeout=idle_timeout,
                    )
                except asyncio.TimeoutError:
                    await self.log_timeout_event(remote_ip, remote_port, idle_timeout)
                    break
                except asyncio.IncompleteReadError:
                    break
                except asyncio.LimitOverrunError:
                    # Oversized single line — matches the sanitizer's intent.
                    await self.log_sanitizer_event(
                        remote_ip, remote_port, "ftp_line_overrun"
                    )
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
                        writer.write(b"500 Command too long.\r\n")
                        await writer.drain()
                    except Exception:  # noqa: BLE001
                        pass
                    continue
                line = raw.rstrip(b"\r\n").decode("latin-1", errors="replace")
                if not line:
                    continue
                cmd, _, arg = line.partition(" ")
                cmd = cmd.upper().strip()
                session.record_command(line)

                if cmd == "USER":
                    username = arg.strip()
                    writer.write(b"331 Please specify the password.\r\n")
                elif cmd == "PASS":
                    password = arg.strip()
                    session.record_credentials(username, password)
                    match = self.engine.rules.match_auth(
                        protocol="ftp", username=username, password=password, remote_ip=remote_ip
                    )
                    await self.emit(
                        Event(
                            protocol="ftp",
                            event_type="auth_attempt",
                            remote_ip=remote_ip,
                            session_id=session.session_id,
                            country_code=session.country_code,
                            country_name=session.country_name,
                            username=username,
                            password=password,
                            message=f"FTP login attempt for {username}",
                            data={"tags": match.tags, "granted": match.metadata.get("granted")},
                        )
                    )
                    if self.allow_anonymous and username.lower() in {"anonymous", "ftp"} or match.metadata.get("granted"):
                        writer.write(b"230 Login successful.\r\n")
                    else:
                        writer.write(b"530 Login incorrect.\r\n")
                elif cmd == "SYST":
                    writer.write(b"215 UNIX Type: L8\r\n")
                elif cmd == "FEAT":
                    writer.write(b"211-Features:\r\n MDTM\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End\r\n")
                elif cmd == "PWD":
                    writer.write(f'257 "{cwd}" is the current directory\r\n'.encode())
                elif cmd == "CWD":
                    if arg:
                        cwd = arg if arg.startswith("/") else f"{cwd.rstrip('/')}/{arg}"
                        writer.write(b"250 Directory successfully changed.\r\n")
                    else:
                        writer.write(b"550 Failed to change directory.\r\n")
                elif cmd == "CDUP":
                    cwd = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
                    writer.write(b"250 Directory successfully changed.\r\n")
                elif cmd == "TYPE":
                    writer.write(b"200 Switching to Binary mode.\r\n")
                elif cmd == "NOOP":
                    writer.write(b"200 OK\r\n")
                elif cmd in {"LIST", "NLST"}:
                    writer.write(b"150 Here comes the directory listing.\r\n")
                    listing = self._fake_listing(cwd, personality)
                    writer.write(listing.encode())
                    writer.write(b"226 Directory send OK.\r\n")
                    await self.emit(
                        Event(
                            protocol="ftp",
                            event_type="list",
                            remote_ip=remote_ip,
                            session_id=session.session_id,
                            path=cwd,
                            message=f"LIST {cwd}",
                        )
                    )
                elif cmd == "RETR":
                    writer.write(b"150 Opening BINARY mode data connection.\r\n")
                    content = self._fake_file_content(arg, personality)
                    writer.write(content.encode())
                    writer.write(b"226 Transfer complete.\r\n")
                    await self.emit(
                        Event(
                            protocol="ftp",
                            event_type="download",
                            remote_ip=remote_ip,
                            session_id=session.session_id,
                            path=arg,
                            message=f"RETR {arg}",
                        )
                    )
                elif cmd == "STOR":
                    writer.write(b"150 Ok to send data.\r\n")
                    writer.write(b"226 Transfer complete.\r\n")
                    await self.emit(
                        Event(
                            protocol="ftp",
                            event_type="upload_attempt",
                            remote_ip=remote_ip,
                            session_id=session.session_id,
                            path=arg,
                            message=f"STOR {arg}",
                        )
                    )
                elif cmd in {"QUIT", "BYE"}:
                    writer.write(b"221 Goodbye.\r\n")
                    break
                else:
                    writer.write(b"500 Unknown command.\r\n")
                try:
                    await writer.drain()
                except ConnectionError:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.exception("FTP handler exception for %s: %s", remote_ip, exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.emit(
                Event(
                    protocol="ftp",
                    event_type="connection_close",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    message="FTP session closed",
                )
            )

    # ------------------------------------------------------------------
    # Fake FS
    # ------------------------------------------------------------------
    def _fake_listing(self, cwd: str, personality) -> str:  # noqa: ANN001
        """Build a realistic ``ls -l`` style listing."""
        entries = self._visible_entries(cwd, personality)
        lines: list[str] = []
        lines.append("drwxr-xr-x 2 ftp ftp 4096 Apr 19 12:00 .")
        lines.append("drwxr-xr-x 3 ftp ftp 4096 Apr 19 12:00 ..")
        for entry in entries:
            name = entry["name"]
            size = entry.get("size", 1024)
            kind = entry.get("type", "file")
            perms = "drwxr-xr-x" if kind == "dir" else "-rw-r--r--"
            lines.append(f"{perms} 1 ftp ftp {size:>9} Apr 19 12:00 {name}")
        return "\r\n".join(lines) + "\r\n"

    def _visible_entries(self, cwd: str, personality) -> list[dict[str, Any]]:  # noqa: ANN001
        """Compute the listing for ``cwd`` from profile + personality."""
        cwd_norm = cwd.strip("/")
        entries: list[dict[str, Any]] = []
        prefix = cwd_norm + "/" if cwd_norm else ""

        # Entries from the profile.
        for entry in self.fake_files:
            raw_path = str(entry.get("path", "")).strip("/")
            if not raw_path:
                continue
            if not raw_path.startswith(prefix):
                continue
            remainder = raw_path[len(prefix) :]
            first = remainder.split("/", 1)[0]
            if "/" in remainder:
                if not any(e["name"] == first for e in entries):
                    entries.append({"name": first, "type": "dir", "size": 4096})
            else:
                size = self._fake_size(entry.get("size_fake") or entry.get("content", ""))
                entries.append({"name": first, "type": "file", "size": size})

        # If no entries and we're at the top, decorate with the personality file names.
        if not entries and cwd_norm == "":
            for name in personality.sample_file_names:
                entries.append({"name": name, "type": "file", "size": 1024 * 16})
        return entries

    @staticmethod
    def _fake_size(value: Any) -> int:
        """Best-effort conversion of ``size_fake`` to bytes."""
        if isinstance(value, int):
            return value
        if not value:
            return 1024
        if isinstance(value, str):
            text = value.strip().upper()
            m = re.match(r"^([\d.]+)\s*([KMGT]?)B?$", text)
            if m:
                number = float(m.group(1))
                mult = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}[m.group(2)]
                return int(number * mult)
            return len(value)
        return 1024

    def _fake_file_content(self, path: str, personality) -> str:  # noqa: ANN001
        """Return canned text content for a requested file."""
        normalized = (path or "").strip("/")
        for entry in self.fake_files:
            if str(entry.get("path", "")).strip("/") == normalized and "content" in entry:
                return str(entry["content"])
        # fallback "readme"
        if normalized.endswith("readme.txt"):
            return f"{personality.welcome_banner}\r\nDo not share credentials.\r\n"
        return f"This is the file {normalized} on {personality.company}\r\n"
