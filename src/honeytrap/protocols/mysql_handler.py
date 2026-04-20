"""MySQL honeypot.

A hand-rolled asyncio implementation of just enough of the MySQL
client/server protocol (as documented at
https://dev.mysql.com/doc/internals/en/client-server-protocol.html) to
keep scanners and brute-force tools engaged while logging everything.

The goal is *plausibility*, not correctness: we speak protocol version
10, send a greeting that looks like a stock MySQL 5.7/8.0 install, handle
one round of authentication, then reply to a curated set of ``COM_QUERY``
statements with fake result sets. Everything else falls back to a generic
OK packet.

Protocol primitives implemented here:

* Packet framing (``3-byte length || 1-byte seq || payload``)
* Handshake V10 with ``auth_plugin_data`` (scramble) and capability flags
* OK / ERR / EOF packets
* Column definition packets and row data packets
* ``COM_QUIT``, ``COM_PING``, ``COM_QUERY``, ``COM_INIT_DB``
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import struct
from dataclasses import dataclass
from typing import Any

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

_CAP_LONG_PASSWORD = 0x00000001
_CAP_FOUND_ROWS = 0x00000002
_CAP_LONG_FLAG = 0x00000004
_CAP_CONNECT_WITH_DB = 0x00000008
_CAP_PROTOCOL_41 = 0x00000200
_CAP_TRANSACTIONS = 0x00002000
_CAP_SECURE_CONNECTION = 0x00008000
_CAP_PLUGIN_AUTH = 0x00080000
_CAP_PLUGIN_AUTH_LENENC_DATA = 0x00200000

_SERVER_CAPS = (
    _CAP_LONG_PASSWORD
    | _CAP_FOUND_ROWS
    | _CAP_LONG_FLAG
    | _CAP_CONNECT_WITH_DB
    | _CAP_PROTOCOL_41
    | _CAP_TRANSACTIONS
    | _CAP_SECURE_CONNECTION
    | _CAP_PLUGIN_AUTH
    | _CAP_PLUGIN_AUTH_LENENC_DATA
)

_CHARSET_UTF8 = 0x21  # utf8_general_ci
_STATUS_AUTOCOMMIT = 0x0002

_COM_QUIT = 0x01
_COM_INIT_DB = 0x02
_COM_QUERY = 0x03
_COM_PING = 0x0E

# MySQL column type codes we actually use.
_MYSQL_TYPE_LONG = 0x03
_MYSQL_TYPE_VARCHAR = 0x0F
_MYSQL_TYPE_DATETIME = 0x0C
_MYSQL_TYPE_VAR_STRING = 0xFD

_DEFAULT_VERSION = "5.7.42-0ubuntu0.18.04.1"
_DEFAULT_FAKE_DATABASES = ("information_schema", "mysql", "performance_schema", "sys")
_DEFAULT_FAKE_TABLES = ("users", "config", "sessions", "payments")
_DEFAULT_WEAK_CREDENTIALS: tuple[dict[str, str], ...] = (
    {"username": "root", "password": "root"},
    {"username": "mysql", "password": "mysql"},
    {"username": "admin", "password": "password"},
)


_SQL_INJECTION_RE = re.compile(
    r"(union\s+select|or\s+1=1|'\s*or\s*'1'='1|information_schema|sleep\(\d+\))",
    re.I,
)


# ---------------------------------------------------------------------------
# Packet encoding helpers
# ---------------------------------------------------------------------------


def _lenenc_int(value: int) -> bytes:
    """Encode a MySQL length-encoded integer."""
    if value < 0xFB:
        return struct.pack("<B", value)
    if value <= 0xFFFF:
        return b"\xfc" + struct.pack("<H", value)
    if value <= 0xFFFFFF:
        return b"\xfd" + struct.pack("<I", value)[:3]
    return b"\xfe" + struct.pack("<Q", value)


def _lenenc_str(value: bytes) -> bytes:
    """Encode a length-encoded MySQL string."""
    return _lenenc_int(len(value)) + value


def _null_terminated(value: str | bytes) -> bytes:
    """Encode a NUL-terminated string."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return value + b"\x00"


@dataclass
class _Packet:
    """A decoded MySQL packet (payload + sequence id)."""

    seq: int
    payload: bytes


class _PacketIO:
    """Thin wrapper around asyncio streams that speaks MySQL packet framing."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def read_packet(self, timeout: float) -> _Packet | None:
        """Read a single MySQL packet; returns ``None`` on EOF/timeout."""
        try:
            header = await asyncio.wait_for(self.reader.readexactly(4), timeout=timeout)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        seq = header[3]
        try:
            payload = await asyncio.wait_for(self.reader.readexactly(length), timeout=timeout)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
        return _Packet(seq=seq, payload=payload)

    def write_packet(self, seq: int, payload: bytes) -> None:
        """Frame ``payload`` with ``seq`` and push it to the write buffer."""
        length = len(payload)
        header = bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, seq & 0xFF])
        self.writer.write(header + payload)

    async def drain(self) -> None:
        """Drain the underlying writer, swallowing connection errors."""
        try:
            await self.writer.drain()
        except ConnectionError:
            pass


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class MySQLHandler(ProtocolHandler):
    """Custom asyncio MySQL honeypot speaking MySQL protocol v10."""

    name = "mysql"

    def __init__(self, service: ServiceSpec, engine) -> None:  # noqa: ANN001
        """Initialize the MySQL honeypot handler."""
        super().__init__(service, engine)
        self._server: asyncio.base_events.Server | None = None
        self.server_version = str(service.data.get("server_version", _DEFAULT_VERSION))
        self.banner = service.banner or f"MySQL {self.server_version}"
        self.weak_credentials = self._normalize_creds(
            service.data.get("weak_credentials") or _DEFAULT_WEAK_CREDENTIALS
        )
        self.fake_databases = list(service.data.get("fake_databases") or _DEFAULT_FAKE_DATABASES)
        self.fake_tables = list(service.data.get("fake_tables") or _DEFAULT_FAKE_TABLES)
        self._connection_id = 1000

    @staticmethod
    def _normalize_creds(raw: Any) -> set[tuple[str, str]]:
        """Coerce the profile's ``weak_credentials`` into a set of tuples."""
        pairs: set[tuple[str, str]] = set()
        if isinstance(raw, dict):
            raw = [raw]
        for item in raw or []:
            if isinstance(item, dict):
                u = str(item.get("username", ""))
                p = str(item.get("password", ""))
                pairs.add((u, p))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.add((str(item[0]), str(item[1])))
        return pairs

    async def start(self, bind_address: str, port: int) -> None:
        """Start the MySQL listener on the configured port."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            self._server = await asyncio.start_server(self._handle, bind_address, port)
        except OSError as exc:
            raise PortBindError(f"Could not bind MySQL on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop the MySQL listener and disconnect clients."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Connection dispatch
    # ------------------------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Gate a new connection and dispatch to the session loop."""
        peer = writer.get_extra_info("peername") or ("", 0)
        remote_ip, remote_port = peer[0], peer[1]

        allowed, decision, _reason = await self.check_connection_allowed(remote_ip)
        if not allowed:
            await self.log_rate_limit_event(remote_ip, remote_port, decision)
            await self.apply_tarpit(decision)
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
        """Run the MySQL protocol dialogue for a single client."""
        self._connection_id += 1
        conn_id = self._connection_id

        geo = await self.resolve_geo(remote_ip)
        session = self.engine.sessions.create(remote_ip, remote_port, "mysql", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")

        await self.emit(
            Event(
                protocol="mysql",
                event_type="connection_open",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                session_id=session.session_id,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                message="MySQL client connected",
                data={"connection_id": conn_id},
            )
        )

        io = _PacketIO(reader, writer)
        idle_timeout = self.idle_timeout()
        scramble = os.urandom(20)

        try:
            io.write_packet(0, self._build_handshake(conn_id, scramble))
            await io.drain()

            auth_pkt = await io.read_packet(idle_timeout)
            if auth_pkt is None:
                await self.log_timeout_event(remote_ip, remote_port, idle_timeout)
                return

            username, password_bytes, initial_db = self._parse_auth(auth_pkt.payload)
            password_display = password_bytes.hex() if password_bytes else ""
            granted = (username, password_display) in self.weak_credentials or any(
                u == username and p == password_display for u, p in self.weak_credentials
            )
            # Many scanners send a valid plaintext password within the
            # protocol's mysql_native_password slot when they actually want to
            # brute force something trivially. We can't re-derive the
            # plaintext from the SHA1 scramble, but we can match a handful of
            # common short-circuit cases the profile ships with.
            plaintext_guess = self._plaintext_guess(username, password_bytes)
            if plaintext_guess is not None and not granted:
                granted = (username, plaintext_guess) in self.weak_credentials

            match = self.engine.rules.match_auth(
                protocol="mysql",
                username=username,
                password=plaintext_guess or "",
                remote_ip=remote_ip,
            )
            session.record_credentials(username, plaintext_guess or "")
            await self.emit(
                Event(
                    protocol="mysql",
                    event_type="auth_attempt",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    session_id=session.session_id,
                    username=username,
                    password=plaintext_guess or "",
                    message=f"MySQL AUTH for {username}",
                    data={
                        "granted": granted or bool(match.metadata.get("granted")),
                        "initial_db": initial_db,
                        "auth_bytes_hex": password_bytes.hex(),
                        "tags": match.tags,
                    },
                )
            )

            if not (granted or match.metadata.get("granted")):
                io.write_packet(2, self._build_err(1045, "28000", f"Access denied for user '{username}'@'{remote_ip}' (using password: YES)"))
                await io.drain()
                return

            io.write_packet(2, self._build_ok(0, 0))
            await io.drain()

            current_db = initial_db or "information_schema"
            while True:
                pkt = await io.read_packet(idle_timeout)
                if pkt is None:
                    await self.log_timeout_event(remote_ip, remote_port, idle_timeout)
                    break
                if not pkt.payload:
                    continue
                cmd = pkt.payload[0]
                body = pkt.payload[1:]

                if cmd == _COM_QUIT:
                    await self.emit(
                        Event(
                            protocol="mysql",
                            event_type="quit",
                            remote_ip=remote_ip,
                            session_id=session.session_id,
                            message="MySQL COM_QUIT",
                        )
                    )
                    break
                if cmd == _COM_PING:
                    io.write_packet(1, self._build_ok(0, 0))
                    await io.drain()
                    continue
                if cmd == _COM_INIT_DB:
                    current_db = body.decode("utf-8", errors="replace")
                    io.write_packet(1, self._build_ok(0, 0))
                    await io.drain()
                    continue
                if cmd == _COM_QUERY:
                    query = body.decode("utf-8", errors="replace").strip().rstrip(";")
                    session.record_command(query)
                    await self.emit(
                        Event(
                            protocol="mysql",
                            event_type="query",
                            remote_ip=remote_ip,
                            session_id=session.session_id,
                            message=f"QUERY: {query[:200]}",
                            data={"query": query, "database": current_db, "username": username},
                        )
                    )
                    self._dispatch_query(io, query, username, remote_ip, current_db)
                    await io.drain()
                    continue

                # Unknown command — respond with an ERR so the client moves on.
                io.write_packet(
                    1, self._build_err(1047, "HY000", "Unknown command")
                )
                await io.drain()
        except Exception as exc:  # noqa: BLE001
            logger.exception("MySQL handler exception for %s: %s", remote_ip, exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.emit(
                Event(
                    protocol="mysql",
                    event_type="connection_close",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    message="MySQL session closed",
                )
            )

    # ------------------------------------------------------------------
    # Handshake / auth
    # ------------------------------------------------------------------
    def _build_handshake(self, connection_id: int, scramble: bytes) -> bytes:
        """Build a handshake v10 packet.

        Structure:
            protocol_version (1)
            server_version (NUL-terminated string)
            connection_id (u32)
            auth-plugin-data-part-1 (8 bytes)
            filler (1 byte, 0x00)
            capability_flag_1 (2 bytes, lower)
            character_set (1)
            status_flags (2)
            capability_flags_2 (2 bytes, upper)
            auth_plugin_data_len (1)
            reserved (10 bytes, zero)
            auth-plugin-data-part-2 (13 bytes, includes trailing NUL)
            auth_plugin_name (NUL-terminated string)
        """
        caps = _SERVER_CAPS
        scramble_1 = scramble[:8]
        scramble_2 = scramble[8:20] + b"\x00"
        payload = b"\x0a"
        payload += _null_terminated(self.server_version)
        payload += struct.pack("<I", connection_id)
        payload += scramble_1
        payload += b"\x00"
        payload += struct.pack("<H", caps & 0xFFFF)
        payload += struct.pack("<B", _CHARSET_UTF8)
        payload += struct.pack("<H", _STATUS_AUTOCOMMIT)
        payload += struct.pack("<H", (caps >> 16) & 0xFFFF)
        payload += struct.pack("<B", 21)  # auth plugin data length (20) + 1
        payload += b"\x00" * 10
        payload += scramble_2
        payload += _null_terminated("mysql_native_password")
        return payload

    @staticmethod
    def _parse_auth(payload: bytes) -> tuple[str, bytes, str]:
        """Parse a protocol-41 handshake-response packet.

        Structure (when CLIENT_PROTOCOL_41 is set):
            client_flags (4)
            max_packet_size (4)
            charset (1)
            reserved (23 bytes)
            username (NUL-terminated)
            auth_response (lenenc or length-prefixed bytes)
            (optional) initial_database (NUL-terminated)
        """
        if len(payload) < 32:
            return "", b"", ""
        client_flags = struct.unpack("<I", payload[0:4])[0]
        pos = 32  # 4 + 4 + 1 + 23
        try:
            nul = payload.index(b"\x00", pos)
        except ValueError:
            return "", b"", ""
        username = payload[pos:nul].decode("utf-8", errors="replace")
        pos = nul + 1
        # auth response: either length-prefixed (1 byte) or length-encoded.
        if pos >= len(payload):
            return username, b"", ""
        if client_flags & _CAP_PLUGIN_AUTH_LENENC_DATA:
            ar_len, consumed = _read_lenenc_int(payload, pos)
            pos += consumed
        else:
            ar_len = payload[pos]
            pos += 1
        auth_response = payload[pos : pos + ar_len]
        pos += ar_len
        initial_db = ""
        if client_flags & _CAP_CONNECT_WITH_DB and pos < len(payload):
            try:
                nul2 = payload.index(b"\x00", pos)
                initial_db = payload[pos:nul2].decode("utf-8", errors="replace")
            except ValueError:
                initial_db = payload[pos:].decode("utf-8", errors="replace")
        return username, auth_response, initial_db

    @staticmethod
    def _plaintext_guess(username: str, password_bytes: bytes) -> str | None:
        """Best-effort guess of the plaintext password behind the scramble.

        For the mysql_native_password scheme we'd need to reverse a SHA-1
        XOR which is impossible in the general case. But if the client sent
        an empty auth response (very common for misconfigured scanners) we
        know the password was empty. Otherwise we return ``None`` so the
        caller can still log the raw hex.
        """
        if not password_bytes:
            return ""
        return None

    # ------------------------------------------------------------------
    # Query dispatch
    # ------------------------------------------------------------------
    def _dispatch_query(
        self,
        io: _PacketIO,
        query: str,
        username: str,
        remote_ip: str,
        current_db: str,
    ) -> None:
        """Route a COM_QUERY statement to the appropriate fake response."""
        normalized = query.strip().lower()

        if normalized.startswith("select @@version") or normalized == "select version()":
            self._write_result(io, ["@@version"], [[self.server_version]])
            return
        if normalized.startswith("select database()"):
            self._write_result(io, ["database()"], [[current_db]])
            return
        if normalized.startswith("select user()") or normalized.startswith("select current_user"):
            self._write_result(io, ["user()"], [[f"{username}@{remote_ip}"]])
            return
        if normalized.startswith("show databases"):
            self._write_result(io, ["Database"], [[d] for d in self.fake_databases])
            return
        if normalized.startswith("show tables"):
            self._write_result(
                io,
                [f"Tables_in_{current_db}"],
                [[t] for t in self.fake_tables],
            )
            return
        if normalized.startswith("describe ") or normalized.startswith("desc "):
            target = normalized.split(None, 1)[1].strip("`; ")
            self._write_result(io, _DESCRIBE_COLUMNS, self._describe_rows(target))
            return
        if normalized.startswith("select") and " from users" in normalized:
            self._write_result(io, _USER_COLUMNS, list(_FAKE_USER_ROWS))
            return
        if normalized.startswith("use "):
            io.write_packet(1, self._build_ok(0, 0))
            return
        if normalized.startswith("set "):
            io.write_packet(1, self._build_ok(0, 0))
            return
        # Generic empty result / OK
        io.write_packet(1, self._build_ok(0, 0))

    def _write_result(
        self,
        io: _PacketIO,
        columns: list[str],
        rows: list[list[str]],
    ) -> None:
        """Serialize a simple text-mode result set onto the wire."""
        seq = 1
        io.write_packet(seq, _lenenc_int(len(columns)))
        seq += 1
        for col in columns:
            io.write_packet(seq, self._build_column_def(col))
            seq += 1
        io.write_packet(seq, self._build_eof())
        seq += 1
        for row in rows:
            io.write_packet(seq, self._build_row(row))
            seq += 1
        io.write_packet(seq, self._build_eof())

    # ------------------------------------------------------------------
    # Packet builders
    # ------------------------------------------------------------------
    @staticmethod
    def _build_ok(affected_rows: int, last_insert_id: int) -> bytes:
        """Build an OK response packet."""
        payload = b"\x00"
        payload += _lenenc_int(affected_rows)
        payload += _lenenc_int(last_insert_id)
        payload += struct.pack("<H", _STATUS_AUTOCOMMIT)
        payload += struct.pack("<H", 0)  # warnings
        return payload

    @staticmethod
    def _build_err(code: int, sqlstate: str, message: str) -> bytes:
        """Build an ERR response packet."""
        payload = b"\xff"
        payload += struct.pack("<H", code)
        payload += b"#" + sqlstate.encode("ascii")[:5].ljust(5, b"0")
        payload += message.encode("utf-8", errors="replace")
        return payload

    @staticmethod
    def _build_eof() -> bytes:
        """Build an EOF (legacy) packet."""
        return b"\xfe" + struct.pack("<H", 0) + struct.pack("<H", _STATUS_AUTOCOMMIT)

    @staticmethod
    def _build_column_def(name: str) -> bytes:
        """Build a COM_QUERY column-definition packet for ``name``."""
        payload = b""
        payload += _lenenc_str(b"def")
        payload += _lenenc_str(b"")  # schema
        payload += _lenenc_str(b"")  # table
        payload += _lenenc_str(b"")  # org_table
        payload += _lenenc_str(name.encode("utf-8"))
        payload += _lenenc_str(b"")  # org_name
        payload += b"\x0c"  # next length
        payload += struct.pack("<H", _CHARSET_UTF8)
        payload += struct.pack("<I", 255)  # column length
        payload += struct.pack("<B", _MYSQL_TYPE_VAR_STRING)
        payload += struct.pack("<H", 0)  # flags
        payload += struct.pack("<B", 0)  # decimals
        payload += b"\x00\x00"  # filler
        return payload

    @staticmethod
    def _build_row(values: list[str]) -> bytes:
        """Build a single text-mode result row."""
        parts: list[bytes] = []
        for value in values:
            if value is None:
                parts.append(b"\xfb")
            else:
                parts.append(_lenenc_str(str(value).encode("utf-8")))
        return b"".join(parts)

    @staticmethod
    def greeting_preview(server_version: str, connection_id: int = 1001) -> bytes:
        """Build a handshake packet for tests that want to inspect it."""
        scramble = b"\x00" * 20
        handler_stub = MySQLHandler.__new__(MySQLHandler)
        handler_stub.server_version = server_version
        payload = MySQLHandler._build_handshake(handler_stub, connection_id, scramble)
        length = len(payload)
        header = bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, 0])
        return header + payload


def _read_lenenc_int(payload: bytes, pos: int) -> tuple[int, int]:
    """Decode a length-encoded integer. Returns ``(value, bytes_consumed)``."""
    first = payload[pos]
    if first < 0xFB:
        return first, 1
    if first == 0xFC:
        return struct.unpack("<H", payload[pos + 1 : pos + 3])[0], 3
    if first == 0xFD:
        raw = payload[pos + 1 : pos + 4] + b"\x00"
        return struct.unpack("<I", raw)[0], 4
    if first == 0xFE:
        return struct.unpack("<Q", payload[pos + 1 : pos + 9])[0], 9
    return 0, 1


_USER_COLUMNS = ["id", "username", "password", "email", "created_at"]
_FAKE_USER_ROWS: tuple[list[str], ...] = (
    ["1", "admin", "$2b$12$KIX/abc123fakeh4sh", "admin@example.com", "2021-05-14 09:14:22"],
    ["2", "jsmith", "$2b$12$ABC/fakehashforjsmith", "jsmith@example.com", "2022-01-03 17:01:45"],
    ["3", "rpaul", "$2b$12$ZZZ/fakehashforrpaul01", "rpaul@example.com", "2023-07-19 08:50:10"],
    ["4", "operator", "$2b$12$QQQ/operatorhashplace", "operator@example.com", "2024-11-02 22:33:09"],
)

_DESCRIBE_COLUMNS = ["Field", "Type", "Null", "Key", "Default", "Extra"]
_DESCRIBE_USERS_ROWS: tuple[list[str], ...] = (
    ["id", "int(11)", "NO", "PRI", "", "auto_increment"],
    ["username", "varchar(64)", "NO", "UNI", "", ""],
    ["password", "varchar(255)", "NO", "", "", ""],
    ["email", "varchar(128)", "YES", "", "NULL", ""],
    ["created_at", "datetime", "NO", "", "CURRENT_TIMESTAMP", ""],
)
_DESCRIBE_GENERIC_ROWS: tuple[list[str], ...] = (
    ["id", "int(11)", "NO", "PRI", "", "auto_increment"],
    ["name", "varchar(128)", "YES", "", "NULL", ""],
    ["value", "text", "YES", "", "NULL", ""],
)


def _describe_target(rows_source: tuple[list[str], ...]) -> list[list[str]]:
    return [list(r) for r in rows_source]


# Bind helper onto class for neatness.
MySQLHandler._describe_rows = staticmethod(  # type: ignore[attr-defined]
    lambda target: _describe_target(
        _DESCRIBE_USERS_ROWS if target.lower() == "users" else _DESCRIBE_GENERIC_ROWS
    )
)


__all__ = ["MySQLHandler"]
