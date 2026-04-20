"""Tests for the MySQL protocol handler."""

from __future__ import annotations

import asyncio
import socket
import struct
from pathlib import Path

import pytest

from honeytrap.core.config import Config
from honeytrap.core.engine import Engine
from honeytrap.core.profile import DeviceProfile, ServiceSpec
from honeytrap.protocols.mysql_handler import (
    _CAP_CONNECT_WITH_DB,
    _CAP_PLUGIN_AUTH,
    _CAP_PROTOCOL_41,
    _CAP_SECURE_CONNECTION,
    MySQLHandler,
    _lenenc_int,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_profile(port: int, **overrides) -> DeviceProfile:
    data = {
        "server_version": "5.7.42-0ubuntu0.18.04.1",
        "weak_credentials": [
            {"username": "root", "password": ""},
            {"username": "mysql", "password": ""},
        ],
        "fake_databases": ["information_schema", "mysql", "performance_schema", "sys"],
        "fake_tables": ["users", "config", "sessions", "payments"],
    }
    data.update(overrides)
    return DeviceProfile(
        name="mysql test",
        description="",
        category="database",
        services=[ServiceSpec(protocol="mysql", port=port, banner="", data=data)],
    )


async def _start_engine(tmp_path: Path, **profile_overrides) -> tuple[Engine, int]:
    cfg = Config()
    cfg.general.log_directory = str(tmp_path)
    cfg.general.bind_address = "127.0.0.1"
    cfg.geo.enabled = False
    cfg.general.dashboard = False
    cfg.ai.enabled = False
    cfg.timeouts.mysql_idle = 3.0

    port = _free_port()
    profile = _make_profile(port, **profile_overrides)
    engine = Engine(cfg, profile)
    await engine.start()
    bound = next(p for proto, _req, p in engine.active_ports if proto == "mysql")
    return engine, bound


# ---------------------------------------------------------------------------
# Client helpers
# ---------------------------------------------------------------------------


async def _read_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await reader.readexactly(4)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq = header[3]
    payload = await reader.readexactly(length)
    return seq, payload


def _write_packet(writer: asyncio.StreamWriter, seq: int, payload: bytes) -> None:
    length = len(payload)
    writer.write(bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, seq & 0xFF]))
    writer.write(payload)


def _build_auth_packet(username: str, password: bytes, database: str = "") -> bytes:
    caps = _CAP_PROTOCOL_41 | _CAP_SECURE_CONNECTION | _CAP_PLUGIN_AUTH
    if database:
        caps |= _CAP_CONNECT_WITH_DB
    payload = struct.pack("<I", caps)
    payload += struct.pack("<I", 1 << 24)  # max packet size
    payload += struct.pack("<B", 0x21)  # charset
    payload += b"\x00" * 23
    payload += username.encode("utf-8") + b"\x00"
    # Length-prefixed auth response.
    payload += struct.pack("<B", len(password)) + password
    if database:
        payload += database.encode("utf-8") + b"\x00"
    payload += b"mysql_native_password\x00"
    return payload


def _parse_greeting(payload: bytes) -> dict:
    """Parse a handshake v10 payload into a dict."""
    assert payload[0] == 0x0A
    nul = payload.index(b"\x00", 1)
    server_version = payload[1:nul].decode()
    pos = nul + 1
    connection_id = struct.unpack("<I", payload[pos : pos + 4])[0]
    pos += 4
    scramble1 = payload[pos : pos + 8]
    pos += 8 + 1  # filler
    caps_lower = struct.unpack("<H", payload[pos : pos + 2])[0]
    pos += 2
    charset = payload[pos]
    pos += 1
    status = struct.unpack("<H", payload[pos : pos + 2])[0]
    pos += 2
    caps_upper = struct.unpack("<H", payload[pos : pos + 2])[0]
    pos += 2
    auth_len = payload[pos]
    pos += 1
    pos += 10  # reserved
    scramble2 = payload[pos : pos + 12]
    pos += 13
    nul = payload.index(b"\x00", pos)
    plugin = payload[pos:nul].decode()
    return {
        "server_version": server_version,
        "connection_id": connection_id,
        "scramble": scramble1 + scramble2,
        "caps": (caps_upper << 16) | caps_lower,
        "charset": charset,
        "status": status,
        "auth_plugin_data_len": auth_len,
        "auth_plugin_name": plugin,
    }


async def _read_resultset(reader: asyncio.StreamReader) -> tuple[list[str], list[list[str]]]:
    """Read a text-mode result set: count + columns + EOF + rows + EOF."""
    _, first = await _read_packet(reader)
    assert first[0] != 0xFF, f"ERR packet: {first!r}"
    if first[0] == 0x00:
        # OK packet, no result set.
        return [], []
    n = first[0]
    columns: list[str] = []
    for _ in range(n):
        _, col = await _read_packet(reader)
        columns.append(_parse_column_name(col))
    _, eof = await _read_packet(reader)
    assert eof[0] == 0xFE
    rows: list[list[str]] = []
    while True:
        _, pkt = await _read_packet(reader)
        if pkt[0] == 0xFE and len(pkt) < 9:
            break
        rows.append(_parse_row(pkt, n))
    return columns, rows


def _parse_column_name(payload: bytes) -> str:
    """Skip def/schema/table/org_table to find the column name (4th lenenc)."""
    pos = 0
    for _ in range(4):
        length = payload[pos]
        pos += 1 + length
    length = payload[pos]
    pos += 1
    return payload[pos : pos + length].decode("utf-8")


def _parse_row(payload: bytes, n: int) -> list[str]:
    pos = 0
    values: list[str] = []
    for _ in range(n):
        length = payload[pos]
        pos += 1
        values.append(payload[pos : pos + length].decode("utf-8", errors="replace"))
        pos += length
    return values


async def _login(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    username: str,
    password: bytes = b"",
    database: str = "",
) -> tuple[dict, int, bytes]:
    """Perform a MySQL login handshake and return (greeting, resp_type, payload)."""
    _, greeting_payload = await _read_packet(reader)
    greeting = _parse_greeting(greeting_payload)
    _write_packet(writer, 1, _build_auth_packet(username, password, database))
    await writer.drain()
    _, resp = await _read_packet(reader)
    return greeting, resp[0], resp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greeting_is_valid(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        _, payload = await _read_packet(reader)
        g = _parse_greeting(payload)
        assert g["server_version"] == "5.7.42-0ubuntu0.18.04.1"
        assert g["auth_plugin_name"] == "mysql_native_password"
        assert g["charset"] == 0x21
        assert len(g["scramble"]) == 20
        assert g["caps"] & _CAP_PROTOCOL_41
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_auth_success_with_weak_credentials(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        _greeting, kind, _payload = await _login(reader, writer, "root", b"")
        assert kind == 0x00  # OK packet
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_auth_failure_with_unknown_user(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        _greeting, kind, payload = await _login(reader, writer, "nobody", b"\x01\x02\x03")
        assert kind == 0xFF
        assert b"Access denied" in payload
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_select_version_returns_configured_value(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, "root")
        _write_packet(writer, 0, b"\x03SELECT @@version")
        await writer.drain()
        columns, rows = await _read_resultset(reader)
        assert columns == ["@@version"]
        assert rows == [["5.7.42-0ubuntu0.18.04.1"]]
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_show_databases_returns_expected_list(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, "root")
        _write_packet(writer, 0, b"\x03SHOW DATABASES")
        await writer.drain()
        columns, rows = await _read_resultset(reader)
        assert columns == ["Database"]
        names = [r[0] for r in rows]
        assert "information_schema" in names
        assert "mysql" in names
        assert "performance_schema" in names
        assert "sys" in names
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_show_tables_returns_fake_tables(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, "root")
        _write_packet(writer, 0, b"\x03SHOW TABLES")
        await writer.drain()
        columns, rows = await _read_resultset(reader)
        assert columns and columns[0].startswith("Tables_in_")
        names = [r[0] for r in rows]
        assert set(names) >= {"users", "config", "sessions", "payments"}
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_select_star_from_users_returns_rows(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, "root")
        _write_packet(writer, 0, b"\x03SELECT * FROM users")
        await writer.drain()
        columns, rows = await _read_resultset(reader)
        assert columns == ["id", "username", "password", "email", "created_at"]
        assert 3 <= len(rows) <= 8
        # At least one row has an email that looks like an email.
        assert any("@" in r[3] for r in rows)
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_describe_users_returns_column_definitions(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, "root")
        _write_packet(writer, 0, b"\x03DESCRIBE users")
        await writer.drain()
        columns, rows = await _read_resultset(reader)
        assert columns == ["Field", "Type", "Null", "Key", "Default", "Extra"]
        names = [r[0] for r in rows]
        assert names == ["id", "username", "password", "email", "created_at"]
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_unknown_query_returns_ok(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, "root")
        _write_packet(writer, 0, b"\x03SELECT 1 + 1")
        await writer.drain()
        _, resp = await _read_packet(reader)
        assert resp[0] == 0x00
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_idle_timeout_closes_connection(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    engine.config.timeouts.mysql_idle = 0.2
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Read greeting but never respond.
        await _read_packet(reader)
        await asyncio.sleep(0.5)
        # The server should have closed the connection by now.
        tail = await asyncio.wait_for(reader.read(), timeout=1.0)
        assert tail == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_query_event_logged_with_sql_injection_mapping(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        queue = engine.subscribe()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, "root")
        _write_packet(writer, 0, b"\x03SELECT * FROM users WHERE 1=1 UNION SELECT * FROM mysql.user")
        await writer.drain()
        await _read_resultset(reader)
        writer.close()
        await writer.wait_closed()
        found_query = False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 1.0
        while loop.time() < deadline and not found_query:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=deadline - loop.time())
            except asyncio.TimeoutError:
                break
            if ev.event_type == "query":
                found_query = True
                assert "UNION" in ev.data.get("query", "").upper()
        engine.unsubscribe(queue)
        assert found_query
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_quit_closes_cleanly(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _login(reader, writer, "root")
        _write_packet(writer, 0, b"\x01")  # COM_QUIT
        await writer.drain()
        tail = await asyncio.wait_for(reader.read(), timeout=1.0)
        assert tail == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


def test_lenenc_int_encodes_small_values() -> None:
    assert _lenenc_int(0) == b"\x00"
    assert _lenenc_int(10) == b"\x0a"
    assert _lenenc_int(250) == b"\xfa"
    assert _lenenc_int(300).startswith(b"\xfc")


def test_normalize_creds_accepts_list_and_dict() -> None:
    pairs = MySQLHandler._normalize_creds([{"username": "a", "password": "b"}])
    assert ("a", "b") in pairs
    pairs2 = MySQLHandler._normalize_creds([("x", "y")])
    assert ("x", "y") in pairs2
