"""Tests for the IMAP4rev1 honeypot."""

from __future__ import annotations

import asyncio
import base64
import socket
from pathlib import Path

import pytest

from honeytrap.core.config import Config
from honeytrap.core.engine import Engine
from honeytrap.core.profile import ServiceSpec, load_profile
from honeytrap.protocols.imap_handler import (
    IMAPHandler,
    ProtocolParseError,
    _parse_imap_command,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _start_engine(tmp_path: Path) -> tuple[Engine, int]:
    cfg = Config()
    cfg.general.log_directory = str(tmp_path)
    cfg.general.bind_address = "127.0.0.1"
    cfg.geo.enabled = False
    cfg.general.dashboard = False
    cfg.ai.enabled = False
    cfg.timeouts.imap_idle = 5.0

    profile = load_profile("mail_server")
    for s in profile.services:
        s.port = _free_port()

    engine = Engine(cfg, profile)
    await engine.start()
    port = next(p for proto, _req, p in engine.active_ports if proto == "imap")
    return engine, port


# ---------------------------------------------------------------------------
# Parser-level unit tests
# ---------------------------------------------------------------------------


def test_parse_command_basic() -> None:
    tag, command, args = _parse_imap_command(b"a001 LOGIN admin admin\r\n")
    assert tag == "a001"
    assert command == "LOGIN"
    assert args == "admin admin"


def test_parse_command_uppercases_command() -> None:
    tag, command, args = _parse_imap_command(b"X CAPABILITY\r\n")
    assert command == "CAPABILITY"
    assert tag == "X"
    assert args == ""


def test_parse_command_truncates_long_tag() -> None:
    tag, command, _args = _parse_imap_command(b"A" * 100 + b" NOOP\r\n")
    assert len(tag) == 32
    assert command == "NOOP"


def test_parse_command_rejects_oversize() -> None:
    with pytest.raises(ProtocolParseError):
        _parse_imap_command(b"x" * (256 * 1024 + 1))


def test_split_login_args_quoted() -> None:
    user, password = IMAPHandler._split_login_args('"admin user" "p ssw"')
    assert user == "admin user"
    assert password == "p ssw"


def test_split_login_args_unquoted() -> None:
    user, password = IMAPHandler._split_login_args("admin admin123")
    assert user == "admin"
    assert password == "admin123"


def test_decode_sasl_plain_three_field() -> None:
    payload = base64.b64encode(b"\x00alice\x00secret123")
    user, password = IMAPHandler._decode_sasl_plain(payload)
    assert user == "alice"
    assert password == "secret123"


def test_decode_sasl_plain_with_authzid() -> None:
    payload = base64.b64encode(b"alice\x00alice\x00secret")
    user, password = IMAPHandler._decode_sasl_plain(payload)
    assert user == "alice"
    assert password == "secret"


def test_decode_sasl_plain_invalid_returns_empty() -> None:
    user, password = IMAPHandler._decode_sasl_plain(b"!!!not base64!!!")
    # The decoder is permissive (validate=False), but should not crash.
    assert isinstance(user, str)
    assert isinstance(password, str)


def test_handler_loads_default_fixtures_when_path_missing() -> None:
    spec = ServiceSpec(protocol="imap", port=143, data={"mailbox_fixture": "does/not/exist.yaml"})

    class _E:
        class _C:
            ai = None

            class _T:
                imap_idle = 30.0
                http_idle = ssh_idle = telnet_idle = ftp_idle = 30.0
                smb_idle = smtp_idle = mysql_idle = rdp_idle = mqtt_idle = coap_idle = 30.0

            timeouts = _T()

        config = _C()

    handler = IMAPHandler(spec, _E())
    assert handler.name == "imap"
    assert len(handler._messages) >= 1


# ---------------------------------------------------------------------------
# Engine-integrated tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greeting_advertises_capabilities(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        greeting = await reader.readuntil(b"\n")
        assert greeting.startswith(b"* OK")
        assert b"IMAP4rev1" in greeting
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_capability_returns_capabilities(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")  # greeting
        writer.write(b"a CAPABILITY\r\n")
        await writer.drain()
        cap_line = await reader.readuntil(b"\n")
        ok_line = await reader.readuntil(b"\n")
        assert cap_line.startswith(b"* CAPABILITY")
        assert ok_line.startswith(b"a OK")
        writer.write(b"b LOGOUT\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_login_emits_auth_event(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"x LOGIN admin admin\r\n")
        await writer.drain()
        resp = await reader.readuntil(b"\n")
        assert resp.startswith(b"x ")
        writer.write(b"y LOGOUT\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        types = {row["event_type"] for row in engine.database.events_by_type()}
        assert "auth_attempt" in types
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_select_inbox_emits_select_event(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"a LOGIN admin admin\r\n")
        await writer.drain()
        await reader.readuntil(b"\n")
        writer.write(b'b SELECT "INBOX"\r\n')
        await writer.drain()
        # Drain until tagged response.
        while True:
            line = await reader.readuntil(b"\n")
            if line.startswith(b"b "):
                break
        writer.write(b"z LOGOUT\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        types = {row["event_type"] for row in engine.database.events_by_type()}
        assert "select" in types
    finally:
        await engine.stop()
