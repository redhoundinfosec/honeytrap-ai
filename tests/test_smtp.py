"""Tests for the SMTP protocol handler."""

from __future__ import annotations

import asyncio
import base64
import socket
from pathlib import Path

import pytest

from honeytrap.core.config import Config
from honeytrap.core.engine import Engine
from honeytrap.core.profile import load_profile
from honeytrap.protocols.smtp_handler import SMTPHandler


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _start_engine(tmp_path: Path, max_data: int | None = None) -> tuple[Engine, int]:
    cfg = Config()
    cfg.general.log_directory = str(tmp_path)
    cfg.general.bind_address = "127.0.0.1"
    cfg.geo.enabled = False
    cfg.general.dashboard = False
    cfg.ai.enabled = False
    cfg.timeouts.smtp_idle = 5.0

    profile = load_profile("mail_server")
    profile.services[0].port = _free_port()
    if max_data is not None:
        profile.services[0].data["max_data_bytes"] = max_data

    engine = Engine(cfg, profile)
    await engine.start()
    port = next(p for proto, _req, p in engine.active_ports if proto == "smtp")
    return engine, port


async def _read_response(reader: asyncio.StreamReader) -> str:
    """Read a single SMTP response, which may span several CRLF-delimited lines."""
    lines: list[str] = []
    while True:
        line = await reader.readuntil(b"\n")
        text = line.decode("latin-1").rstrip("\r\n")
        lines.append(text)
        if len(text) < 4 or text[3] == " ":
            break
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Engine-integrated tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ehlo_advertises_capabilities(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        banner = await reader.readuntil(b"\n")
        assert banner.startswith(b"220 ")
        writer.write(b"EHLO client.example.com\r\n")
        await writer.drain()
        response = await _read_response(reader)
        assert "AUTH PLAIN LOGIN" in response
        assert "PIPELINING" in response
        assert "SIZE 52428800" in response
        assert "8BITMIME" in response
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_helo_single_line_250(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"HELO basicclient\r\n")
        await writer.drain()
        line = await reader.readuntil(b"\n")
        assert line.startswith(b"250 ")
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_mail_from_and_rcpt_to_accepted(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"EHLO client\r\n")
        await writer.drain()
        await _read_response(reader)
        writer.write(b"MAIL FROM:<alice@evil.example>\r\n")
        writer.write(b"RCPT TO:<victim@example.com>\r\n")
        await writer.drain()
        mail_resp = await reader.readuntil(b"\n")
        rcpt_resp = await reader.readuntil(b"\n")
        assert mail_resp.startswith(b"250")
        assert rcpt_resp.startswith(b"250")
        writer.write(b"QUIT\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        types = {row["event_type"] for row in engine.database.events_by_type()}
        assert "mail_from" in types
        assert "rcpt_to" in types
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_data_flow_354_then_250(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"EHLO me\r\n")
        await writer.drain()
        await _read_response(reader)
        writer.write(b"MAIL FROM:<a@b>\r\n")
        writer.write(b"RCPT TO:<c@d>\r\n")
        writer.write(b"DATA\r\n")
        await writer.drain()
        await reader.readuntil(b"\n")  # 250 MAIL
        await reader.readuntil(b"\n")  # 250 RCPT
        line = await reader.readuntil(b"\n")
        assert line.startswith(b"354")
        writer.write(b"Subject: hello\r\nFrom: a@b\r\nTo: c@d\r\n\r\nbody body body\r\n.\r\n")
        await writer.drain()
        ok = await reader.readuntil(b"\n")
        assert ok.startswith(b"250")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        types = {row["event_type"] for row in engine.database.events_by_type()}
        assert "data_received" in types
        assert "open_relay" in types
    finally:
        await engine.stop()


async def _collect_auth_events(engine: Engine, timeout: float = 0.5) -> list:
    """Drain the engine's event subscriber queue until auth_attempt appears."""
    queue = engine.subscribe()
    collected: list = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=deadline - loop.time())
        except asyncio.TimeoutError:
            break
        collected.append(event)
        if event.event_type == "auth_attempt":
            break
    engine.unsubscribe(queue)
    return collected


@pytest.mark.asyncio
async def test_auth_plain_decodes_credentials(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        queue = engine.subscribe()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"EHLO me\r\n")
        await writer.drain()
        await _read_response(reader)
        payload = base64.b64encode(b"\x00badguy\x00hunter2").decode()
        writer.write(f"AUTH PLAIN {payload}\r\n".encode())
        await writer.drain()
        line = await reader.readuntil(b"\n")
        assert line.startswith(b"235")
        writer.close()
        await writer.wait_closed()
        found = False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 1.0
        while loop.time() < deadline and not found:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=deadline - loop.time())
            except asyncio.TimeoutError:
                break
            if ev.event_type == "auth_attempt" and ev.username == "badguy" and ev.password == "hunter2":
                found = True
        engine.unsubscribe(queue)
        assert found
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_auth_login_multi_step(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        queue = engine.subscribe()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"EHLO me\r\n")
        await writer.drain()
        await _read_response(reader)
        writer.write(b"AUTH LOGIN\r\n")
        await writer.drain()
        prompt1 = await reader.readuntil(b"\n")
        assert prompt1.startswith(b"334 VXNlcm5hbWU6")
        writer.write(base64.b64encode(b"root") + b"\r\n")
        await writer.drain()
        prompt2 = await reader.readuntil(b"\n")
        assert prompt2.startswith(b"334 UGFzc3dvcmQ6")
        writer.write(base64.b64encode(b"toor") + b"\r\n")
        await writer.drain()
        success = await reader.readuntil(b"\n")
        assert success.startswith(b"235")
        writer.close()
        await writer.wait_closed()
        found = False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 1.0
        while loop.time() < deadline and not found:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=deadline - loop.time())
            except asyncio.TimeoutError:
                break
            if ev.event_type == "auth_attempt" and ev.username == "root" and ev.password == "toor":
                found = True
        engine.unsubscribe(queue)
        assert found
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_vrfy_returns_252(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"EHLO me\r\n")
        await writer.drain()
        await _read_response(reader)
        writer.write(b"VRFY root\r\n")
        await writer.drain()
        line = await reader.readuntil(b"\n")
        assert line.startswith(b"252")
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_expn_returns_502(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"EHLO me\r\n")
        await writer.drain()
        await _read_response(reader)
        writer.write(b"EXPN staff\r\n")
        await writer.drain()
        line = await reader.readuntil(b"\n")
        assert line.startswith(b"502")
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_quit_closes_connection(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"QUIT\r\n")
        await writer.drain()
        line = await reader.readuntil(b"\n")
        assert line.startswith(b"221")
        # Server should close; reading again should EOF.
        tail = await reader.read()
        assert tail == b""
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_malformed_command_returns_500(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"HOWDY PARTNER\r\n")
        await writer.drain()
        line = await reader.readuntil(b"\n")
        assert line.startswith(b"500")
        writer.close()
        await writer.wait_closed()
    finally:
        await engine.stop()


@pytest.mark.asyncio
async def test_oversized_data_rejected(tmp_path: Path) -> None:
    engine, port = await _start_engine(tmp_path, max_data=256)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"\n")
        writer.write(b"EHLO me\r\n")
        await writer.drain()
        await _read_response(reader)
        writer.write(b"MAIL FROM:<a@b>\r\n")
        writer.write(b"RCPT TO:<c@d>\r\n")
        writer.write(b"DATA\r\n")
        await writer.drain()
        await reader.readuntil(b"\n")
        await reader.readuntil(b"\n")
        await reader.readuntil(b"\n")  # 354
        big = b"X" * 300
        writer.write(b"Subject: big\r\n\r\n" + big + b"\r\n.\r\n")
        await writer.drain()
        resp = await reader.readuntil(b"\n")
        assert resp.startswith(b"552")
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        types = {row["event_type"] for row in engine.database.events_by_type()}
        assert "data_rejected" in types
    finally:
        await engine.stop()


# ---------------------------------------------------------------------------
# Pure-unit tests on helpers
# ---------------------------------------------------------------------------


def test_extract_address_trims_angle_brackets() -> None:
    assert SMTPHandler._extract_address("FROM:<a@b>", prefix="FROM:") == "a@b"
    assert SMTPHandler._extract_address("TO:<c@d>", prefix="TO:") == "c@d"
    assert SMTPHandler._extract_address("<x@y>", prefix="FROM:") == "x@y"


def test_decode_auth_plain_handles_three_parts() -> None:
    blob = base64.b64encode(b"\x00user\x00pass").decode()
    assert SMTPHandler._decode_auth_plain(blob) == ("user", "pass")


def test_parse_headers_extracts_subject_from_to() -> None:
    raw = b"Subject: hello\r\nFrom: alice@example.com\r\nTo: bob@example.com\r\nX-Mailer: evil\r\n"
    subject, from_hdr, to_hdr = SMTPHandler._parse_headers(raw)
    assert subject == "hello"
    assert from_hdr == "alice@example.com"
    assert to_hdr == "bob@example.com"
