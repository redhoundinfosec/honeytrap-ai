"""Unit tests for the RDP signature honeypot parser and handler."""

from __future__ import annotations

import struct

import pytest

from honeytrap.core.profile import ServiceSpec
from honeytrap.protocols.rdp_handler import (
    ProtocolParseError,
    RDPHandler,
    _build_x224_connection_confirm,
    _parse_ntlm_negotiate,
    _parse_tpkt,
    _parse_x224_connection_request,
)


def _build_cr_tpdu(*, cookie: str = "", requested_protocols: int | None = None) -> bytes:
    # X.224 fixed part: code(1) + dst-ref(2) + src-ref(2) + class(1) = 6 bytes.
    payload = bytearray()
    payload.append(0x06)  # LI: length of header excluding LI itself
    payload.append(0xE0)  # CR-TPDU code
    payload += b"\x00\x00\x00\x00\x00"  # dst-ref(2) + src-ref(2) + class(1)
    # body_start = li + 1 = 7, where the variable part begins.
    if cookie:
        payload += f"Cookie: mstshash={cookie}\r\n".encode("latin-1")
    if requested_protocols is not None:
        payload += struct.pack("<BBHI", 0x01, 0x00, 8, requested_protocols)
    return bytes(payload)


def _wrap_tpkt(payload: bytes) -> bytes:
    total = 4 + len(payload)
    return struct.pack(">BBH", 0x03, 0x00, total) + payload


def test_tpkt_parses_clean_frame() -> None:
    body = b"hello"
    raw = _wrap_tpkt(body)
    result = _parse_tpkt(raw)
    assert result is not None
    length, remainder = result
    assert length == 9
    assert remainder == body


def test_tpkt_rejects_bad_version() -> None:
    raw = b"\x05\x00\x00\x05\x00"
    with pytest.raises(ProtocolParseError):
        _parse_tpkt(raw)


def test_tpkt_returns_none_for_short_buffer() -> None:
    assert _parse_tpkt(b"\x03\x00") is None


def test_x224_cr_extracts_mstshash() -> None:
    cr = _build_cr_tpdu(cookie="hello-attacker")
    info = _parse_x224_connection_request(cr)
    assert info["mstshash"] == "hello-attacker"
    assert info["negreq_present"] is False


def test_x224_cr_extracts_neg_request() -> None:
    cr = _build_cr_tpdu(requested_protocols=0x03)
    info = _parse_x224_connection_request(cr)
    assert info["negreq_present"] is True
    assert info["requested_protocols"] == 0x03


def test_x224_cr_rejects_non_cr_tpdu() -> None:
    bad = bytes([0x06, 0xD0, 0, 0, 0, 0, 0])  # CC code 0xD0
    with pytest.raises(ProtocolParseError):
        _parse_x224_connection_request(bad)


def test_x224_cc_response_includes_selected_protocol() -> None:
    cc = _build_x224_connection_confirm(0x01)
    # Last 4 LE bytes are the selected protocol.
    assert cc[-4:] == struct.pack("<I", 0x01)
    # First byte is TPKT version 3.
    assert cc[0] == 0x03


def test_ntlm_negotiate_parses_workstation_and_domain() -> None:
    workstation = b"KALI-LINUX"
    domain = b"WORKGROUP"
    # NTLMSSP\x00 + msg_type=1 + flags + domain fields + workstation fields + payload
    sig = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", 1)
    flags = struct.pack("<I", 0)
    payload_offset = 32
    domain_field = struct.pack("<HHI", len(domain), len(domain), payload_offset)
    workstation_field = struct.pack(
        "<HHI", len(workstation), len(workstation), payload_offset + len(domain)
    )
    blob = sig + msg_type + flags + domain_field + workstation_field + domain + workstation
    info = _parse_ntlm_negotiate(blob)
    assert info is not None
    assert info["workstation"] == "KALI-LINUX"
    assert info["domain"] == "WORKGROUP"


def test_ntlm_negotiate_returns_none_without_signature() -> None:
    assert _parse_ntlm_negotiate(b"no ntlm here") is None


def test_handler_construct_with_profile_data() -> None:
    spec = ServiceSpec(
        protocol="rdp",
        port=3389,
        data={"server_name": "TEST-WS", "domain": "DOMAIN", "request_tls": True},
    )

    class _E:
        class _C:
            ai = None

            class _T:
                rdp_idle = 30.0
                http_idle = ssh_idle = telnet_idle = ftp_idle = 30.0
                smb_idle = smtp_idle = mysql_idle = imap_idle = mqtt_idle = coap_idle = 30.0

            timeouts = _T()

        config = _C()

    handler = RDPHandler(spec, _E())
    assert handler.name == "rdp"
    assert handler._mstshash_is_scanner_like("KALI") is True
    assert handler._mstshash_is_scanner_like("Administrator") is False
    assert handler._workstation_is_scanner_like("KALI-LINUX") is True
    assert handler._workstation_is_scanner_like("DESKTOP-FOO") is False
