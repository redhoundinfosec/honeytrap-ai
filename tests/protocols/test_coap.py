"""Unit tests for the CoAP UDP honeypot."""

from __future__ import annotations

import pytest

from honeytrap.core.profile import ServiceSpec
from honeytrap.protocols.coap_handler import (
    COAP_METHOD_GET,
    COAP_METHOD_POST,
    OPT_URI_PATH,
    OPT_URI_QUERY,
    RESP_CONTENT,
    RESP_NOT_FOUND,
    CoAPHandler,
    CoAPMessage,
    ProtocolParseError,
    _PerSourceRateLimiter,
    build_response,
    parse_message,
)


def _build_get_request(path: str, *, message_id: int = 0x1234, token: bytes = b"\x01\x02") -> bytes:
    parts = [p for p in path.strip("/").split("/") if p]
    options: list[tuple[int, bytes]] = [(OPT_URI_PATH, p.encode()) for p in parts]
    return build_response(
        type_=0,  # CON
        code=COAP_METHOD_GET,
        message_id=message_id,
        token=token,
        options=options,
    )


def test_parse_message_get_with_uri_path() -> None:
    raw = _build_get_request("/sensors/temp")
    msg = parse_message(raw)
    assert msg.version == 1
    assert msg.code == COAP_METHOD_GET
    assert msg.token == b"\x01\x02"
    assert msg.message_id == 0x1234
    assert msg.uri_path == "/sensors/temp"
    assert msg.method_name == "GET"


def test_parse_message_too_short_raises() -> None:
    with pytest.raises(ProtocolParseError):
        parse_message(b"\x40\x01")


def test_parse_message_invalid_version_raises() -> None:
    raw = bytes([0x80, 0x01, 0x00, 0x00])  # version=2
    with pytest.raises(ProtocolParseError):
        parse_message(raw)


def test_parse_message_token_truncated_raises() -> None:
    raw = bytes([0x48, 0x01, 0x00, 0x00, 0x00])  # tkl=8, only 1 byte token
    with pytest.raises(ProtocolParseError):
        parse_message(raw)


def test_build_response_roundtrip() -> None:
    body = b"21.7"
    pkt = build_response(
        type_=2,  # ACK
        code=RESP_CONTENT,
        message_id=0x4242,
        token=b"\xaa",
        options=[(OPT_URI_PATH, b"sensors"), (OPT_URI_PATH, b"temp")],
        payload=body,
    )
    parsed = parse_message(pkt)
    assert parsed.code == RESP_CONTENT
    assert parsed.token == b"\xaa"
    assert parsed.payload == body
    assert parsed.uri_path == "/sensors/temp"


def test_build_response_with_query() -> None:
    pkt = build_response(
        type_=0,
        code=COAP_METHOD_POST,
        message_id=1,
        token=b"",
        options=[(OPT_URI_PATH, b"actuators"), (OPT_URI_QUERY, b"on=true")],
        payload=b"",
    )
    parsed = parse_message(pkt)
    assert parsed.uri_query == ["on=true"]
    assert parsed.uri_path == "/actuators"


def test_per_source_rate_limiter_caps() -> None:
    limiter = _PerSourceRateLimiter(max_per_second=3)
    src = "1.2.3.4"
    assert limiter.check(src) is True
    assert limiter.check(src) is True
    assert limiter.check(src) is True
    assert limiter.check(src) is False


def test_per_source_rate_limiter_zero_disabled() -> None:
    limiter = _PerSourceRateLimiter(max_per_second=0)
    for _ in range(100):
        assert limiter.check("x") is True


def test_handler_uses_profile_max_packets_per_second() -> None:
    spec = ServiceSpec(
        protocol="coap",
        port=5683,
        data={"max_packets_per_second": 7, "temperature_c": 19.1},
    )

    class _E:
        class _C:
            ai = None

            class _T:
                coap_idle = 30.0
                http_idle = ssh_idle = telnet_idle = ftp_idle = 30.0
                smb_idle = smtp_idle = mysql_idle = imap_idle = rdp_idle = mqtt_idle = 30.0

            timeouts = _T()

        config = _C()

    handler = CoAPHandler(spec, _E())
    assert handler.max_packets_per_second == 7
    assert handler.temperature_c == pytest.approx(19.1)
    assert handler.name == "coap"


def test_coap_message_method_name_for_unknown_code() -> None:
    msg = CoAPMessage(version=1, type_=0, token=b"", code=0x99, message_id=0)
    assert msg.method_name == "0x99"
    assert RESP_NOT_FOUND == 0x84
