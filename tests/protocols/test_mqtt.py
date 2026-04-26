"""Unit tests for the MQTT honeypot wire-format helpers and handler."""

from __future__ import annotations

import pytest

from honeytrap.core.profile import ServiceSpec
from honeytrap.protocols.mqtt_handler import (
    MQTTHandler,
    ProtocolParseError,
    _decode_remaining_length,
    _encode_remaining_length,
    build_connack,
    build_pingresp,
    build_puback,
    build_pubrec,
    build_suback,
    parse_connect,
    parse_publish,
    parse_subscribe,
)


def _build_connect_v311(client_id: str, *, username: str = "", password: str = "") -> bytes:
    flags = 0
    payload = bytearray()
    payload += b"\x00\x04MQTT"
    payload += b"\x04"  # protocol level 4
    if username:
        flags |= 0x80
    if password:
        flags |= 0x40
    payload += bytes([flags])
    payload += b"\x00\x3c"  # keepalive 60s
    cid = client_id.encode("utf-8")
    payload += len(cid).to_bytes(2, "big") + cid
    if username:
        u = username.encode("utf-8")
        payload += len(u).to_bytes(2, "big") + u
    if password:
        p = password.encode("utf-8")
        payload += len(p).to_bytes(2, "big") + p
    return bytes(payload)


def test_remaining_length_roundtrip() -> None:
    for value in (0, 1, 127, 128, 16_383, 16_384, 2_097_151, 268_435_455):
        encoded = _encode_remaining_length(value)
        decoded, consumed = _decode_remaining_length(encoded, 0)
        assert decoded == value
        assert consumed == len(encoded)


def test_remaining_length_truncated_raises() -> None:
    with pytest.raises(ProtocolParseError):
        _decode_remaining_length(b"\x80", 0)


def test_remaining_length_too_large_raises() -> None:
    with pytest.raises(ProtocolParseError):
        _decode_remaining_length(b"\xff\xff\xff\xff\x7f", 0)


def test_parse_connect_311_basic() -> None:
    payload = _build_connect_v311("ht-test", username="admin", password="admin")
    result = parse_connect(payload)
    assert result["protocol"] == "MQTT"
    assert result["level"] == 4
    assert result["client_id"] == "ht-test"
    assert result["username"] == "admin"
    assert result["password"] == "admin"
    assert result["keepalive"] == 60


def test_parse_connect_rejects_unknown_protocol() -> None:
    bad = b"\x00\x04XXXX\x04\x00\x00\x10\x00\x00"
    with pytest.raises(ProtocolParseError):
        parse_connect(bad)


def test_parse_connect_rejects_truncated() -> None:
    with pytest.raises(ProtocolParseError):
        parse_connect(b"\x00\x04MQTT")


def test_build_connack_v311_shape() -> None:
    pkt = build_connack(level=4)
    assert pkt[0] >> 4 == 2  # CONNACK packet type
    assert pkt[1] == 0x02  # remaining length 2
    assert pkt[2] == 0x00  # session present false
    assert pkt[3] == 0x00  # reason code 0


def test_build_connack_v5_includes_properties() -> None:
    pkt = build_connack(level=5)
    assert pkt[0] >> 4 == 2
    assert pkt[1] > 2  # has properties
    assert pkt[2] == 0x00
    assert pkt[3] == 0x00


def test_parse_subscribe_filters() -> None:
    body = (
        b"\x00\x07"  # packet id 7
        + b"\x00\x05topic\x00"  # filter "topic" qos 0
        + b"\x00\x06topic2\x01"  # qos 1
    )
    parsed = parse_subscribe(body, level=4)
    assert parsed["packet_id"] == 7
    topics = [f["topic"] for f in parsed["filters"]]
    assert topics == ["topic", "topic2"]
    qoses = [f["qos"] for f in parsed["filters"]]
    assert qoses == [0, 1]


def test_build_suback_grants_qos0_per_filter() -> None:
    suback = build_suback(7, [{"topic": "a", "qos": 0}, {"topic": "b", "qos": 1}], level=4)
    assert suback[0] >> 4 == 9  # SUBACK
    # After fixed header: pkt id (2) + 2 reason bytes
    assert suback[-2:] == b"\x00\x00"


def test_parse_publish_qos1_extracts_topic_and_id() -> None:
    body = b"\x00\x05/cmd/run\x00\x2acommand=ls".replace(b"/cmd/run", b"/cmd/x")  # fixup later
    body = b"\x00\x06" + b"/cmd/x" + b"\x00\x2a" + b"ls"
    parsed = parse_publish(body, fixed_flags=0x02, level=4)
    assert parsed["topic"] == "/cmd/x"
    assert parsed["qos"] == 1
    assert parsed["packet_id"] == 0x2A
    assert parsed["payload_size"] == 2


def test_parse_publish_invalid_qos3_raises() -> None:
    body = b"\x00\x01t"
    with pytest.raises(ProtocolParseError):
        parse_publish(body, fixed_flags=0x06, level=4)


def test_build_puback_and_pubrec_and_pingresp() -> None:
    assert build_puback(1, level=4)[0] >> 4 == 4  # PUBACK
    assert build_pubrec(1, level=4)[0] >> 4 == 5  # PUBREC
    assert build_pingresp() == bytes([0xD0, 0x00])


def test_handler_constructs_with_defaults() -> None:
    spec = ServiceSpec(protocol="mqtt", port=1883)

    class _E:
        class _C:
            ai = None

            class _T:
                mqtt_idle = 30.0
                http_idle = ssh_idle = telnet_idle = ftp_idle = 30.0
                smb_idle = smtp_idle = mysql_idle = imap_idle = rdp_idle = coap_idle = 30.0

            timeouts = _T()

        config = _C()

    handler = MQTTHandler(spec, _E())
    assert handler.name == "mqtt"
    assert handler.ghost_publishing is False
