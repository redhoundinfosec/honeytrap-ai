"""MQTT 3.1.1 / 5.0 broker shell honeypot.

Implements just enough of the MQTT Control Packet binary format to keep
attacker tooling (IoT scanners, BotenaGo-style libraries, public-broker
abusers) engaged while logging every captured field through the standard
event bus. The handler accepts every CONNECT, grants every SUBSCRIBE
filter at QoS 0, and ACKs every PUBLISH so the attacker keeps feeding
us topics, payloads, and credentials.

Implemented packet types
~~~~~~~~~~~~~~~~~~~~~~~~

* CONNECT (3.1.1 + 5.0): protocol level, flags, keepalive, properties
  (v5), client id, will topic/message, username, password.
* CONNACK: reason code 0x00. v5 includes Receive Maximum and Maximum
  Packet Size properties.
* SUBSCRIBE / SUBACK: filter list parsed; SUBACK grants every filter
  QoS 0.
* PUBLISH: topic + payload captured. PUBACK for QoS 1, PUBREC for
  QoS 2.
* PINGREQ -> PINGRESP.
* DISCONNECT (graceful close).

Optional ghost-publishing of fake values onto subscribed topics is
disabled by default — operators must opt in because injecting traffic
into an attacker session is active deception, not pure observation.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


_BUFFER_CAP_BYTES = 256 * 1024

_PT_CONNECT = 0x01
_PT_CONNACK = 0x02
_PT_PUBLISH = 0x03
_PT_PUBACK = 0x04
_PT_PUBREC = 0x05
_PT_SUBSCRIBE = 0x08
_PT_SUBACK = 0x09
_PT_UNSUBSCRIBE = 0x0A
_PT_UNSUBACK = 0x0B
_PT_PINGREQ = 0x0C
_PT_PINGRESP = 0x0D
_PT_DISCONNECT = 0x0E

_C2_TOPIC_FRAGMENTS: tuple[str, ...] = ("/cmd", "/exec", "/ota", "/firmware/upload")
_SCANNER_CLIENT_PREFIXES: tuple[str, ...] = (
    "mqtt-explorer",
    "mosquitto_sub",
    "mosquitto_pub",
    "paho",
    "iotsearch",
)


class ProtocolParseError(Exception):
    """Raised when the MQTT parser refuses attacker input."""


# ---------------------------------------------------------------------------
# Wire-format helpers
# ---------------------------------------------------------------------------


def _decode_remaining_length(buffer: bytes, offset: int) -> tuple[int, int]:
    """Decode an MQTT variable-byte integer.

    Returns ``(value, bytes_consumed)``. Raises :class:`ProtocolParseError`
    on truncated or oversize encodings.
    """
    multiplier = 1
    value = 0
    for i in range(4):
        if offset + i >= len(buffer):
            raise ProtocolParseError("truncated remaining-length")
        byte = buffer[offset + i]
        value += (byte & 0x7F) * multiplier
        if not (byte & 0x80):
            return value, i + 1
        multiplier *= 128
        if multiplier > 128 * 128 * 128 * 128:
            raise ProtocolParseError("remaining-length too large")
    raise ProtocolParseError("malformed remaining-length")


def _encode_remaining_length(value: int) -> bytes:
    """Encode an integer into MQTT variable-byte form."""
    if value < 0 or value > 268_435_455:
        raise ValueError(f"remaining-length out of range: {value}")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
            out.append(byte)
        else:
            out.append(byte)
            break
    return bytes(out)


def _read_string(buffer: bytes, offset: int) -> tuple[str, int]:
    """Read an MQTT length-prefixed UTF-8 string from ``buffer``."""
    if offset + 2 > len(buffer):
        raise ProtocolParseError("string length truncated")
    length = struct.unpack(">H", buffer[offset : offset + 2])[0]
    end = offset + 2 + length
    if end > len(buffer):
        raise ProtocolParseError("string body truncated")
    text = buffer[offset + 2 : end].decode("utf-8", errors="replace")
    return text, end


def _read_binary(buffer: bytes, offset: int) -> tuple[bytes, int]:
    """Read an MQTT length-prefixed binary blob."""
    if offset + 2 > len(buffer):
        raise ProtocolParseError("binary length truncated")
    length = struct.unpack(">H", buffer[offset : offset + 2])[0]
    end = offset + 2 + length
    if end > len(buffer):
        raise ProtocolParseError("binary body truncated")
    return buffer[offset + 2 : end], end


def _skip_v5_properties(buffer: bytes, offset: int) -> int:
    """Skip the v5 property block at ``offset``. Returns new offset."""
    prop_len, consumed = _decode_remaining_length(buffer, offset)
    end = offset + consumed + prop_len
    if end > len(buffer):
        raise ProtocolParseError("v5 properties truncated")
    return end


def parse_connect(payload: bytes) -> dict[str, Any]:
    """Parse the variable header + payload of a ``CONNECT`` packet.

    Returns a dict with the captured fields. Raises
    :class:`ProtocolParseError` on malformed input.
    """
    if len(payload) < 10:
        raise ProtocolParseError("CONNECT too short")
    proto_name, off = _read_string(payload, 0)
    if proto_name not in {"MQTT", "MQIsdp"}:
        raise ProtocolParseError(f"unexpected protocol name {proto_name!r}")
    if off + 4 > len(payload):
        raise ProtocolParseError("CONNECT header truncated")
    level = payload[off]
    flags = payload[off + 1]
    keepalive = struct.unpack(">H", payload[off + 2 : off + 4])[0]
    off += 4
    if level == 5:
        off = _skip_v5_properties(payload, off)
    client_id, off = _read_string(payload, off)
    will_topic = ""
    will_payload = b""
    if flags & 0x04:  # will flag
        if level == 5:
            off = _skip_v5_properties(payload, off)
        will_topic, off = _read_string(payload, off)
        will_payload, off = _read_binary(payload, off)
    username = ""
    password = ""
    if flags & 0x80:  # username flag
        username, off = _read_string(payload, off)
    if flags & 0x40:  # password flag
        pwd_bytes, off = _read_binary(payload, off)
        password = pwd_bytes.decode("utf-8", errors="replace")
    return {
        "protocol": proto_name,
        "level": level,
        "flags": flags,
        "keepalive": keepalive,
        "client_id": client_id,
        "username": username,
        "password": password,
        "will_topic": will_topic,
        "will_payload_preview": will_payload[:256],
        "will_payload_size": len(will_payload),
    }


def build_connack(*, level: int, session_present: bool = False) -> bytes:
    """Build a CONNACK accepting the connection (reason 0x00)."""
    if level == 5:
        # v5: ack flags(1) | reason(1) | property length(varbyte) | properties
        # Properties: 0x21 Receive Maximum (uint16) = 32, 0x27 Maximum Packet Size (uint32) = 65535
        props = b"\x21" + struct.pack(">H", 32) + b"\x27" + struct.pack(">I", 65535)
        var_header = bytes([0x01 if session_present else 0x00, 0x00]) + (
            _encode_remaining_length(len(props)) + props
        )
    else:
        var_header = bytes([0x01 if session_present else 0x00, 0x00])
    fixed = bytes([_PT_CONNACK << 4]) + _encode_remaining_length(len(var_header))
    return fixed + var_header


def parse_subscribe(payload: bytes, level: int) -> dict[str, Any]:
    """Parse a ``SUBSCRIBE`` packet variable header + filter list."""
    if len(payload) < 2:
        raise ProtocolParseError("SUBSCRIBE truncated")
    packet_id = struct.unpack(">H", payload[:2])[0]
    off = 2
    if level == 5:
        off = _skip_v5_properties(payload, off)
    filters: list[dict[str, Any]] = []
    while off < len(payload):
        topic, off = _read_string(payload, off)
        if off >= len(payload):
            raise ProtocolParseError("SUBSCRIBE missing options byte")
        opts = payload[off]
        off += 1
        filters.append({"topic": topic, "qos": opts & 0x03, "options": opts})
    return {"packet_id": packet_id, "filters": filters}


def build_suback(packet_id: int, filters: list[dict[str, Any]], level: int) -> bytes:
    """Build a SUBACK granting each requested filter QoS 0."""
    body = struct.pack(">H", packet_id)
    if level == 5:
        body += b"\x00"  # empty property length
    body += bytes(0x00 for _ in filters) or b"\x00"
    fixed = bytes([_PT_SUBACK << 4]) + _encode_remaining_length(len(body))
    return fixed + body


def parse_publish(payload: bytes, fixed_flags: int, level: int) -> dict[str, Any]:
    """Parse a ``PUBLISH`` packet variable header + payload."""
    qos = (fixed_flags >> 1) & 0x03
    if qos == 3:
        raise ProtocolParseError("PUBLISH invalid QoS 3")
    topic, off = _read_string(payload, 0)
    packet_id = 0
    if qos > 0:
        if off + 2 > len(payload):
            raise ProtocolParseError("PUBLISH packet id missing")
        packet_id = struct.unpack(">H", payload[off : off + 2])[0]
        off += 2
    if level == 5:
        off = _skip_v5_properties(payload, off)
    body = payload[off:]
    return {
        "topic": topic,
        "qos": qos,
        "retain": bool(fixed_flags & 0x01),
        "dup": bool(fixed_flags & 0x08),
        "packet_id": packet_id,
        "payload_preview": body[:512],
        "payload_size": len(body),
    }


def build_puback(packet_id: int, level: int) -> bytes:
    """Build a PUBACK for the given packet id."""
    body = struct.pack(">H", packet_id)
    if level == 5:
        body += b"\x00\x00"  # reason code + property length
    fixed = bytes([_PT_PUBACK << 4]) + _encode_remaining_length(len(body))
    return fixed + body


def build_pubrec(packet_id: int, level: int) -> bytes:
    """Build a PUBREC for the given packet id."""
    body = struct.pack(">H", packet_id)
    if level == 5:
        body += b"\x00\x00"
    fixed = bytes([_PT_PUBREC << 4]) + _encode_remaining_length(len(body))
    return fixed + body


def build_pingresp() -> bytes:
    """Build a PINGRESP fixed header."""
    return bytes([_PT_PINGRESP << 4, 0x00])


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class MQTTHandler(ProtocolHandler):
    """Protocol handler for the MQTT broker shell honeypot."""

    name = "mqtt"

    def __init__(self, service: ServiceSpec, engine: Any) -> None:
        """Initialize the MQTT honeypot."""
        super().__init__(service, engine)
        self._server: asyncio.base_events.Server | None = None
        self.adaptive_ai_enabled: bool = bool(service.data.get("adaptive_ai_enabled", False))
        self.ghost_publishing: bool = bool(service.data.get("ghost_publishing", False))
        self.ghost_messages: list[dict[str, Any]] = list(
            service.data.get("ghost_messages", [])
            or [{"topic": "home/alarm/status", "payload": "disabled"}]
        )

    async def start(self, bind_address: str, port: int) -> None:
        """Start the MQTT listener on ``bind_address:port``."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            self._server = await asyncio.start_server(self._handle, bind_address, port)
        except OSError as exc:
            raise PortBindError(f"Could not bind MQTT on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop accepting new MQTT connections."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Gate a new MQTT connection and dispatch into the dialogue."""
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
        """Run the packet-by-packet MQTT dialogue."""
        geo = await self.resolve_geo(remote_ip)
        session = self.engine.sessions.create(remote_ip, remote_port, "mqtt", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")
        await self.emit(
            Event(
                protocol="mqtt",
                event_type="connection_open",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                session_id=session.session_id,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                message="MQTT client connected",
            )
        )

        idle_timeout = self.idle_timeout()
        protocol_level = 4
        bytes_total = 0
        try:
            while True:
                packet = await self._read_packet(reader, idle_timeout)
                if packet is None:
                    break
                packet_type, fixed_flags, payload = packet
                bytes_total += len(payload) + 2
                if bytes_total > _BUFFER_CAP_BYTES:
                    await self.log_sanitizer_event(remote_ip, remote_port, "mqtt_session_cap")
                    break

                try:
                    if packet_type == _PT_CONNECT:
                        info = parse_connect(payload)
                        protocol_level = int(info.get("level") or 4)
                        await self._on_connect(info, remote_ip, remote_port, session)
                        writer.write(build_connack(level=protocol_level))
                    elif packet_type == _PT_SUBSCRIBE:
                        sub = parse_subscribe(payload, protocol_level)
                        await self._on_subscribe(sub, remote_ip, remote_port, session)
                        writer.write(build_suback(sub["packet_id"], sub["filters"], protocol_level))
                        if self.ghost_publishing:
                            for ghost in self._ghost_publish_packets(protocol_level):
                                writer.write(ghost)
                    elif packet_type == _PT_PUBLISH:
                        pub = parse_publish(payload, fixed_flags, protocol_level)
                        await self._on_publish(pub, remote_ip, remote_port, session)
                        if pub["qos"] == 1:
                            writer.write(build_puback(pub["packet_id"], protocol_level))
                        elif pub["qos"] == 2:
                            writer.write(build_pubrec(pub["packet_id"], protocol_level))
                    elif packet_type == _PT_PINGREQ:
                        writer.write(build_pingresp())
                    elif packet_type == _PT_DISCONNECT:
                        await self.emit(
                            Event(
                                protocol="mqtt",
                                event_type="disconnect",
                                remote_ip=remote_ip,
                                remote_port=remote_port,
                                session_id=session.session_id,
                                message="MQTT DISCONNECT",
                            )
                        )
                        break
                    elif packet_type == _PT_UNSUBSCRIBE:
                        # Minimal handling: just ack with UNSUBACK echoing the packet id.
                        if len(payload) >= 2:
                            packet_id = struct.unpack(">H", payload[:2])[0]
                            ack = bytes([_PT_UNSUBACK << 4, 0x02]) + struct.pack(">H", packet_id)
                            writer.write(ack)
                    else:
                        await self.emit(
                            Event(
                                protocol="mqtt",
                                event_type="unknown_packet",
                                remote_ip=remote_ip,
                                remote_port=remote_port,
                                session_id=session.session_id,
                                message=f"unexpected packet type {packet_type:#x}",
                                data={"type": packet_type, "size": len(payload)},
                            )
                        )
                    await writer.drain()
                except ProtocolParseError as exc:
                    await self.emit(
                        Event(
                            protocol="mqtt",
                            event_type="parse_error",
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            session_id=session.session_id,
                            message=f"MQTT parse error: {exc}",
                        )
                    )
                    break
        except Exception as exc:  # noqa: BLE001
            logger.exception("MQTT handler exception for %s: %s", remote_ip, exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.emit(
                Event(
                    protocol="mqtt",
                    event_type="connection_close",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    message="MQTT session closed",
                )
            )

    async def _read_packet(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> tuple[int, int, bytes] | None:
        """Read one full MQTT control packet and return ``(type, flags, payload)``."""
        try:
            first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None
        first = first_byte[0]
        packet_type = (first >> 4) & 0x0F
        flags = first & 0x0F
        # Read the variable-byte remaining length.
        multiplier = 1
        value = 0
        for _ in range(4):
            try:
                byte = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                return None
            value += (byte & 0x7F) * multiplier
            if not (byte & 0x80):
                break
            multiplier *= 128
        else:
            return None
        if value < 0 or value > _BUFFER_CAP_BYTES:
            return None
        try:
            payload = (
                await asyncio.wait_for(reader.readexactly(value), timeout=timeout) if value else b""
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None
        return packet_type, flags, payload

    # ------------------------------------------------------------------
    # Per-packet handlers
    # ------------------------------------------------------------------
    async def _on_connect(
        self,
        info: dict[str, Any],
        remote_ip: str,
        remote_port: int,
        session: Any,
    ) -> None:
        """Emit a connect event and an auth event when credentials were sent."""
        client_id = str(info.get("client_id") or "")
        username = str(info.get("username") or "")
        password = str(info.get("password") or "")
        await self.emit(
            Event(
                protocol="mqtt",
                event_type="mqtt_connect",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                username=username,
                password=password,
                message=f"MQTT CONNECT level={info.get('level')} client_id={client_id!r}",
                data=dict(info, scanner_match=self._client_id_is_scanner_like(client_id)),
            )
        )
        if username or password:
            session.record_credentials(username, password)
            match = self.engine.rules.match_auth(
                protocol="mqtt", username=username, password=password, remote_ip=remote_ip
            )
            await self.emit(
                Event(
                    protocol="mqtt",
                    event_type="auth_attempt",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    session_id=session.session_id,
                    username=username,
                    password=password,
                    message=f"MQTT AUTH {username}",
                    data={"client_id": client_id, "tags": match.tags, "success": True},
                )
            )

    async def _on_subscribe(
        self,
        info: dict[str, Any],
        remote_ip: str,
        remote_port: int,
        session: Any,
    ) -> None:
        """Emit a SUBSCRIBE event listing every requested filter."""
        await self.emit(
            Event(
                protocol="mqtt",
                event_type="subscribe",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                message=f"MQTT SUBSCRIBE {len(info['filters'])} filters",
                data=info,
            )
        )

    async def _on_publish(
        self,
        info: dict[str, Any],
        remote_ip: str,
        remote_port: int,
        session: Any,
    ) -> None:
        """Emit a PUBLISH event capturing topic + payload preview."""
        topic = str(info.get("topic") or "")
        payload_bytes = info.get("payload_preview") or b""
        try:
            payload_preview = payload_bytes.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            payload_preview = ""
        await self.emit(
            Event(
                protocol="mqtt",
                event_type="publish",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                message=f"MQTT PUBLISH topic={topic} qos={info.get('qos')}",
                data={
                    "topic": topic,
                    "qos": info.get("qos"),
                    "retain": info.get("retain"),
                    "packet_id": info.get("packet_id"),
                    "payload_preview": payload_preview,
                    "payload_size": info.get("payload_size"),
                    "c2_pattern_match": self._topic_is_c2_like(topic),
                },
            )
        )

    def _ghost_publish_packets(self, level: int) -> list[bytes]:
        """Return wire bytes for each configured ghost-publish payload."""
        out: list[bytes] = []
        for entry in self.ghost_messages:
            topic = str(entry.get("topic") or "")
            payload = str(entry.get("payload") or "").encode("utf-8")
            if not topic:
                continue
            topic_bytes = topic.encode("utf-8")
            var_header = struct.pack(">H", len(topic_bytes)) + topic_bytes
            if level == 5:
                var_header += b"\x00"
            body = var_header + payload
            fixed = bytes([_PT_PUBLISH << 4]) + _encode_remaining_length(len(body))
            out.append(fixed + body)
        return out

    @staticmethod
    def _topic_is_c2_like(topic: str) -> bool:
        """Return True when ``topic`` looks like a C2/firmware push channel."""
        lower = topic.lower()
        return any(frag in lower for frag in _C2_TOPIC_FRAGMENTS)

    @staticmethod
    def _client_id_is_scanner_like(client_id: str) -> bool:
        """Return True when ``client_id`` matches a known scanner-tool prefix."""
        if not client_id:
            return True  # empty client id is itself suspicious
        lower = client_id.lower()
        return any(lower.startswith(prefix) for prefix in _SCANNER_CLIENT_PREFIXES)


__all__ = [
    "MQTTHandler",
    "ProtocolParseError",
    "parse_connect",
    "parse_subscribe",
    "parse_publish",
    "build_connack",
    "build_suback",
    "build_puback",
    "build_pubrec",
    "build_pingresp",
    "_decode_remaining_length",
    "_encode_remaining_length",
]
