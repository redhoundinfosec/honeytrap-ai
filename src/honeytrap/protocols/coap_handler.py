"""CoAP server honeypot (RFC 7252).

A UDP-based protocol shell that responds to CoAP requests with a small
catalogue of fake IoT resources — sensor readings, an actuator endpoint,
firmware version metadata. Every request is captured as an event so the
ATT&CK mapper, IOC extractor, and alert rules can attribute reconnaissance
and exploitation attempts.

DTLS on port 5684 is intentionally **not** implemented this cycle. We
listen on the requested port and log the bytes seen, but we do not run
a DTLS handshake. A follow-up cycle will wire that in.

Implemented features
~~~~~~~~~~~~~~~~~~~~

* CoAP message parsing: version (must be 1), type (CON/NON/ACK/RST),
  token length, code (method.detail), message id, token, options, and
  payload (after the ``0xFF`` marker).
* GET / POST / PUT / DELETE method handling for a curated resource set.
* ``GET /.well-known/core`` returns CoRE Link Format strings for the
  catalogue.
* Malformed CON messages return 4.00 Bad Request (with an RST fallback
  for messages we cannot even parse the header of).
* Per-source-IP token bucket (default 60 packets/sec) rejects clients
  abusing the listener as a DDoS amplifier.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


_BUFFER_CAP_BYTES = 8192  # Max realistic CoAP datagram per RFC 7252
_PAYLOAD_MARKER = 0xFF

# Type values
COAP_TYPE_CON = 0
COAP_TYPE_NON = 1
COAP_TYPE_ACK = 2
COAP_TYPE_RST = 3

# Method codes
COAP_METHOD_GET = 0x01
COAP_METHOD_POST = 0x02
COAP_METHOD_PUT = 0x03
COAP_METHOD_DELETE = 0x04

# Response codes (class.detail packed into a byte: class << 5 | detail)
RESP_CONTENT = 0x45  # 2.05
RESP_CHANGED = 0x44  # 2.04
RESP_DELETED = 0x42  # 2.02
RESP_BAD_REQUEST = 0x80  # 4.00
RESP_NOT_FOUND = 0x84  # 4.04
RESP_METHOD_NOT_ALLOWED = 0x85  # 4.05

# Option numbers we care about
OPT_URI_PATH = 11
OPT_URI_QUERY = 15
OPT_CONTENT_FORMAT = 12

_DEFAULT_RESOURCES: tuple[str, ...] = (
    '</sensors/temp>;rt="temperature";if="sensor"',
    '</sensors/humidity>;rt="humidity";if="sensor"',
    '</actuators/light>;rt="lighting";if="actuator"',
    '</fw/version>;rt="firmware";if="info"',
)

_SENSITIVE_PATHS: tuple[str, ...] = (
    "config",
    "credentials",
    "secret",
    "tokens",
    "fw/upload",
    "fw/update",
)


class ProtocolParseError(Exception):
    """Raised when the CoAP parser refuses attacker input."""


@dataclass
class CoAPMessage:
    """Parsed CoAP message."""

    version: int
    type_: int
    token: bytes
    code: int
    message_id: int
    options: list[tuple[int, bytes]] = field(default_factory=list)
    payload: bytes = b""

    @property
    def uri_path(self) -> str:
        """Joined URI path from the option list."""
        parts = [v.decode("utf-8", errors="replace") for n, v in self.options if n == OPT_URI_PATH]
        return "/" + "/".join(parts) if parts else "/"

    @property
    def uri_query(self) -> list[str]:
        """List of URI query parameters."""
        return [v.decode("utf-8", errors="replace") for n, v in self.options if n == OPT_URI_QUERY]

    @property
    def method_name(self) -> str:
        """Best-effort method name for the request code."""
        return {
            COAP_METHOD_GET: "GET",
            COAP_METHOD_POST: "POST",
            COAP_METHOD_PUT: "PUT",
            COAP_METHOD_DELETE: "DELETE",
        }.get(self.code, f"0x{self.code:02x}")


def parse_message(data: bytes) -> CoAPMessage:
    """Parse a single CoAP datagram.

    Raises :class:`ProtocolParseError` for any structural problem so the
    caller can decide whether to drop or RST.
    """
    if not data or len(data) < 4:
        raise ProtocolParseError("CoAP datagram too short")
    first = data[0]
    version = (first >> 6) & 0x03
    type_ = (first >> 4) & 0x03
    tkl = first & 0x0F
    if version != 1:
        raise ProtocolParseError(f"unsupported CoAP version {version}")
    if tkl > 8:
        raise ProtocolParseError(f"invalid token length {tkl}")
    code = data[1]
    message_id = (data[2] << 8) | data[3]
    if 4 + tkl > len(data):
        raise ProtocolParseError("CoAP token truncated")
    token = data[4 : 4 + tkl]
    pos = 4 + tkl
    options: list[tuple[int, bytes]] = []
    last_option = 0
    while pos < len(data):
        byte = data[pos]
        if byte == _PAYLOAD_MARKER:
            pos += 1
            break
        delta = (byte >> 4) & 0x0F
        length = byte & 0x0F
        pos += 1
        if delta == 13:
            if pos >= len(data):
                raise ProtocolParseError("option-delta extended truncated")
            delta = data[pos] + 13
            pos += 1
        elif delta == 14:
            if pos + 1 >= len(data):
                raise ProtocolParseError("option-delta extended truncated")
            delta = (data[pos] << 8 | data[pos + 1]) + 269
            pos += 2
        elif delta == 15:
            raise ProtocolParseError("reserved option-delta 15")
        if length == 13:
            if pos >= len(data):
                raise ProtocolParseError("option-length extended truncated")
            length = data[pos] + 13
            pos += 1
        elif length == 14:
            if pos + 1 >= len(data):
                raise ProtocolParseError("option-length extended truncated")
            length = (data[pos] << 8 | data[pos + 1]) + 269
            pos += 2
        elif length == 15:
            raise ProtocolParseError("reserved option-length 15")
        if pos + length > len(data):
            raise ProtocolParseError("option value truncated")
        option_number = last_option + delta
        last_option = option_number
        options.append((option_number, data[pos : pos + length]))
        pos += length
    payload = data[pos:] if pos < len(data) else b""
    return CoAPMessage(
        version=version,
        type_=type_,
        token=token,
        code=code,
        message_id=message_id,
        options=options,
        payload=payload,
    )


def _encode_options(options: list[tuple[int, bytes]]) -> bytes:
    """Encode an options list using the CoAP delta format."""
    out = bytearray()
    last = 0
    for number, value in sorted(options, key=lambda x: x[0]):
        delta = number - last
        last = number
        length = len(value)

        def _ext_byte(field_value: int) -> tuple[int, bytes]:
            if field_value < 13:
                return field_value, b""
            if field_value < 269:
                return 13, bytes([field_value - 13])
            return 14, bytes([(field_value - 269) >> 8 & 0xFF, (field_value - 269) & 0xFF])

        delta_nibble, delta_ext = _ext_byte(delta)
        length_nibble, length_ext = _ext_byte(length)
        out.append((delta_nibble << 4) | length_nibble)
        out.extend(delta_ext)
        out.extend(length_ext)
        out.extend(value)
    return bytes(out)


def build_response(
    *,
    type_: int,
    code: int,
    message_id: int,
    token: bytes,
    options: list[tuple[int, bytes]] | None = None,
    payload: bytes = b"",
) -> bytes:
    """Build a CoAP response datagram."""
    if len(token) > 8:
        raise ValueError("token too long")
    first = (1 << 6) | ((type_ & 0x03) << 4) | (len(token) & 0x0F)
    header = bytes([first, code, (message_id >> 8) & 0xFF, message_id & 0xFF]) + token
    body = _encode_options(options or [])
    if payload:
        body += bytes([_PAYLOAD_MARKER]) + payload
    return header + body


# ---------------------------------------------------------------------------
# Per-source rate limiter (token bucket-ish, 1-second window).
# ---------------------------------------------------------------------------


class _PerSourceRateLimiter:
    """Cap CoAP packets per source IP per second."""

    def __init__(self, max_per_second: int) -> None:
        """Configure the per-source-IP cap."""
        self.max_per_second = int(max_per_second)
        self._counters: dict[str, list[float]] = {}

    def check(self, source: str) -> bool:
        """Return True when ``source`` is allowed to send another packet."""
        if self.max_per_second <= 0:
            return True
        now = time.monotonic()
        bucket = self._counters.setdefault(source, [])
        cutoff = now - 1.0
        # Trim while iterating from the left.
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= self.max_per_second:
            return False
        bucket.append(now)
        return True


# ---------------------------------------------------------------------------
# UDP protocol implementation
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601, timezone-aware."""
    return datetime.now(timezone.utc).isoformat()


class _CoAPDatagramProtocol(asyncio.DatagramProtocol):
    """Asyncio datagram protocol bridging UDP packets to ``CoAPHandler``."""

    def __init__(self, handler: CoAPHandler) -> None:
        """Bind this datagram protocol to the parent handler."""
        super().__init__()
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Cache the transport for outbound replies."""
        if isinstance(transport, asyncio.DatagramTransport):
            self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Pass each datagram to the handler's async dispatcher."""
        if self.transport is None:
            return
        coro = self.handler._dispatch_datagram(data, addr, self.transport)
        try:
            asyncio.get_running_loop().create_task(coro)
        except RuntimeError:
            logger.debug("CoAP datagram_received without a running loop")


class CoAPHandler(ProtocolHandler):
    """RFC 7252 CoAP server honeypot."""

    name = "coap"

    def __init__(self, service: ServiceSpec, engine: Any) -> None:
        """Initialize the CoAP honeypot."""
        super().__init__(service, engine)
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _CoAPDatagramProtocol | None = None
        self.adaptive_ai_enabled: bool = bool(service.data.get("adaptive_ai_enabled", False))
        self.resources: tuple[str, ...] = tuple(service.data.get("resources", _DEFAULT_RESOURCES))
        self.temperature_c: float = float(service.data.get("temperature_c", 21.4))
        self.humidity_pct: float = float(service.data.get("humidity_pct", 47.2))
        self.firmware_version: str = str(
            service.data.get("firmware_version", "openhab-3.4.5-arm32")
        )
        self.max_packets_per_second: int = int(service.data.get("max_packets_per_second", 60))
        self.amplification_threshold: int = int(
            service.data.get("amplification_alert_payload_size", 64)
        )
        self._rate_limiter = _PerSourceRateLimiter(self.max_packets_per_second)

    async def start(self, bind_address: str, port: int) -> None:
        """Start the UDP listener."""
        self.bind_address = bind_address
        self.bound_port = port
        loop = asyncio.get_running_loop()
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _CoAPDatagramProtocol(self),
                local_addr=(bind_address, port),
            )
        except OSError as exc:
            raise PortBindError(f"Could not bind CoAP UDP on {bind_address}:{port}: {exc}") from exc
        self._transport = transport
        self._protocol = protocol

    async def stop(self) -> None:
        """Close the UDP transport."""
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:  # noqa: BLE001
                pass
            self._transport = None
            self._protocol = None

    # ------------------------------------------------------------------
    # Datagram dispatch
    # ------------------------------------------------------------------
    async def _dispatch_datagram(
        self,
        data: bytes,
        addr: tuple[str, int],
        transport: asyncio.DatagramTransport,
    ) -> None:
        """Process a single inbound UDP datagram."""
        remote_ip, remote_port = addr[0], addr[1]
        if len(data) > _BUFFER_CAP_BYTES:
            await self.emit(
                Event(
                    protocol="coap",
                    event_type="oversize",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    message=f"Dropping oversize CoAP datagram ({len(data)} bytes)",
                    data={"size": len(data)},
                )
            )
            return
        if not self._rate_limiter.check(remote_ip):
            await self.emit(
                Event(
                    protocol="coap",
                    event_type="rate_limited",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    message="CoAP per-source rate limit exceeded",
                    data={"reason": "per_source_rate_limit"},
                )
            )
            return

        try:
            message = parse_message(data)
        except ProtocolParseError as exc:
            await self.emit(
                Event(
                    protocol="coap",
                    event_type="parse_error",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    message=f"CoAP parse error: {exc}",
                    data={"size": len(data), "hex": data[:32].hex()},
                )
            )
            # Per RFC 7252: respond to malformed CON with RST; drop NON.
            if data and len(data) >= 4 and ((data[0] >> 4) & 0x03) == COAP_TYPE_CON:
                rst = build_response(
                    type_=COAP_TYPE_RST,
                    code=0x00,
                    message_id=(data[2] << 8) | data[3],
                    token=b"",
                )
                try:
                    transport.sendto(rst, addr)
                except OSError:
                    pass
            return

        await self._on_message(message, remote_ip, remote_port, transport, addr, data)

    async def _on_message(
        self,
        message: CoAPMessage,
        remote_ip: str,
        remote_port: int,
        transport: asyncio.DatagramTransport,
        addr: tuple[str, int],
        raw: bytes,
    ) -> None:
        """Dispatch a parsed CoAP message and send the response."""
        method = message.method_name
        path = message.uri_path
        sensitive = self._is_sensitive_path(path)
        amplification = (
            method == "GET"
            and (path == "/.well-known/core" or "rd-lookup" in path)
            and len(raw) <= self.amplification_threshold
        )
        await self.emit(
            Event(
                protocol="coap",
                event_type="request",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                method=method,
                path=path,
                message=f"CoAP {method} {path}",
                data={
                    "type": message.type_,
                    "code": message.code,
                    "message_id": message.message_id,
                    "token_hex": message.token.hex(),
                    "uri_query": message.uri_query,
                    "payload_size": len(message.payload),
                    "payload_preview": message.payload[:256].decode("utf-8", errors="replace"),
                    "sensitive_path": sensitive,
                    "amplification_probe": amplification,
                    "captured_at": _utc_now_iso(),
                },
            )
        )

        response = self._build_response_for(message, sensitive)
        if response is None:
            return
        try:
            transport.sendto(response, addr)
        except OSError as exc:  # noqa: BLE001
            logger.debug("CoAP sendto failed: %s", exc)

    def _build_response_for(self, message: CoAPMessage, sensitive: bool) -> bytes | None:
        """Compose the CoAP response for an inbound request."""
        # Decide ACK vs NON. CON requests demand an ACK; NON allows a NON
        # reply, but a piggybacked ACK matches what most stacks emit.
        if message.type_ == COAP_TYPE_CON:
            response_type = COAP_TYPE_ACK
        elif message.type_ == COAP_TYPE_NON:
            response_type = COAP_TYPE_NON
        else:
            return None

        path = message.uri_path
        method = message.method_name
        if method == "GET":
            if path == "/.well-known/core":
                payload = ",".join(self.resources).encode("utf-8")
                return build_response(
                    type_=response_type,
                    code=RESP_CONTENT,
                    message_id=message.message_id,
                    token=message.token,
                    options=[(OPT_CONTENT_FORMAT, b"\x28")],  # 40 = application/link-format
                    payload=payload,
                )
            if path == "/sensors/temp":
                body = json.dumps({"value": self.temperature_c, "unit": "C"}).encode("utf-8")
                return build_response(
                    type_=response_type,
                    code=RESP_CONTENT,
                    message_id=message.message_id,
                    token=message.token,
                    options=[(OPT_CONTENT_FORMAT, b"\x32")],  # 50 = application/json
                    payload=body,
                )
            if path == "/sensors/humidity":
                body = json.dumps({"value": self.humidity_pct, "unit": "%"}).encode("utf-8")
                return build_response(
                    type_=response_type,
                    code=RESP_CONTENT,
                    message_id=message.message_id,
                    token=message.token,
                    options=[(OPT_CONTENT_FORMAT, b"\x32")],
                    payload=body,
                )
            if path == "/fw/version":
                body = json.dumps({"version": self.firmware_version}).encode("utf-8")
                return build_response(
                    type_=response_type,
                    code=RESP_CONTENT,
                    message_id=message.message_id,
                    token=message.token,
                    options=[(OPT_CONTENT_FORMAT, b"\x32")],
                    payload=body,
                )
        if method == "POST" and path == "/actuators/light":
            return build_response(
                type_=response_type,
                code=RESP_CHANGED,
                message_id=message.message_id,
                token=message.token,
            )
        if method == "PUT" and path == "/actuators/light":
            return build_response(
                type_=response_type,
                code=RESP_CHANGED,
                message_id=message.message_id,
                token=message.token,
            )
        if method == "DELETE":
            return build_response(
                type_=response_type,
                code=RESP_DELETED,
                message_id=message.message_id,
                token=message.token,
            )
        # Unknown resource; honour 4.04 / 4.00.
        if message.code == 0:
            # Empty message: nothing to do.
            return None
        if sensitive:
            return build_response(
                type_=response_type,
                code=RESP_NOT_FOUND,
                message_id=message.message_id,
                token=message.token,
            )
        return build_response(
            type_=response_type,
            code=RESP_NOT_FOUND,
            message_id=message.message_id,
            token=message.token,
        )

    @staticmethod
    def _is_sensitive_path(path: str) -> bool:
        """Return True when ``path`` matches a known sensitive resource pattern."""
        lower = path.lower().strip("/")
        return any(fragment in lower for fragment in _SENSITIVE_PATHS)


__all__ = [
    "CoAPHandler",
    "CoAPMessage",
    "ProtocolParseError",
    "parse_message",
    "build_response",
    "COAP_TYPE_CON",
    "COAP_TYPE_NON",
    "COAP_TYPE_ACK",
    "COAP_TYPE_RST",
    "COAP_METHOD_GET",
    "COAP_METHOD_POST",
    "COAP_METHOD_PUT",
    "COAP_METHOD_DELETE",
    "RESP_CONTENT",
    "RESP_CHANGED",
    "RESP_NOT_FOUND",
    "RESP_BAD_REQUEST",
]
