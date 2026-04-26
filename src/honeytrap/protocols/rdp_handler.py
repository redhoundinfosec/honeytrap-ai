"""RDP signature/handshake honeypot.

The goal is *signature collection*, not full RDP impersonation. We
parse just enough of the RDP wire protocol to identify the attacker
tooling and capture forensic artifacts:

* TPKT header (RFC 1006): version 0x03, length 16-bit BE.
* X.224 Class 0 Connection Request (CR-TPDU). RFC 905. We pull out the
  ``Cookie: mstshash=<user>`` routing token and the ``rdpNegReq``
  requested security types if present.
* Reply with a valid Class 0 Connection Confirm choosing
  ``PROTOCOL_SSL`` so the attacker continues with a TLS ClientHello,
  which we capture via ``tls_peek`` for JA3/JA4 fingerprinting.
* Optionally read the next bytes after TLS upgrade (NLA / CredSSP /
  NTLM ``NEGOTIATE_MESSAGE``) and parse the OEM workstation/domain
  fields for additional IOC value.

We then tear the connection down — full RDP impersonation is out of
scope. Future cycles can build on the captured handshake material.
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct
from typing import Any

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


_BUFFER_CAP_BYTES = 256 * 1024
_TPKT_VERSION = 0x03
_PROTOCOL_RDP = 0x00000000
_PROTOCOL_SSL = 0x00000001
_PROTOCOL_HYBRID = 0x00000002
_PROTOCOL_HYBRID_EX = 0x00000008
_NTLMSSP_SIGNATURE = b"NTLMSSP\x00"

_SCANNER_USER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^kali", re.I),
    re.compile(r"^win-[A-Z0-9]{8,}$", re.I),
    re.compile(r"^desktop-[A-Z0-9]{6,}$", re.I),
    re.compile(r"^(parrot|nmap|masscan|rdpscan)", re.I),
)


class ProtocolParseError(Exception):
    """Raised when the RDP signature parser refuses attacker input."""


def _parse_tpkt(buffer: bytes) -> tuple[int, bytes] | None:
    """Parse a single TPKT header. Returns ``(length, remainder)`` or None.

    Strict length checks prevent under-/over-read on truncated frames.
    """
    if len(buffer) < 4:
        return None
    version, _reserved, length = struct.unpack(">BBH", buffer[:4])
    if version != _TPKT_VERSION:
        raise ProtocolParseError(f"bad TPKT version: {version:#04x}")
    if length < 4 or length > _BUFFER_CAP_BYTES:
        raise ProtocolParseError(f"bad TPKT length: {length}")
    if len(buffer) < length:
        return None
    return length, buffer[4:length]


_COOKIE_RE = re.compile(rb"Cookie:\s*mstshash=([^\r\n]+)\r\n", re.I)


def _parse_x224_connection_request(payload: bytes) -> dict[str, Any]:
    """Parse an X.224 Class 0 Connection Request (CR-TPDU).

    Pulls out ``mstshash`` and the optional ``rdpNegReq`` flags. Always
    returns a dict — fields default to empty/zero when absent.
    """
    info: dict[str, Any] = {
        "mstshash": "",
        "requested_protocols": 0,
        "negreq_present": False,
    }
    if len(payload) < 7:
        raise ProtocolParseError("X.224 CR too short")
    li = payload[0]
    if li + 1 > len(payload):
        raise ProtocolParseError("X.224 LI overruns frame")
    if (payload[1] & 0xF0) != 0xE0:
        raise ProtocolParseError("not a CR-TPDU")
    body_start = li + 1
    cookie_match = _COOKIE_RE.search(payload[7:])
    if cookie_match:
        try:
            info["mstshash"] = cookie_match.group(1).decode("latin-1", "replace")[:128]
        except Exception:  # noqa: BLE001
            info["mstshash"] = ""
    if body_start < len(payload):
        rdp_neg = payload[body_start:]
        # rdpNegReq is 8 bytes: type(1) | flags(1) | length(2 LE) | requested(4 LE).
        if len(rdp_neg) >= 8 and rdp_neg[0] == 0x01:
            try:
                _, _, _, requested = struct.unpack("<BBHI", rdp_neg[:8])
                info["negreq_present"] = True
                info["requested_protocols"] = int(requested)
            except struct.error:
                pass
    return info


def _build_x224_connection_confirm(selected_protocol: int) -> bytes:
    """Build a Class 0 Connection Confirm choosing the given security type."""
    # rdpNegRsp: type 0x02, flags 0x00, length 8 LE, selected protocol 4 LE.
    neg_rsp = struct.pack("<BBHI", 0x02, 0x00, 8, selected_protocol)
    # X.224 CC-TPDU: LI | code(0xD0) | dst-ref(0) | src-ref(0) | class(0)
    x224 = bytes([0x06, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00]) + neg_rsp
    total = 4 + len(x224)
    tpkt = struct.pack(">BBH", _TPKT_VERSION, 0x00, total)
    return tpkt + x224


def _parse_ntlm_negotiate(buffer: bytes) -> dict[str, Any] | None:
    """Parse an NTLM ``NEGOTIATE_MESSAGE`` if one is present in ``buffer``.

    The message may be wrapped inside a CredSSP/SPNEGO blob; we hunt for
    the ``NTLMSSP\\x00`` magic and pull the OEM workstation/domain
    strings after that anchor. Returns None when no NTLM blob is found.
    """
    idx = buffer.find(_NTLMSSP_SIGNATURE)
    if idx < 0:
        return None
    blob = buffer[idx:]
    if len(blob) < 32:
        return None
    msg_type = struct.unpack("<I", blob[8:12])[0]
    if msg_type != 1:
        return None
    flags = struct.unpack("<I", blob[12:16])[0]
    domain_len = struct.unpack("<H", blob[16:18])[0]
    domain_off = struct.unpack("<I", blob[20:24])[0]
    workstation_len = struct.unpack("<H", blob[24:26])[0]
    workstation_off = struct.unpack("<I", blob[28:32])[0]

    def _safe_read(offset: int, length: int) -> str:
        if length <= 0 or length > 256:
            return ""
        end = offset + length
        if offset < 0 or end > len(blob):
            return ""
        return blob[offset:end].decode("latin-1", errors="replace")

    return {
        "flags": flags,
        "domain": _safe_read(domain_off, domain_len),
        "workstation": _safe_read(workstation_off, workstation_len),
    }


class RDPHandler(ProtocolHandler):
    """RDP signature-only honeypot handler."""

    name = "rdp"

    def __init__(self, service: ServiceSpec, engine: Any) -> None:
        """Initialize the RDP signature honeypot."""
        super().__init__(service, engine)
        self._server: asyncio.base_events.Server | None = None
        self.adaptive_ai_enabled: bool = bool(service.data.get("adaptive_ai_enabled", False))

    async def start(self, bind_address: str, port: int) -> None:
        """Start the RDP listener on ``bind_address:port``."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            self._server = await asyncio.start_server(self._handle, bind_address, port)
        except OSError as exc:
            raise PortBindError(f"Could not bind RDP on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop accepting new RDP connections and shut the listener down."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Gate a new RDP connection and dispatch to the signature loop."""
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
            await self._signature_dialogue(reader, writer, remote_ip, remote_port)
        finally:
            await self.engine.rate_limiter.release(remote_ip)

    async def _signature_dialogue(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        remote_ip: str,
        remote_port: int,
    ) -> None:
        """Run the bounded RDP handshake capture for a single client."""
        geo = await self.resolve_geo(remote_ip)
        session = self.engine.sessions.create(remote_ip, remote_port, "rdp", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")
        await self.emit(
            Event(
                protocol="rdp",
                event_type="connection_open",
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=self.bound_port,
                session_id=session.session_id,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                message="RDP client connected",
            )
        )

        idle_timeout = self.idle_timeout()
        try:
            cr_payload = await self._read_tpkt(reader, idle_timeout)
            if cr_payload is None:
                await self.emit(
                    Event(
                        protocol="rdp",
                        event_type="malformed",
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        session_id=session.session_id,
                        message="RDP malformed or empty preamble",
                    )
                )
                return
            try:
                cr_info = _parse_x224_connection_request(cr_payload)
            except ProtocolParseError as exc:
                await self.emit(
                    Event(
                        protocol="rdp",
                        event_type="parse_error",
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        session_id=session.session_id,
                        message=f"RDP CR parse failed: {exc}",
                    )
                )
                return
            mstshash = str(cr_info.get("mstshash", ""))
            if mstshash:
                session.record_credentials(mstshash, "")
            await self.emit(
                Event(
                    protocol="rdp",
                    event_type="x224_connect_request",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    session_id=session.session_id,
                    username=mstshash,
                    message=f"RDP CR mstshash={mstshash or '(none)'}",
                    data={
                        "mstshash": mstshash,
                        "requested_protocols": cr_info.get("requested_protocols", 0),
                        "negreq_present": cr_info.get("negreq_present", False),
                        "scanner_match": self._mstshash_is_scanner_like(mstshash),
                    },
                )
            )

            # Choose TLS so attacker continues with a ClientHello we can
            # fingerprint. Fall back to plain RDP only if HYBRID/HYBRID_EX
            # was the only option offered.
            requested = int(cr_info.get("requested_protocols") or 0)
            if requested & _PROTOCOL_SSL or not requested:
                selected = _PROTOCOL_SSL
            elif requested & _PROTOCOL_HYBRID_EX:
                selected = _PROTOCOL_HYBRID_EX
            elif requested & _PROTOCOL_HYBRID:
                selected = _PROTOCOL_HYBRID
            else:
                selected = _PROTOCOL_RDP
            writer.write(_build_x224_connection_confirm(selected))
            await writer.drain()

            await self._capture_post_cc(reader, remote_ip, remote_port, session, mstshash=mstshash)
        except Exception as exc:  # noqa: BLE001
            logger.exception("RDP handler exception for %s: %s", remote_ip, exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.emit(
                Event(
                    protocol="rdp",
                    event_type="connection_close",
                    remote_ip=remote_ip,
                    session_id=session.session_id,
                    message="RDP session closed",
                )
            )

    async def _read_tpkt(self, reader: asyncio.StreamReader, timeout: float) -> bytes | None:
        """Read one full TPKT message and return its payload."""
        header_buf = bytearray()
        try:
            while len(header_buf) < 4:
                chunk = await asyncio.wait_for(reader.read(4 - len(header_buf)), timeout=timeout)
                if not chunk:
                    return None
                header_buf.extend(chunk)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None
        try:
            version, _res, length = struct.unpack(">BBH", bytes(header_buf))
        except struct.error:
            return None
        if version != _TPKT_VERSION or length < 4 or length > _BUFFER_CAP_BYTES:
            return None
        body = bytearray()
        try:
            while len(body) < length - 4:
                chunk = await asyncio.wait_for(reader.read(length - 4 - len(body)), timeout=timeout)
                if not chunk:
                    return None
                body.extend(chunk)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None
        return bytes(body)

    async def _capture_post_cc(
        self,
        reader: asyncio.StreamReader,
        remote_ip: str,
        remote_port: int,
        session: Any,
        *,
        mstshash: str,
    ) -> None:
        """Capture either a TLS ClientHello (JA3/JA4) or a CredSSP/NTLM blob."""
        try:
            from honeytrap.intel.tls.fingerprinter import TLSFingerprinter
            from honeytrap.protocols.tls_peek import peek_tls_client_hello
        except Exception as exc:  # noqa: BLE001
            logger.debug("RDP TLS peek unavailable: %s", exc)
            return
        try:
            result = await peek_tls_client_hello(reader, TLSFingerprinter())
        except Exception as exc:  # noqa: BLE001
            logger.debug("RDP TLS peek raised: %s", exc)
            return
        fp = result.fingerprint
        tls_fingerprint = fp.to_dict() if fp is not None else {}
        await self.emit(
            Event(
                protocol="rdp",
                event_type="tls_handshake_seen",
                remote_ip=remote_ip,
                remote_port=remote_port,
                session_id=session.session_id,
                message="RDP TLS ClientHello captured",
                data={
                    "tls_fingerprint": tls_fingerprint,
                    "is_tls": result.is_tls,
                    "captured_bytes": len(result.consumed_bytes),
                    "mstshash": mstshash,
                },
            )
        )
        ntlm = _parse_ntlm_negotiate(result.consumed_bytes)
        if ntlm is not None:
            await self.emit(
                Event(
                    protocol="rdp",
                    event_type="ntlm_negotiate",
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    session_id=session.session_id,
                    username=mstshash,
                    message=(
                        f"NTLM negotiate: workstation={ntlm['workstation'] or '?'} "
                        f"domain={ntlm['domain'] or '?'}"
                    ),
                    data={
                        "ntlm_workstation": ntlm["workstation"],
                        "ntlm_domain": ntlm["domain"],
                        "ntlm_flags_hex": f"0x{ntlm['flags']:08x}",
                        "scanner_match": (
                            self._workstation_is_scanner_like(ntlm["workstation"])
                            or self._mstshash_is_scanner_like(mstshash)
                        ),
                    },
                )
            )

    @staticmethod
    def _mstshash_is_scanner_like(value: str) -> bool:
        """Return True when an mstshash cookie matches a known scanner pattern."""
        if not value:
            return False
        return any(pattern.match(value) for pattern in _SCANNER_USER_PATTERNS)

    @staticmethod
    def _workstation_is_scanner_like(value: str) -> bool:
        """Return True when a NEGOTIATE_MESSAGE workstation looks like tooling."""
        if not value:
            return False
        return any(pattern.match(value) for pattern in _SCANNER_USER_PATTERNS)


__all__ = [
    "RDPHandler",
    "ProtocolParseError",
    "_parse_tpkt",
    "_parse_x224_connection_request",
    "_parse_ntlm_negotiate",
    "_build_x224_connection_confirm",
]
