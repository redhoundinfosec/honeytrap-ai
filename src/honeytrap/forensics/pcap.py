"""libpcap-format writer with synthesized TCP/IP framing.

PCAP-lite renders recorded :class:`~honeytrap.forensics.recorder.SessionFrame`
streams as a libpcap capture that opens cleanly in Wireshark or
``tshark``. Because the frames originally arrived as application-layer
payloads, the writer *synthesizes* the TCP three-way handshake at the
session start, segments inbound/outbound payloads into MSS-sized chunks
with monotonic sequence numbers, and emits a FIN/ACK teardown at the
end. The capture is a faithful reconstruction of the conversation, not
a packet-for-packet trace -- this is the right trade-off for analysis
tooling but should be flagged in any analyst-facing UI.

Format references:
* https://wiki.wireshark.org/Development/LibpcapFileFormat
* RFC 791  (IPv4)
* RFC 793  (TCP)
* RFC 8200 (IPv6)
"""

from __future__ import annotations

import logging
import socket
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from honeytrap.forensics.recorder import Direction, SessionFrame, SessionMetadata

logger = logging.getLogger(__name__)


# Constants from the libpcap on-disk format
PCAP_MAGIC: int = 0xA1B2C3D4
PCAP_VERSION_MAJOR: int = 2
PCAP_VERSION_MINOR: int = 4
PCAP_LINKTYPE_ETHERNET: int = 1
PCAP_DEFAULT_SNAPLEN: int = 65535

# Ethernet
ETHERTYPE_IPV4: int = 0x0800
ETHERTYPE_IPV6: int = 0x86DD
ATTACKER_MAC: bytes = b"\x02\x00\x00\x00\x00\x01"  # locally-administered, attacker
HONEYPOT_MAC: bytes = b"\x02\x00\x00\x00\x00\x02"  # locally-administered, honeypot

# TCP flags
TCP_FIN: int = 0x01
TCP_SYN: int = 0x02
TCP_RST: int = 0x04
TCP_PSH: int = 0x08
TCP_ACK: int = 0x10

DEFAULT_MSS: int = 1460


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SessionFlow:
    """A single session's metadata + frames as fed to the PCAP writer."""

    metadata: SessionMetadata
    frames: list[SessionFrame] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


class PcapWriter:
    """Streams synthesized TCP packets for one or more sessions to a file."""

    def __init__(
        self,
        sink: BinaryIO,
        *,
        snaplen: int = PCAP_DEFAULT_SNAPLEN,
        mss: int = DEFAULT_MSS,
    ) -> None:
        """Initialize the writer with a binary sink (typically a file)."""
        self.sink = sink
        self.snaplen = int(snaplen)
        self.mss = int(mss)
        self._wrote_header = False

    def write_header(self) -> None:
        """Emit the libpcap global file header."""
        if self._wrote_header:
            return
        header = struct.pack(
            "<IHHiIII",
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,
            0,
            self.snaplen,
            PCAP_LINKTYPE_ETHERNET,
        )
        self.sink.write(header)
        self._wrote_header = True

    def write_session(self, flow: SessionFlow) -> int:
        """Render one session as a SYN/SYN-ACK/ACK + payload + FIN/ACK exchange.

        Returns the number of packet records written.
        """
        self.write_header()
        return _emit_flow(self.sink, flow, mss=self.mss)

    def write_sessions(self, flows: Iterable[SessionFlow]) -> int:
        """Write several sessions back-to-back."""
        self.write_header()
        total = 0
        for flow in flows:
            total += _emit_flow(self.sink, flow, mss=self.mss)
        return total


def write_pcap(
    path: str | Path,
    flows: Sequence[SessionFlow],
    *,
    mss: int = DEFAULT_MSS,
) -> Path:
    """Convenience helper: open ``path`` and write every flow into it."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as fh:
        writer = PcapWriter(fh, mss=mss)
        writer.write_sessions(flows)
    return out


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------


def _emit_flow(sink: BinaryIO, flow: SessionFlow, *, mss: int) -> int:
    """Render the full TCP exchange for a single session to ``sink``."""
    meta = flow.metadata
    frames = sorted(flow.frames, key=lambda f: f.timestamp_ns)

    family, _ = _classify_address(meta.remote_ip, meta.local_ip, frames)

    client_ip = meta.remote_ip or _peer_ip(frames, Direction.INBOUND, "src") or "0.0.0.0"
    server_ip = meta.local_ip or _peer_ip(frames, Direction.INBOUND, "dst") or "0.0.0.0"
    client_port = meta.remote_port or _peer_port(frames, Direction.INBOUND, "src")
    server_port = meta.local_port or _peer_port(frames, Direction.INBOUND, "dst")

    if not client_ip or not server_ip:
        return 0

    # Establish a chronological reference for the synthesized handshake.
    if frames:
        start_ns = frames[0].timestamp_ns - 1_000_000  # 1 ms before first payload
        end_ns = frames[-1].timestamp_ns + 1_000_000
    else:
        start_ns = int(meta.started_at.timestamp() * 1_000_000_000)
        end_ns = start_ns + 2_000_000

    client_seq = 1_000
    server_seq = 2_000

    written = 0

    # Three-way handshake: SYN, SYN-ACK, ACK
    written += _emit_packet(
        sink,
        family=family,
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        seq=client_seq,
        ack=0,
        flags=TCP_SYN,
        payload=b"",
        timestamp_ns=start_ns,
        from_attacker=True,
    )
    client_seq += 1

    written += _emit_packet(
        sink,
        family=family,
        src_ip=server_ip,
        dst_ip=client_ip,
        src_port=server_port,
        dst_port=client_port,
        seq=server_seq,
        ack=client_seq,
        flags=TCP_SYN | TCP_ACK,
        payload=b"",
        timestamp_ns=start_ns + 100_000,
        from_attacker=False,
    )
    server_seq += 1

    written += _emit_packet(
        sink,
        family=family,
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        seq=client_seq,
        ack=server_seq,
        flags=TCP_ACK,
        payload=b"",
        timestamp_ns=start_ns + 200_000,
        from_attacker=True,
    )

    # Data exchange
    for frame in frames:
        attacker = frame.direction is Direction.INBOUND
        seg_seq = client_seq if attacker else server_seq
        for offset in range(0, max(len(frame.payload), 1), max(mss, 1)):
            chunk = frame.payload[offset : offset + mss]
            if not chunk and offset > 0:
                break
            seq_to_send = seg_seq + offset
            ack_to_send = server_seq if attacker else client_seq
            written += _emit_packet(
                sink,
                family=family,
                src_ip=client_ip if attacker else server_ip,
                dst_ip=server_ip if attacker else client_ip,
                src_port=client_port if attacker else server_port,
                dst_port=server_port if attacker else client_port,
                seq=seq_to_send,
                ack=ack_to_send,
                flags=TCP_ACK | TCP_PSH,
                payload=chunk,
                timestamp_ns=frame.timestamp_ns + offset,
                from_attacker=attacker,
            )
        if attacker:
            client_seq += max(len(frame.payload), 0)
        else:
            server_seq += max(len(frame.payload), 0)

    # Teardown: FIN/ACK from each side
    written += _emit_packet(
        sink,
        family=family,
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        seq=client_seq,
        ack=server_seq,
        flags=TCP_FIN | TCP_ACK,
        payload=b"",
        timestamp_ns=end_ns,
        from_attacker=True,
    )
    client_seq += 1
    written += _emit_packet(
        sink,
        family=family,
        src_ip=server_ip,
        dst_ip=client_ip,
        src_port=server_port,
        dst_port=client_port,
        seq=server_seq,
        ack=client_seq,
        flags=TCP_FIN | TCP_ACK,
        payload=b"",
        timestamp_ns=end_ns + 100_000,
        from_attacker=False,
    )
    server_seq += 1
    written += _emit_packet(
        sink,
        family=family,
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        seq=client_seq,
        ack=server_seq,
        flags=TCP_ACK,
        payload=b"",
        timestamp_ns=end_ns + 200_000,
        from_attacker=True,
    )

    return written


def _emit_packet(
    sink: BinaryIO,
    *,
    family: int,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    timestamp_ns: int,
    from_attacker: bool,
) -> int:
    """Build and emit a single Ethernet+IP+TCP record. Returns ``1`` on success."""
    src_mac = ATTACKER_MAC if from_attacker else HONEYPOT_MAC
    dst_mac = HONEYPOT_MAC if from_attacker else ATTACKER_MAC

    if family == socket.AF_INET6:
        ethertype = ETHERTYPE_IPV6
        ip_header, tcp_segment = _build_ipv6_tcp(
            src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload
        )
    else:
        ethertype = ETHERTYPE_IPV4
        ip_header, tcp_segment = _build_ipv4_tcp(
            src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload
        )

    ethernet = dst_mac + src_mac + struct.pack("!H", ethertype)
    packet = ethernet + ip_header + tcp_segment

    seconds, micros = divmod(int(timestamp_ns), 1_000_000_000)
    record = struct.pack(
        "<IIII",
        seconds,
        micros // 1000,
        len(packet),
        len(packet),
    )
    sink.write(record + packet)
    return 1


def _build_ipv4_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
) -> tuple[bytes, bytes]:
    """Return ``(ip_header, tcp_segment_with_payload)`` for IPv4."""
    src = socket.inet_pton(socket.AF_INET, _normalize_ip(src_ip, socket.AF_INET))
    dst = socket.inet_pton(socket.AF_INET, _normalize_ip(dst_ip, socket.AF_INET))
    tcp_header_length = 20
    total_length = 20 + tcp_header_length + len(payload)
    # Version 4, IHL 5 (20 bytes), DSCP 0, ECN 0
    version_ihl = (4 << 4) | 5
    ttl = 64
    proto = socket.IPPROTO_TCP
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,  # ToS
        total_length,
        0,  # ID
        0,  # Flags + fragment
        ttl,
        proto,
        0,  # checksum placeholder
        src,
        dst,
    )
    ip_checksum = _checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]

    tcp_segment = _build_tcp_segment(
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        payload,
        pseudo_header=struct.pack(
            "!4s4sBBH",
            src,
            dst,
            0,
            socket.IPPROTO_TCP,
            tcp_header_length + len(payload),
        ),
    )
    return ip_header, tcp_segment


def _build_ipv6_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
) -> tuple[bytes, bytes]:
    """Return ``(ip_header, tcp_segment_with_payload)`` for IPv6."""
    src = socket.inet_pton(socket.AF_INET6, _normalize_ip(src_ip, socket.AF_INET6))
    dst = socket.inet_pton(socket.AF_INET6, _normalize_ip(dst_ip, socket.AF_INET6))
    tcp_header_length = 20
    payload_length = tcp_header_length + len(payload)
    # Version 6, traffic class 0, flow label 0
    ip_header = struct.pack(
        "!IHBB16s16s",
        (6 << 28),
        payload_length,
        socket.IPPROTO_TCP,  # next header
        64,  # hop limit
        src,
        dst,
    )
    pseudo = (
        src
        + dst
        + struct.pack("!I", payload_length)
        + b"\x00\x00\x00"
        + struct.pack("!B", socket.IPPROTO_TCP)
    )
    tcp_segment = _build_tcp_segment(
        src_port, dst_port, seq, ack, flags, payload, pseudo_header=pseudo
    )
    return ip_header, tcp_segment


def _build_tcp_segment(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    *,
    pseudo_header: bytes,
) -> bytes:
    """Assemble a TCP header + payload with a correct checksum."""
    data_offset = 5 << 4  # 20-byte header, no options
    window = 65535
    segment = struct.pack(
        "!HHIIBBHHH",
        int(src_port) & 0xFFFF,
        int(dst_port) & 0xFFFF,
        int(seq) & 0xFFFFFFFF,
        int(ack) & 0xFFFFFFFF,
        data_offset,
        flags & 0xFF,
        window,
        0,  # checksum placeholder
        0,  # urgent
    )
    checksum = _checksum(pseudo_header + segment + payload)
    segment = segment[:16] + struct.pack("!H", checksum) + segment[18:]
    return segment + payload


def _checksum(data: bytes) -> int:
    """16-bit one's complement checksum used by IP/TCP/UDP."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _classify_address(
    remote_ip: str,
    local_ip: str,
    frames: Sequence[SessionFrame],
) -> tuple[int, int]:
    """Return ``(socket family, ethertype)`` for the addresses in play."""
    candidates = [remote_ip, local_ip]
    candidates.extend(f.source_ip for f in frames)
    candidates.extend(f.dest_ip for f in frames)
    for ip in candidates:
        if ip and ":" in ip:
            return socket.AF_INET6, ETHERTYPE_IPV6
    return socket.AF_INET, ETHERTYPE_IPV4


def _peer_ip(frames: Sequence[SessionFrame], direction: Direction, side: str) -> str:
    """Look up the first matching ip for a given direction/side."""
    for frame in frames:
        if frame.direction is direction:
            return frame.source_ip if side == "src" else frame.dest_ip
    return ""


def _peer_port(frames: Sequence[SessionFrame], direction: Direction, side: str) -> int:
    """Look up the first matching port for a given direction/side."""
    for frame in frames:
        if frame.direction is direction:
            return frame.source_port if side == "src" else frame.dest_port
    return 0


def _normalize_ip(ip: str, family: int) -> str:
    """Coerce blank or wrong-family addresses to a sane default."""
    if family == socket.AF_INET6:
        if not ip or ":" not in ip:
            return "::"
        return ip
    if not ip or ":" in ip:
        return "0.0.0.0"
    return ip


# ---------------------------------------------------------------------------
# Lightweight reader used by tests + CLI parity checks
# ---------------------------------------------------------------------------


@dataclass
class PcapPacket:
    """A single record returned by :func:`read_pcap`."""

    timestamp_seconds: int
    timestamp_micros: int
    raw: bytes

    @property
    def ethertype(self) -> int:
        """Best-effort ethertype lookup (Ethernet II framing only)."""
        if len(self.raw) < 14:
            return 0
        return int.from_bytes(self.raw[12:14], "big")

    def ip_payload(self) -> bytes:
        """Return the IP payload (TCP segment for our writer)."""
        if self.ethertype == ETHERTYPE_IPV4:
            ihl = (self.raw[14] & 0x0F) * 4
            return self.raw[14 + ihl :]
        if self.ethertype == ETHERTYPE_IPV6:
            return self.raw[14 + 40 :]
        return b""

    def tcp_payload(self) -> bytes:
        """Return the bytes carried inside the TCP segment, if any."""
        ip_payload = self.ip_payload()
        if len(ip_payload) < 20:
            return b""
        data_offset = (ip_payload[12] >> 4) * 4
        return ip_payload[data_offset:]

    def tcp_flags(self) -> int:
        """Return the raw TCP flag byte, or ``0`` if the packet is too short."""
        ip_payload = self.ip_payload()
        if len(ip_payload) < 14:
            return 0
        return ip_payload[13]


def read_pcap(path: str | Path) -> tuple[dict[str, int], list[PcapPacket]]:
    """Parse a pcap file written by :class:`PcapWriter`. Returns ``(header, packets)``."""
    p = Path(path)
    raw = p.read_bytes()
    if len(raw) < 24:
        raise ValueError("pcap file too short for global header")
    magic, vmaj, vmin, _zone, _sigfigs, snaplen, linktype = struct.unpack("<IHHiIII", raw[:24])
    if magic != PCAP_MAGIC:
        raise ValueError(f"bad pcap magic: 0x{magic:08x}")
    cursor = 24
    packets: list[PcapPacket] = []
    while cursor + 16 <= len(raw):
        ts_sec, ts_usec, incl, _orig = struct.unpack("<IIII", raw[cursor : cursor + 16])
        cursor += 16
        if cursor + incl > len(raw):
            break
        packets.append(PcapPacket(ts_sec, ts_usec, raw[cursor : cursor + incl]))
        cursor += incl
    return (
        {
            "magic": magic,
            "version_major": vmaj,
            "version_minor": vmin,
            "snaplen": snaplen,
            "linktype": linktype,
        },
        packets,
    )
