"""PCAP-lite writer/reader coverage."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from honeytrap.forensics.pcap import (
    DEFAULT_MSS,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    PCAP_MAGIC,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_SYN,
    SessionFlow,
    read_pcap,
    write_pcap,
)
from honeytrap.forensics.recorder import (
    Direction,
    SessionFrame,
    SessionMetadata,
)


def _make_flow(
    *,
    remote_ip: str = "1.2.3.4",
    local_ip: str = "10.0.0.1",
    payloads: list[tuple[Direction, bytes]] | None = None,
) -> SessionFlow:
    meta = SessionMetadata(
        session_id="t1",
        protocol="ssh",
        remote_ip=remote_ip,
        remote_port=2222,
        local_ip=local_ip,
        local_port=22,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    frames: list[SessionFrame] = []
    ts = 1_700_000_000_000_000_000
    for i, (direction, payload) in enumerate(payloads or [(Direction.INBOUND, b"hi")]):
        attacker = direction is Direction.INBOUND
        frames.append(
            SessionFrame(
                session_id="t1",
                timestamp_ns=ts + i * 1_000_000,
                direction=direction,
                payload=payload,
                source_ip=remote_ip if attacker else local_ip,
                source_port=2222 if attacker else 22,
                dest_ip=local_ip if attacker else remote_ip,
                dest_port=22 if attacker else 2222,
                protocol="ssh",
            )
        )
    return SessionFlow(metadata=meta, frames=frames)


def test_pcap_header_magic_and_linktype(tmp_path: Path) -> None:
    out = tmp_path / "x.pcap"
    write_pcap(out, [_make_flow()])
    header, packets = read_pcap(out)
    assert header["magic"] == PCAP_MAGIC
    assert header["linktype"] == 1  # Ethernet
    assert packets


def test_handshake_ordering_syn_synack_ack(tmp_path: Path) -> None:
    out = tmp_path / "h.pcap"
    write_pcap(out, [_make_flow(payloads=[(Direction.INBOUND, b"x")])])
    _, packets = read_pcap(out)
    flags = [p.tcp_flags() for p in packets[:3]]
    assert flags[0] & TCP_SYN
    assert (flags[1] & TCP_SYN) and (flags[1] & TCP_ACK)
    assert flags[2] & TCP_ACK


def test_payload_round_trips_through_segments(tmp_path: Path) -> None:
    payload = b"banner\r\nuser admin\r\n"
    out = tmp_path / "p.pcap"
    write_pcap(out, [_make_flow(payloads=[(Direction.INBOUND, payload)])])
    _, packets = read_pcap(out)
    rebuilt = b"".join(p.tcp_payload() for p in packets if p.tcp_payload())
    assert payload in rebuilt


def test_mss_segmentation_splits_large_payloads(tmp_path: Path) -> None:
    payload = b"a" * (DEFAULT_MSS * 2 + 50)
    out = tmp_path / "m.pcap"
    write_pcap(out, [_make_flow(payloads=[(Direction.INBOUND, payload)])])
    _, packets = read_pcap(out)
    data_packets = [p for p in packets if p.tcp_payload()]
    assert len(data_packets) >= 3


def test_fin_ack_teardown_present(tmp_path: Path) -> None:
    out = tmp_path / "f.pcap"
    write_pcap(out, [_make_flow()])
    _, packets = read_pcap(out)
    fin_packets = [p for p in packets if p.tcp_flags() & TCP_FIN]
    assert len(fin_packets) >= 2  # client + server FIN


def test_ipv6_writer_uses_ethertype(tmp_path: Path) -> None:
    out = tmp_path / "v6.pcap"
    write_pcap(
        out,
        [_make_flow(remote_ip="2001:db8::1", local_ip="2001:db8::2")],
    )
    _, packets = read_pcap(out)
    assert any(p.ethertype == ETHERTYPE_IPV6 for p in packets)


def test_ipv4_writer_uses_ethertype(tmp_path: Path) -> None:
    out = tmp_path / "v4.pcap"
    write_pcap(out, [_make_flow()])
    _, packets = read_pcap(out)
    assert all(p.ethertype == ETHERTYPE_IPV4 for p in packets)


def test_writer_handles_zero_frames(tmp_path: Path) -> None:
    flow = _make_flow(payloads=[])
    out = tmp_path / "empty.pcap"
    write_pcap(out, [flow])
    _, packets = read_pcap(out)
    # Still have handshake + teardown packets
    assert len(packets) >= 6


def test_psh_flag_on_data_frames(tmp_path: Path) -> None:
    out = tmp_path / "psh.pcap"
    write_pcap(out, [_make_flow(payloads=[(Direction.INBOUND, b"abc")])])
    _, packets = read_pcap(out)
    assert any((p.tcp_flags() & TCP_PSH) for p in packets if p.tcp_payload())
