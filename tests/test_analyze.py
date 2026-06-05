"""Tests für die reine Analyseschicht (Conversations, Follow-Stream, Expert-Info)."""
from __future__ import annotations

import socket
import struct

from netfett.core.analyze import (
    SEV_ERROR, conversations, expert_info, follow_stream, io_buckets,
    protocol_hierarchy, sequence, tcp_segment,
)
from netfett.core.dissect import dissect

LOCAL = {"192.168.0.10"}


def _ip(src: str, dst: str, proto: int, payload: bytes, ihl: int = 20) -> bytes:
    total = ihl + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x40 | (ihl // 4), 0, total, 1, 0x4000,
                      64, proto, 0)
    hdr += socket.inet_aton(src) + socket.inet_aton(dst)
    return hdr + payload


def _tcp(sport: int, dport: int, seq: int, flags: int, payload: bytes = b"") -> bytes:
    off = (5 << 4)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, off, flags,
                       64240, 0, 0) + payload


def _pkt(n, src, dst, sport, dport, seq, flags, payload=b"", ts=1000.0):
    raw = _ip(src, dst, 6, _tcp(sport, dport, seq, flags, payload))
    return dissect(raw, ts, n, LOCAL)


# --- tcp_segment ----------------------------------------------------------- #
def test_tcp_segment_extracts_seq_and_payload():
    raw = _ip("1.1.1.1", "2.2.2.2", 6, _tcp(1234, 80, 5000, 0x18, b"GET /"))
    seg = tcp_segment(raw)
    assert seg is not None
    seq, ack, flags, payload = seg
    assert seq == 5000 and flags == 0x18 and payload == b"GET /"


def test_tcp_segment_none_for_non_tcp():
    raw = _ip("1.1.1.1", "2.2.2.2", 17, b"\x00" * 8)  # UDP
    assert tcp_segment(raw) is None


# --- conversations --------------------------------------------------------- #
def test_conversations_aggregate_both_directions():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, 0, 0x02, ts=1000.0),
        _pkt(2, "1.1.1.1", "192.168.0.10", 443, 50000, 0, 0x12, ts=1001.0),
        _pkt(3, "192.168.0.10", "1.1.1.1", 50000, 443, 1, 0x18, b"hello", ts=1002.0),
    ]
    convs = conversations(pkts)
    assert len(convs) == 1
    c = convs[0]
    assert c.proto == "TCP"
    assert c.packets == 3
    assert c.a2b_pkts + c.b2a_pkts == 3
    assert c.duration == 2.0
    assert c.bytes == sum(p.length for p in pkts)


def test_conversations_separates_distinct_flows():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, 0, 0x02),
        _pkt(2, "192.168.0.10", "8.8.8.8", 50001, 80, 0, 0x02),
    ]
    assert len(conversations(pkts)) == 2


def test_conversation_sorted_by_bytes_desc():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 1, 443, 0, 0x18, b"x" * 100),
        _pkt(2, "192.168.0.10", "8.8.8.8", 2, 80, 0, 0x18, b"y" * 10),
    ]
    convs = conversations(pkts)
    assert "1.1.1.1" in (convs[0].a, convs[0].b)
    assert convs[0].bytes > convs[1].bytes


# --- follow_stream --------------------------------------------------------- #
def test_follow_stream_reassembles_in_seq_order():
    # Client schickt zwei Segmente vertauscht in der Zeit, korrekte seq-Reihenfolge.
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 80, 100, 0x02, ts=1.0),  # SYN
        _pkt(2, "192.168.0.10", "1.1.1.1", 50000, 80, 201, 0x18, b"World", ts=3.0),
        _pkt(3, "192.168.0.10", "1.1.1.1", 50000, 80, 101, 0x18, b"Hello", ts=2.0),
        _pkt(4, "1.1.1.1", "192.168.0.10", 80, 50000, 500, 0x18, b"Reply", ts=4.0),
    ]
    res = follow_stream(pkts, "192.168.0.10", 50000, "1.1.1.1", 80)
    assert res.client == ("192.168.0.10", 50000)
    assert res.client_bytes == b"HelloWorld"   # nach seq, nicht nach Zeit
    assert res.server_bytes == b"Reply"
    assert res.packets == 3  # nur Pakete mit Nutzdaten


def test_follow_stream_drops_retransmission_overlap():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 80, 100, 0x02, ts=1.0),
        _pkt(2, "192.168.0.10", "1.1.1.1", 50000, 80, 101, 0x18, b"ABCDE", ts=2.0),
        _pkt(3, "192.168.0.10", "1.1.1.1", 50000, 80, 101, 0x18, b"ABCDE", ts=3.0),  # Retrans
    ]
    res = follow_stream(pkts, "192.168.0.10", 50000, "1.1.1.1", 80)
    assert res.client_bytes == b"ABCDE"


def test_follow_stream_empty_for_unknown_tuple():
    pkts = [_pkt(1, "192.168.0.10", "1.1.1.1", 50000, 80, 1, 0x18, b"x")]
    res = follow_stream(pkts, "10.0.0.1", 1, "10.0.0.2", 2)
    assert res.client_bytes == b"" and res.packets == 0


# --- expert_info ----------------------------------------------------------- #
def test_expert_info_flags_reset():
    pkts = [_pkt(1, "1.1.1.1", "192.168.0.10", 80, 50000, 0, 0x04)]  # RST
    f = expert_info(pkts)
    assert any("Reset" in x.summary for x in f)


def test_expert_info_detects_retransmission():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 80, 101, 0x18, b"ABCDE"),
        _pkt(2, "192.168.0.10", "1.1.1.1", 50000, 80, 101, 0x18, b"ABCDE"),
    ]
    f = expert_info(pkts)
    assert any("Retransmission" in x.summary for x in f)


def test_expert_info_detects_port_scan():
    pkts = [
        _pkt(i, "10.0.0.5", "192.168.0.10", 40000, 1000 + i, 0, 0x02)
        for i in range(20)
    ]
    f = expert_info(pkts, scan_port_threshold=15)
    scan = [x for x in f if x.category == "Security" and x.severity == SEV_ERROR]
    assert scan and "Port-Scan" in scan[0].summary


def test_protocol_hierarchy_nests_by_layers():
    # TCP/TLS-Paket und UDP/DNS-Paket teilen sich die IPv4-Wurzel.
    tls = _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, 0, 0x18,
               b"\x16\x03\x01\x00")
    dns_raw = _ip("192.168.0.10", "8.8.8.8", 17,
                  struct.pack("!HHHH", 53, 53, 12, 0)
                  + b"\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x00" * 4)
    dns = dissect(dns_raw, 1000.0, 2, LOCAL)
    roots = protocol_hierarchy([tls, dns])
    assert len(roots) == 1
    ip = roots[0]
    assert ip.name.startswith("Internet Protocol")
    assert ip.packets == 2
    kids = {n.name for n in ip.child_list()}
    assert any("Transmission Control" in k for k in kids)
    assert any("User Datagram" in k for k in kids)


def test_protocol_hierarchy_empty():
    assert protocol_hierarchy([]) == []


def test_io_buckets_splits_by_direction_and_time():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, 0, 0x18, b"x" * 100, ts=1000.0),
        _pkt(2, "1.1.1.1", "192.168.0.10", 443, 50000, 0, 0x18, b"y" * 40, ts=1000.5),
        _pkt(3, "192.168.0.10", "1.1.1.1", 50000, 443, 1, 0x18, b"z" * 60, ts=1002.0),
    ]
    a2b, b2a = io_buckets(pkts, "192.168.0.10", 50000, "1.1.1.1", 443, bucket=1.0)
    assert len(a2b) == len(b2a) == 3            # 0..2 s → 3 Intervalle
    assert a2b[0] == pkts[0].length             # 100-Byte-Paket in Bucket 0
    assert b2a[0] == pkts[1].length             # 40-Byte-Antwort in Bucket 0
    assert a2b[2] == pkts[2].length             # 60-Byte-Paket in Bucket 2


def test_io_buckets_empty_for_unknown():
    assert io_buckets([], "1.1.1.1", 1, "2.2.2.2", 2) == ([], [])


def test_sequence_orders_and_assigns_client():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, 0, 0x02, ts=1.0),   # SYN
        _pkt(2, "1.1.1.1", "192.168.0.10", 443, 50000, 0, 0x12, ts=1.1),   # SYN/ACK
        _pkt(3, "192.168.0.10", "1.1.1.1", 50000, 443, 1, 0x18, b"hi", ts=1.2),
    ]
    client, server, events = sequence(pkts, "192.168.0.10", 50000, "1.1.1.1", 443)
    assert client == ("192.168.0.10", 50000)
    assert server == ("1.1.1.1", 443)
    assert [e.from_client for e in events] == [True, False, True]
    assert "SYN" in events[0].label and "len=2" in events[2].label


def test_sequence_empty_for_unknown():
    _c, _s, events = sequence([], "1.1.1.1", 1, "2.2.2.2", 2)
    assert events == []


def test_expert_info_quiet_for_normal_traffic():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, 0, 0x02),
        _pkt(2, "1.1.1.1", "192.168.0.10", 443, 50000, 0, 0x12),
        _pkt(3, "192.168.0.10", "1.1.1.1", 50000, 443, 1, 0x18, b"data"),
    ]
    assert expert_info(pkts) == []
