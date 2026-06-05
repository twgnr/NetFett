"""Tests für die IPv6-Paketzerlegung."""
from __future__ import annotations

import socket
import struct

from netfett.core.dissect import dissect

V6_SRC = "2001:db8::10"
V6_DST = "2001:db8::1"


def _ipv6(src: str, dst: str, nexthdr: int, payload: bytes, hop: int = 64) -> bytes:
    vtf = 6 << 28                       # Version 6, TC=0, Flow=0
    hdr = struct.pack("!IHBB", vtf, len(payload), nexthdr, hop)
    hdr += socket.inet_pton(socket.AF_INET6, src)
    hdr += socket.inet_pton(socket.AF_INET6, dst)
    return hdr + payload


def _tcp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18,
                       64240, 0, 0) + payload


def test_ipv6_tcp_basic():
    raw = _ipv6(V6_SRC, V6_DST, 6, _tcp(50000, 443))
    pkt = dissect(raw, 1.0, 1, {V6_SRC})
    assert pkt.src == V6_SRC and pkt.dst == V6_DST
    assert pkt.l4 == "TCP" and pkt.protocol == "TCP"
    assert pkt.src_port == 50000 and pkt.dst_port == 443
    assert pkt.direction == "out"               # Quelle ist „lokal"
    assert pkt.layers[0].name == "Internet Protocol Version 6"


def test_ipv6_tcp_tls_sni():
    # IPv6 + TCP + TLS-ClientHello-Beginn → App-Erkennung greift wie bei IPv4.
    raw = _ipv6(V6_SRC, V6_DST, 6, _tcp(50000, 443, b"\x16\x03\x01\x00"))
    pkt = dissect(raw, 1.0, 1, set())
    assert pkt.protocol == "TLS"


def test_ipv6_udp_ports():
    udp = struct.pack("!HHHH", 5353, 5353, 8, 0)
    raw = _ipv6(V6_SRC, V6_DST, 17, udp)
    pkt = dissect(raw, 1.0, 1, set())
    assert pkt.l4 == "UDP" and pkt.src_port == 5353


def test_ipv6_icmpv6_echo():
    icmp = struct.pack("!BBH", 128, 0, 0) + struct.pack("!HH", 0xAB, 7)
    raw = _ipv6(V6_SRC, V6_DST, 58, icmp)
    pkt = dissect(raw, 1.0, 1, set())
    assert pkt.protocol == "ICMPv6"
    assert "Echo Request" in pkt.info and "seq=7" in pkt.info


def test_ipv6_skips_extension_header():
    # Hop-by-Hop-Header (next=6 TCP, hdr_ext_len=0 → 8 Bytes) vor dem TCP.
    tcp = _tcp(1234, 80)
    hop_by_hop = struct.pack("!BB", 6, 0) + b"\x00" * 6   # 8 Byte
    raw = _ipv6(V6_SRC, V6_DST, 0, hop_by_hop + tcp)       # next=0 (Hop-by-Hop)
    pkt = dissect(raw, 1.0, 1, set())
    assert pkt.l4 == "TCP" and pkt.dst_port == 80


def test_ipv6_truncated():
    # ≥20 Byte (sonst greift der generische Kurz-Guard), aber <40 (kein v6-Kopf).
    pkt = dissect(b"\x60" + b"\x00" * 29, 1.0, 1, set())
    assert pkt.protocol == "IPv6"
