"""Tests der Paketzerlegung (rein, ohne Netzwerk)."""
from __future__ import annotations

import socket
import struct

from netfett.core import dissect
from netfett.core.models import DIR_IN, DIR_OUT, DIR_UNKNOWN

LOCAL = "192.168.0.10"


def ipv4(proto: int, payload: bytes, src=LOCAL, dst="1.1.1.1") -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000, 64,
                      proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def tcp(sport, dport, flags=0x02, payload=b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, flags,
                       8192, 0, 0) + payload


def udp(sport, dport, payload=b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name="example.com", qtype=1) -> bytes:
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    q += struct.pack("!HH", qtype, 1)
    header = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    return header + q


def test_ipv4_tcp_syn_direction_out():
    raw = ipv4(6, tcp(50000, 443, flags=0x02))
    pkt = dissect.dissect(raw, 1.0, 1, local_ips={LOCAL})
    assert pkt.src == LOCAL and pkt.dst == "1.1.1.1"
    assert pkt.l4 == "TCP"
    assert pkt.src_port == 50000 and pkt.dst_port == 443
    assert pkt.direction == DIR_OUT
    assert "SYN" in pkt.info
    # Schichten: IPv4 + TCP (+ evtl. TLS); mindestens 2
    names = [l.name for l in pkt.layers]
    assert any("Internet Protocol" in n for n in names)
    assert any("Transmission Control" in n for n in names)


def test_direction_in_and_unknown():
    raw_in = ipv4(6, tcp(443, 50000), src="1.1.1.1", dst=LOCAL)
    assert dissect.dissect(raw_in, 1.0, 1, {LOCAL}).direction == DIR_IN
    raw_other = ipv4(6, tcp(1, 2), src="8.8.8.8", dst="9.9.9.9")
    assert dissect.dissect(raw_other, 1.0, 1, {LOCAL}).direction == DIR_UNKNOWN


def test_tcp_flags_parsed():
    raw = ipv4(6, tcp(1, 2, flags=0x12))  # SYN+ACK
    pkt = dissect.dissect(raw, 1.0, 1, {LOCAL})
    assert "SYN" in pkt.info and "ACK" in pkt.info


def test_udp_dns_query():
    raw = ipv4(17, udp(50000, 53, dns_query("example.com")))
    pkt = dissect.dissect(raw, 1.0, 1, {LOCAL})
    assert pkt.protocol == "DNS"
    assert "example.com" in pkt.info
    assert "A" in pkt.info  # Query-Typ A


def test_tls_detection():
    # TLS-Record: Handshake (0x16), Version 0x0301, dummy length+body
    tls = b"\x16\x03\x01\x00\x05hello"
    raw = ipv4(6, tcp(50000, 443, flags=0x18, payload=tls))
    pkt = dissect.dissect(raw, 1.0, 1, {LOCAL})
    assert pkt.protocol == "TLS"
    assert "Handshake" in pkt.info


def test_icmp_echo():
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1)
    raw = ipv4(1, icmp)
    pkt = dissect.dissect(raw, 1.0, 1, {LOCAL})
    assert pkt.protocol == "ICMP"
    assert "Echo" in pkt.info and "seq=1" in pkt.info


def test_truncated_packet():
    pkt = dissect.dissect(b"\x45\x00\x00", 1.0, 1, {LOCAL})
    assert pkt.protocol == "?"
    assert "Verkürzt" in pkt.info
