"""Tests für die IP-Fragment-Reassemblierung (IPv4 und IPv6)."""
from __future__ import annotations

import socket
import struct

from netfett.core.dissect import dissect
from netfett.core.reassemble import IPReassembler


def _v4(src, dst, ident, proto, payload, mf, frag_off_bytes):
    flags_frag = (mf << 13) | (frag_off_bytes // 8)
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, flags_frag, 64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _udp(sp, dp, data):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data


# --- IPv4 ------------------------------------------------------------------ #
def test_v4_whole_passthrough():
    raw = _v4("1.1.1.1", "2.2.2.2", 1, 17, _udp(1, 2, b"hi"), 0, 0)
    assert IPReassembler().add(raw) == ("whole", raw, 1)


def test_v4_two_fragments_reassemble():
    full_udp = _udp(53, 53, b"A" * 24)              # 32 Byte UDP gesamt
    f1 = _v4("1.1.1.1", "2.2.2.2", 7, 17, full_udp[:16], mf=1, frag_off_bytes=0)
    f2 = _v4("1.1.1.1", "2.2.2.2", 7, 17, full_udp[16:], mf=0, frag_off_bytes=16)
    r = IPReassembler()
    assert r.add(f1)[0] == "incomplete"
    state, data, count = r.add(f2)
    assert state == "reassembled" and count == 2
    # Reassembliertes Datagramm korrekt zerlegbar?
    pkt = dissect(data, 1.0, 1, set())
    assert pkt.l4 == "UDP" and pkt.src_port == 53 and pkt.length == 20 + len(full_udp)


def test_v4_out_of_order():
    payload = _udp(1, 2, b"B" * 24)
    f1 = _v4("1.1.1.1", "2.2.2.2", 9, 17, payload[:16], mf=1, frag_off_bytes=0)
    f2 = _v4("1.1.1.1", "2.2.2.2", 9, 17, payload[16:], mf=0, frag_off_bytes=16)
    r = IPReassembler()
    assert r.add(f2)[0] == "incomplete"             # letztes zuerst
    assert r.add(f1)[0] == "reassembled"


def test_v4_gap_stays_incomplete():
    payload = _udp(1, 2, b"C" * 40)
    f1 = _v4("1.1.1.1", "2.2.2.2", 11, 17, payload[:8], mf=1, frag_off_bytes=0)
    f3 = _v4("1.1.1.1", "2.2.2.2", 11, 17, payload[24:], mf=0, frag_off_bytes=24)
    r = IPReassembler()
    assert r.add(f1)[0] == "incomplete"
    assert r.add(f3)[0] == "incomplete"             # Mittelstück fehlt


def test_v4_separate_datagrams_independent():
    p = _udp(1, 2, b"D" * 16)
    a1 = _v4("1.1.1.1", "2.2.2.2", 1, 17, p[:8], 1, 0)
    b1 = _v4("1.1.1.1", "2.2.2.2", 2, 17, p[:8], 1, 0)   # andere ID
    r = IPReassembler()
    r.add(a1); r.add(b1)
    assert len(r._buf) == 2


# --- IPv6 ------------------------------------------------------------------ #
def _v6_frag(src, dst, ident, nexthdr, payload, mf, off_bytes):
    main = struct.pack("!IHBB", 6 << 28, 8 + len(payload), 44, 64)
    main += socket.inet_pton(socket.AF_INET6, src)
    main += socket.inet_pton(socket.AF_INET6, dst)
    off_flags = (off_bytes & 0xFFF8) | (mf & 1)
    frag_hdr = struct.pack("!BBHI", nexthdr, 0, off_flags, ident)
    return main + frag_hdr + payload


def test_v6_two_fragments_reassemble():
    full_udp = _udp(53, 53, b"E" * 24)
    f1 = _v6_frag("2001:db8::1", "2001:db8::2", 0x1234, 17, full_udp[:16],
                  mf=1, off_bytes=0)
    f2 = _v6_frag("2001:db8::1", "2001:db8::2", 0x1234, 17, full_udp[16:],
                  mf=0, off_bytes=16)
    r = IPReassembler()
    assert r.add(f1)[0] == "incomplete"
    state, data, count = r.add(f2)
    assert state == "reassembled" and count == 2
    pkt = dissect(data, 1.0, 1, set())
    assert pkt.l4 == "UDP" and pkt.src_port == 53
