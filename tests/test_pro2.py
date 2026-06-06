"""Tests: pcapng-Lesen/Merge/Rotation, HTTP-Objekte, TCP-Trace, Decode-As."""
from __future__ import annotations

import os
import socket
import struct
import tempfile

from netfett.core.analyze import tcp_trace
from netfett.core.dissect import dissect, get_decode_as, set_decode_as
from netfett.core.extract import http_objects, suggest_filename
from netfett.core.models import DIR_OUT, Packet
from netfett.core.pcap import (
    RotatingPcapWriter, merge_captures, read_capture, read_pcapng, write_pcap,
    write_pcapng,
)

LOCAL = {"192.168.0.10"}


def _mk(length, ts, b0=0x45):
    raw = bytes([b0]) + bytes([int(ts) % 251]) * (length - 1)
    return Packet(number=1, ts=ts, raw=raw, direction=DIR_OUT, length=length)


def _ip(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000,
                      64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _tcp(sp, dp, seq, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, 0, 0x50, flags, 64240, 0, 0) + payload


# --- pcapng lesen / Merge -------------------------------------------------- #
def test_pcapng_read_roundtrip():
    pkts = [_mk(40, 1.5), _mk(71, 2.5)]
    path = os.path.join(tempfile.mkdtemp(), "c.pcapng")
    write_pcapng(path, pkts)
    out = read_pcapng(path)
    assert [r[1] for r in out] == [p.raw for p in pkts]
    assert abs(out[0][0] - 1.5) < 1e-6


def test_read_capture_autodetect():
    d = tempfile.mkdtemp()
    p_ng = os.path.join(d, "a.pcapng"); write_pcapng(p_ng, [_mk(40, 1.0)])
    p_pcap = os.path.join(d, "b.pcap"); write_pcap(p_pcap, [_mk(40, 1.0)])
    assert len(read_capture(p_ng)) == 1
    assert len(read_capture(p_pcap)) == 1


def test_merge_captures_sorted():
    d = tempfile.mkdtemp()
    p1 = os.path.join(d, "1.pcap"); write_pcap(p1, [_mk(40, 5.0)])
    p2 = os.path.join(d, "2.pcap"); write_pcap(p2, [_mk(40, 1.0), _mk(40, 9.0)])
    merged = merge_captures([p1, p2])
    assert [r[0] for r in merged] == [1.0, 5.0, 9.0]


# --- Rotation -------------------------------------------------------------- #
def test_rotating_writer_creates_and_limits_files():
    d = tempfile.mkdtemp()
    w = RotatingPcapWriter(os.path.join(d, "live.pcap"),
                           max_bytes=1024, keep=2)
    for i in range(200):
        w.write_packet(_mk(100, float(i)))
    w.close()
    assert w.count == 200
    files = [f for f in os.listdir(d) if f.endswith(".pcap")]
    assert len(files) <= 2                            # alte Dateien gelöscht


# --- HTTP-Objekte ---------------------------------------------------------- #
def test_http_objects_content_length_and_chunked():
    client = (b"GET /a.html HTTP/1.1\r\nHost: x\r\n\r\n"
              b"GET /b.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    server = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
              b"Content-Length: 5\r\n\r\nHELLO"
              b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
              b"Transfer-Encoding: chunked\r\n\r\n4\r\nABCD\r\n0\r\n\r\n")
    objs = http_objects(client, server)
    assert len(objs) == 2
    assert objs[0].content_type == "text/html" and objs[0].data == b"HELLO"
    assert objs[0].url == "/a.html"
    assert objs[1].data == b"ABCD"
    assert suggest_filename(objs[0]) == "a.html"


# --- TCP-Trace ------------------------------------------------------------- #
def test_tcp_trace_relative_seq():
    pkts = [
        dissect(_ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, 1000, 0x02)),
                1.0, 1, LOCAL),
        dissect(_ip("192.168.0.10", "1.1.1.1", 6,
                    _tcp(50000, 443, 1001, 0x18, b"hello")), 1.5, 2, LOCAL),
    ]
    samples = tcp_trace(pkts, "192.168.0.10", 50000, "1.1.1.1", 443)
    assert len(samples) == 2
    assert samples[0].seq == 0 and samples[1].seq == 1     # relativ zur Start-Seq
    assert samples[1].length == 5
    assert abs(samples[1].t - 0.5) < 1e-6


# --- Decode-As ------------------------------------------------------------- #
def test_decode_as_forces_http():
    set_decode_as({8081: "http"})
    try:
        raw = _ip("192.168.0.10", "1.1.1.1", 6,
                  _tcp(50000, 8081, 1, 0x18, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        pkt = dissect(raw, 1.0, 1, LOCAL)
        assert pkt.protocol == "HTTP"
        assert get_decode_as() == {8081: "http"}
    finally:
        set_decode_as({})
