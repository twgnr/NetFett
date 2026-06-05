"""Tests für TCP-Gesundheit (RTT/Retrans/Dup-ACK/Zero-Window) und Sicherheit."""
from __future__ import annotations

import base64
import socket
import struct

from netfett.core.analyze import beaconing, credentials, tcp_health
from netfett.core.dissect import dissect

LOCAL = {"192.168.0.10"}


def _ip(src: str, dst: str, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000,
                      64, 6, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _tcp(sp, dp, seq, ack, flags, window=64240, payload=b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 0x50, flags,
                       window, 0, 0) + payload


def _pkt(n, src, dst, sp, dp, seq=0, ack=0, flags=0x10, window=64240,
         payload=b"", ts=1.0):
    return dissect(_ip(src, dst, _tcp(sp, dp, seq, ack, flags, window, payload)),
                   ts, n, LOCAL)


# --- RTT ------------------------------------------------------------------- #
def test_health_handshake_rtt():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, flags=0x02, ts=1.00),
        _pkt(2, "1.1.1.1", "192.168.0.10", 443, 50000, flags=0x12, ts=1.05),
    ]
    h = tcp_health(pkts)
    assert len(h) == 1
    assert h[0].rtt_ms is not None
    assert 49 < h[0].rtt_ms < 51


# --- Retransmission -------------------------------------------------------- #
def test_health_counts_retransmission():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, seq=100, flags=0x18,
             payload=b"ABCDE", ts=1.0),
        _pkt(2, "192.168.0.10", "1.1.1.1", 50000, 443, seq=100, flags=0x18,
             payload=b"ABCDE", ts=2.0),
    ]
    assert tcp_health(pkts)[0].retransmissions == 1


# --- Dup-ACK --------------------------------------------------------------- #
def test_health_counts_dup_acks():
    pkts = [
        _pkt(i, "1.1.1.1", "192.168.0.10", 443, 50000, ack=500, flags=0x10,
             ts=float(i))
        for i in range(1, 4)            # 3 identische reine ACKs
    ]
    assert tcp_health(pkts)[0].dup_acks == 2


# --- Zero-Window ----------------------------------------------------------- #
def test_health_counts_zero_window():
    pkts = [
        _pkt(1, "1.1.1.1", "192.168.0.10", 443, 50000, ack=500, flags=0x10,
             window=0, ts=1.0),
    ]
    h = tcp_health(pkts)[0]
    assert h.zero_window == 1 and h.has_issue


# --- Beaconing ------------------------------------------------------------- #
def test_beaconing_detects_regular_interval():
    pkts = [
        _pkt(i, "192.168.0.10", "9.9.9.9", 50000 + i, 443, flags=0x02,
             ts=float(i * 10))
        for i in range(5)              # alle 10 s ein SYN
    ]
    f = beaconing(pkts)
    assert any("Beaconing" in x.summary for x in f)


def test_beaconing_ignores_irregular():
    times = [0, 3, 17, 18, 40]
    pkts = [
        _pkt(i, "192.168.0.10", "9.9.9.9", 50000 + i, 443, flags=0x02,
             ts=float(t))
        for i, t in enumerate(times)
    ]
    assert beaconing(pkts) == []


# --- Klartext-Credentials -------------------------------------------------- #
def test_credentials_http_basic_auth():
    token = base64.b64encode(b"alice:s3cret").decode()
    req = (f"GET /admin HTTP/1.1\r\nHost: x\r\n"
           f"Authorization: Basic {token}\r\n\r\n").encode()
    pkts = [_pkt(1, "192.168.0.10", "1.1.1.1", 50000, 80, flags=0x18, payload=req)]
    f = credentials(pkts)
    assert any("alice:s3cret" in x.summary for x in f)


def test_credentials_ftp_user_pass():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 21, flags=0x18,
             payload=b"USER bob\r\n"),
        _pkt(2, "192.168.0.10", "1.1.1.1", 50000, 21, flags=0x18,
             payload=b"PASS hunter2\r\n"),
    ]
    f = credentials(pkts)
    assert any("bob" in x.summary and "Benutzer" in x.summary for x in f)
    assert any("hunter2" in x.summary and "Passwort" in x.summary for x in f)


def test_credentials_quiet_for_clean_traffic():
    pkts = [_pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, flags=0x18,
                 payload=b"\x16\x03\x01\x00")]
    assert credentials(pkts) == []
