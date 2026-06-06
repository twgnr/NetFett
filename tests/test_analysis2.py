"""Tests für DNS-Tiefenanalyse, Endpunkt-/Port-Statistik, Lebenszyklus, JA3."""
from __future__ import annotations

import socket
import struct

from netfett.core.analyze import (
    connection_states, dns_analysis, endpoints, parse_dns, port_stats,
    size_histogram,
)
from netfett.core.dissect import dissect
from netfett.core.ja3 import ja3, ja3s, parse_client_hello

LOCAL = {"192.168.0.10"}


def _ip(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000,
                      64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def _tcp(sp, dp, seq, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, 0, 0x50, flags,
                       64240, 0, 0) + payload


def _pkt(n, raw, ts=1000.0):
    return dissect(raw, ts, n, LOCAL)


def _dns_query(txid, name, qtype=1):
    q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack("!HH", qtype, 1)


def _dns_response(txid, name, ip, rcode=0):
    flags = 0x8000 | rcode
    q = struct.pack("!HHHHHH", txid, flags, 1, 1, 0, 0)
    qn = b""
    for part in name.split("."):
        qn += bytes([len(part)]) + part.encode()
    qn += b"\x00"
    body = qn + struct.pack("!HH", 1, 1)
    ans = qn + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return q + body + ans


# --- DNS ------------------------------------------------------------------- #
def test_parse_dns_query_and_response():
    q = parse_dns(_dns_query(0x1234, "example.com"))
    assert q and not q.is_response and q.qname == "example.com" and q.qtype == "A"
    r = parse_dns(_dns_response(0x1234, "example.com", "93.184.216.34"))
    assert r and r.is_response and r.answers == [("A", "93.184.216.34")]


def test_dns_analysis_correlates_response_time():
    pkts = [
        _pkt(1, _ip("192.168.0.10", "8.8.8.8", 17, _udp(40000, 53,
             _dns_query(0xAB, "test.org"))), ts=1.0),
        _pkt(2, _ip("8.8.8.8", "192.168.0.10", 17, _udp(53, 40000,
             _dns_response(0xAB, "test.org", "1.2.3.4"))), ts=1.05),
    ]
    stats = dns_analysis(pkts)
    assert len(stats) == 1
    s = stats[0]
    assert s.name == "test.org" and s.queries == 1 and s.responses == 1
    assert s.addresses == ("1.2.3.4",)
    assert s.avg_ms is not None and 49 < s.avg_ms < 51


def test_dns_analysis_counts_nxdomain():
    pkts = [
        _pkt(1, _ip("192.168.0.10", "8.8.8.8", 17, _udp(40000, 53,
             _dns_query(0x01, "nope.invalid"))), ts=1.0),
        _pkt(2, _ip("8.8.8.8", "192.168.0.10", 17, _udp(53, 40000,
             _dns_response(0x01, "nope.invalid", "0.0.0.0", rcode=3))), ts=1.1),
    ]
    assert dns_analysis(pkts)[0].nxdomain == 1


# --- Endpoints / Ports / Sizes --------------------------------------------- #
def test_endpoints_tx_rx():
    pkts = [
        _pkt(1, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, 0, 0x18,
             b"x" * 100))),
        _pkt(2, _ip("1.1.1.1", "192.168.0.10", 6, _tcp(443, 50000, 0, 0x18,
             b"y" * 40))),
    ]
    eps = {e.ip: e for e in endpoints(pkts)}
    assert eps["192.168.0.10"].tx_pkts == 1 and eps["192.168.0.10"].rx_pkts == 1
    assert eps["1.1.1.1"].bytes == pkts[0].length + pkts[1].length


def test_port_stats_uses_known_port():
    pkts = [_pkt(1, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, 0, 0x18)))]
    ps = port_stats(pkts)
    assert ps[0].port == 443 and ps[0].service == "HTTPS"


def test_size_histogram_buckets():
    pkts = [_pkt(1, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(1, 2, 0, 0x10)))]
    hist = dict(size_histogram(pkts))
    assert sum(hist.values()) == 1


# --- Connection lifecycle -------------------------------------------------- #
def test_connection_state_established_and_failed():
    ok = [
        _pkt(1, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, 0, 0x02)), ts=1.0),
        _pkt(2, _ip("1.1.1.1", "192.168.0.10", 6, _tcp(443, 50000, 0, 0x12)), ts=1.02),
        _pkt(3, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, 1, 0x18, b"hi")), ts=1.1),
    ]
    failed = [
        _pkt(4, _ip("192.168.0.10", "2.2.2.2", 6, _tcp(50001, 81, 0, 0x02)), ts=2.0),
    ]
    conns = connection_states(ok + failed)

    def find(ip, port):
        for c in conns:
            if (c.a, c.a_port) == (ip, port) or (c.b, c.b_port) == (ip, port):
                return c
        raise KeyError((ip, port))

    est = find("1.1.1.1", 443)
    assert est.state == "Aktiv (established)" and est.setup_ms is not None
    assert 19 < est.setup_ms < 21
    assert find("2.2.2.2", 81).state == "Fehlgeschlagen (keine Antwort)"


def test_connection_state_reset():
    pkts = [
        _pkt(1, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, 0, 0x02)), ts=1.0),
        _pkt(2, _ip("1.1.1.1", "192.168.0.10", 6, _tcp(443, 50000, 0, 0x04)), ts=1.1),
    ]
    assert connection_states(pkts)[0].state == "Zurückgesetzt (RST)"


# --- JA3 ------------------------------------------------------------------- #
def _client_hello_with(ciphers, exts):
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    ext_block = b""
    for et in exts:
        ext_block += struct.pack("!HH", et, 0)
    exts_field = struct.pack("!H", len(ext_block)) + ext_block
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + struct.pack("!H", len(cs)) + cs + b"\x00" + exts_field)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_ja3_filters_grease_and_hashes():
    import hashlib
    rec = _client_hello_with([0x0A0A, 0x1301, 0x1302], [0x0A0A, 0x0000, 0x0017])
    parsed = parse_client_hello(rec)
    assert parsed is not None
    version, ciphers, ext_list, _curves, _formats = parsed
    assert ciphers == [0x1301, 0x1302]              # GREASE entfernt
    assert ext_list == [0x0000, 0x0017]
    text, digest = ja3(rec)
    assert text == "771,4865-4866,0-23,,"
    assert digest == hashlib.md5(text.encode()).hexdigest()


def test_ja3_none_for_non_clienthello():
    assert ja3(b"\x16\x03\x01\x00\x04\x02\x00\x00\x00") is None  # ServerHello-Typ
