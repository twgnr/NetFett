"""Tests für Profi-Features: Coloring-Rules, IOC, IO-Timeline, Topologie."""
from __future__ import annotations

import socket
import struct

from netfett.core.analyze import io_timeline, topology
from netfett.core.coloring import ColorRule, RuleSet
from netfett.core.dissect import dissect
from netfett.core.displayfilter import compile_filter
from netfett.core.ioc import IocSet, ioc_findings

LOCAL = {"192.168.0.10"}


def _ip(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000,
                      64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _tcp(sp, dp, payload=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 0x50, 0x18, 64240, 0, 0) + payload


def _pkt(n, src, dst, sp, dp, payload=b"", ts=1000.0):
    return dissect(_ip(src, dst, 6, _tcp(sp, dp, payload)), ts, n, LOCAL)


# --- Coloring-Rules -------------------------------------------------------- #
def test_ruleset_first_match_wins():
    rules = [ColorRule("tls", "tls", bg="#111"),
             ColorRule("tcp", "tcp", bg="#222")]
    rs = RuleSet(rules)
    tls = _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, b"\x16\x03\x01\x00")
    plain = _pkt(2, "192.168.0.10", "1.1.1.1", 50000, 80)
    assert rs.match(tls) == ("", "#111")        # TLS-Regel zuerst
    assert rs.match(plain) == ("", "#222")      # nur TCP


def test_ruleset_skips_disabled_and_invalid():
    rules = [ColorRule("aus", "tcp", bg="#111", enabled=False),
             ColorRule("kaputt", "port abc", bg="#222"),   # ungültig
             ColorRule("ok", "tcp", bg="#333")]
    rs = RuleSet(rules)
    assert rs.match(_pkt(1, "192.168.0.10", "1.1.1.1", 1, 80)) == ("", "#333")


def test_ruleset_roundtrip():
    rs = RuleSet([ColorRule("x", "udp", fg="#abc", bg="#def")])
    rs2 = RuleSet.from_list(rs.to_list())
    assert rs2.rules[0].filter_text == "udp" and rs2.rules[0].fg == "#abc"


# --- IOC ------------------------------------------------------------------- #
def test_ioc_parse_and_match():
    iocs = IocSet.from_text("# böse\n1.2.3.4\n10.0.0.0/8\nevil.example\n")
    assert iocs
    p1 = _pkt(1, "192.168.0.10", "1.2.3.4", 50000, 443)
    p2 = _pkt(2, "10.5.6.7", "192.168.0.10", 80, 50000)
    p3 = _pkt(3, "192.168.0.10", "9.9.9.9", 1, 2)
    assert iocs.match(p1) == "1.2.3.4"
    assert iocs.match(p2) == "10.0.0.0/8"
    assert iocs.match(p3) == ""


def test_ioc_domain_suffix_match():
    iocs = IocSet.from_text("evil.example")
    p = _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443,
             b"\x16\x03\x01\x00")           # kein Domain
    p.domain = "sub.evil.example"
    assert iocs.match(p) == "evil.example"
    p.domain = "notevil.example.org"
    assert iocs.match(p) == ""


def test_ioc_findings():
    iocs = IocSet.from_text("1.2.3.4")
    f = ioc_findings([_pkt(7, "192.168.0.10", "1.2.3.4", 1, 443)], iocs)
    assert len(f) == 1 and f[0].packet == 7 and "1.2.3.4" in f[0].summary


# --- IO-Timeline ----------------------------------------------------------- #
def test_io_timeline_multi_filter():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, b"x" * 100, ts=1000.0),
        _pkt(2, "192.168.0.10", "8.8.8.8", 50001, 80, b"y" * 50, ts=1000.0),
        _pkt(3, "192.168.0.10", "1.1.1.1", 50000, 443, b"z" * 30, ts=1002.0),
    ]
    preds = [None, compile_filter("port 443"), compile_filter("port 80")]
    n, series = io_timeline(pkts, preds, bucket=1.0)
    assert n == 3                                # 0..2 s
    assert series[0][0] == pkts[0].length + pkts[1].length   # alles in Bucket 0
    assert series[1][0] == pkts[0].length and series[1][2] == pkts[2].length
    assert series[2][0] == pkts[1].length


def test_io_timeline_by_packets():
    pkts = [_pkt(1, "192.168.0.10", "1.1.1.1", 1, 443, ts=1.0),
            _pkt(2, "192.168.0.10", "1.1.1.1", 1, 443, ts=1.0)]
    n, series = io_timeline(pkts, [None], bucket=1.0, by_packets=True)
    assert series[0][0] == 2


# --- Topologie ------------------------------------------------------------- #
def test_topology_nodes_and_edges():
    pkts = [
        _pkt(1, "192.168.0.10", "1.1.1.1", 50000, 443, b"x" * 500),
        _pkt(2, "1.1.1.1", "192.168.0.10", 443, 50000, b"y" * 100),
        _pkt(3, "192.168.0.10", "8.8.8.8", 50001, 53, b"z" * 20),
    ]
    nodes, edges = topology(pkts, LOCAL, max_nodes=10)
    ips = {n.ip for n in nodes}
    assert ips == {"192.168.0.10", "1.1.1.1", "8.8.8.8"}
    assert any(n.is_local for n in nodes if n.ip == "192.168.0.10")
    big = max(edges, key=lambda e: e.bytes)
    assert {big.a, big.b} == {"192.168.0.10", "1.1.1.1"}


def test_topology_limits_nodes():
    pkts = [_pkt(i, "192.168.0.10", f"10.0.0.{i}", 50000 + i, 443, b"x" * i)
            for i in range(1, 30)]
    nodes, _edges = topology(pkts, LOCAL, max_nodes=5)
    assert len(nodes) == 5
