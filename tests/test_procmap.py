"""Tests für die (betriebssystemunabhängige) Prozess-Zuordnungslogik."""
from __future__ import annotations

from netfett.core.models import DIR_IN, DIR_OUT, Packet
from netfett.core.procmap import aggregate_processes, process_for_packet

LOCAL = {"192.168.0.10"}


def _pkt(src, dst, sp, dp, l4="TCP", direction=DIR_OUT, length=100, process=""):
    return Packet(number=1, ts=1.0, raw=b"", direction=direction, src=src,
                  dst=dst, src_port=sp, dst_port=dp, l4=l4, length=length,
                  process=process)


def test_process_for_outgoing_uses_local_src_port():
    pmap = {("TCP", 50000): (1234, "firefox.exe")}
    pkt = _pkt("192.168.0.10", "1.1.1.1", 50000, 443, direction=DIR_OUT)
    assert process_for_packet(pkt, pmap, LOCAL) == "firefox.exe"


def test_process_for_incoming_uses_local_dst_port():
    pmap = {("UDP", 53): (4, "System")}
    pkt = _pkt("8.8.8.8", "192.168.0.10", 53, 53, l4="UDP", direction=DIR_IN)
    assert process_for_packet(pkt, pmap, LOCAL) == "System"


def test_process_unknown_when_not_in_map():
    pkt = _pkt("192.168.0.10", "1.1.1.1", 50000, 443)
    assert process_for_packet(pkt, {}, LOCAL) == ""


def test_process_empty_for_non_tcp_udp():
    pkt = _pkt("192.168.0.10", "1.1.1.1", None, None, l4="ICMP")
    assert process_for_packet(pkt, {}, LOCAL) == ""


def test_aggregate_processes_groups_and_sorts():
    pkts = [
        _pkt("192.168.0.10", "1.1.1.1", 1, 443, direction=DIR_OUT,
             length=1000, process="firefox.exe"),
        _pkt("1.1.1.1", "192.168.0.10", 443, 1, direction=DIR_IN,
             length=200, process="firefox.exe"),
        _pkt("192.168.0.10", "8.8.8.8", 2, 53, direction=DIR_OUT,
             length=80, process=""),               # → unbekannt
    ]
    stats = aggregate_processes(pkts)
    assert stats[0].name == "firefox.exe"
    assert stats[0].bytes == 1200
    assert stats[0].tx_bytes == 1000 and stats[0].rx_bytes == 200
    assert stats[1].name == "unbekannt"
