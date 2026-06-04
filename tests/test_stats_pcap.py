"""Tests für Statistik-Akkumulation und PCAP-Roundtrip."""
from __future__ import annotations

import os
import tempfile

from netfett.core.models import DIR_IN, DIR_OUT, Packet
from netfett.core.pcap import read_pcap, write_pcap
from netfett.core.stats import Stats


def mk(direction, length, proto="TCP") -> Packet:
    return Packet(number=1, ts=1.5, raw=b"x" * length, direction=direction,
                  src="a", dst="b", protocol=proto, length=length)


def test_stats_throughput_and_totals():
    s = Stats(window=5)
    s.add(mk(DIR_OUT, 100))
    s.add(mk(DIR_IN, 40))
    s.add(mk(DIR_IN, 60, proto="UDP"))
    assert s.total_packets == 3
    assert s.total_bytes == 200
    assert s.total_out_bytes == 100
    assert s.total_in_bytes == 100
    s.tick()
    assert s.out_bps[-1] == 100
    assert s.in_bps[-1] == 100
    assert s.in_pps[-1] == 2
    # nach erneutem Tick ohne Pakete: 0
    s.tick()
    assert s.out_bps[-1] == 0
    protos = dict((n, b) for n, _c, b in s.top_protocols())
    assert protos["TCP"] == 140 and protos["UDP"] == 60


def test_pcap_roundtrip():
    pkts = [mk(DIR_OUT, 50), mk(DIR_IN, 70)]
    for i, p in enumerate(pkts):
        p.raw = bytes([0x45]) + bytes([i]) * (p.length - 1)  # plausibles IPv4-Startbyte
    path = os.path.join(tempfile.mkdtemp(), "cap.pcap")
    n = write_pcap(path, pkts)
    assert n == 2
    out = read_pcap(path)
    assert len(out) == 2
    assert out[0][1] == pkts[0].raw
    assert abs(out[0][0] - 1.5) < 1e-6
