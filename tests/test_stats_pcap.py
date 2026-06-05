"""Tests für Statistik-Akkumulation und PCAP-Roundtrip."""
from __future__ import annotations

import os
import tempfile

from netfett.core.models import DIR_IN, DIR_OUT, Packet
import struct

from netfett.core.pcap import PcapWriter, read_pcap, write_pcap, write_pcapng
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


def test_pcap_writer_streaming_roundtrip():
    pkts = [mk(DIR_OUT, 50), mk(DIR_IN, 70), mk(DIR_OUT, 30)]
    for i, p in enumerate(pkts):
        p.raw = bytes([0x45]) + bytes([i]) * (p.length - 1)
    path = os.path.join(tempfile.mkdtemp(), "stream.pcap")
    with PcapWriter(path) as w:
        for p in pkts:
            w.write_packet(p)
            w.flush()                        # mitten im Schreiben lesbar
        assert w.count == 3
    out = read_pcap(path)
    assert len(out) == 3
    assert [r[1] for r in out] == [p.raw for p in pkts]


def _read_pcapng_epb_data(path):
    """Minimaler pcapng-Parser: liefert die Paketdaten aller EPBs."""
    with open(path, "rb") as f:
        data = f.read()
    pos, packets = 0, []
    while pos + 12 <= len(data):
        btype, total = struct.unpack("<II", data[pos:pos + 8])
        if btype == 0x00000006:                         # Enhanced Packet Block
            caplen = struct.unpack("<I", data[pos + 20:pos + 24])[0]
            packets.append(data[pos + 28:pos + 28 + caplen])
        pos += total
    return packets


def test_pcapng_export_roundtrip():
    pkts = [mk(DIR_OUT, 50), mk(DIR_IN, 71)]            # 71 → ungerade (Padding!)
    for i, p in enumerate(pkts):
        p.raw = bytes([0x45]) + bytes([i]) * (p.length - 1)
    path = os.path.join(tempfile.mkdtemp(), "cap.pcapng")
    n = write_pcapng(path, pkts)
    assert n == 2
    # Datei beginnt mit dem Section-Header-Block-Typ.
    with open(path, "rb") as f:
        assert struct.unpack("<I", f.read(4))[0] == 0x0A0D0D0A
    out = _read_pcapng_epb_data(path)
    assert out == [p.raw for p in pkts]                 # inkl. korrektem Padding
