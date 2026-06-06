"""Tests: TCP-Optionen, DHCP/NTP/QUIC-Dissection, WHOIS-Referral, CLI."""
from __future__ import annotations

import os
import socket
import struct
import tempfile

from netfett.cli import run_cli
from netfett.core.dissect import dissect
from netfett.core.pcap import write_pcap
from netfett.core.whois import referral

LOCAL = {"192.168.0.10"}


def _ip(src, dst, proto, payload, ihl=20):
    total = ihl + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x40 | (ihl // 4), 0, total, 1, 0x4000,
                      64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


# --- TCP-Optionen ---------------------------------------------------------- #
def test_tcp_options_parsed():
    opts = (struct.pack("!BBH", 2, 4, 1460)          # MSS (4)
            + struct.pack("!BBB", 3, 3, 7)           # Window Scale (3)
            + b"\x04\x02"                             # SACK permitted (2)
            + b"\x01\x01\x01")                        # NOPs → Länge 12 (×4)
    data_off = 20 + len(opts)
    off_words = (data_off // 4) << 4
    tcp = struct.pack("!HHIIBBHHH", 50000, 443, 1, 0, off_words, 0x02,
                      64240, 0, 0) + opts
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 6, tcp), 1.0, 1, LOCAL)
    tcp_layer = [l for l in pkt.layers if l.name.startswith("Transmission")][0]
    optval = dict(tcp_layer.fields).get("Optionen", "")
    assert "MSS=1460" in optval and "WScale=7" in optval and "SACK-erlaubt" in optval


# --- DHCP / NTP / QUIC ----------------------------------------------------- #
def test_dhcp_message_type():
    body = b"\x01" + b"\x00" * 235 + b"\x63\x82\x53\x63"   # op=1 + Magic-Cookie
    body += b"\x35\x01\x01\xff"                            # Option 53 = Discover
    raw = _ip("0.0.0.0", "255.255.255.255", 17, _udp(68, 67, body))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    assert pkt.protocol == "DHCP" and "Discover" in pkt.info


def test_ntp_detected():
    body = bytes([0x1B]) + bytes([2]) + b"\x00" * 46      # v3, mode 3, stratum 2
    raw = _ip("192.168.0.10", "1.1.1.1", 17, _udp(50000, 123, body))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    assert pkt.protocol == "NTP" and "stratum=2" in pkt.info


def test_quic_detected():
    body = b"\xc0" + struct.pack("!I", 0x00000001) + b"\x00" * 20   # Long-Header
    raw = _ip("192.168.0.10", "1.1.1.1", 17, _udp(50000, 443, body))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    assert pkt.protocol == "QUIC"


# --- WHOIS-Referral -------------------------------------------------------- #
def test_whois_referral_parsing():
    text = "domain: EXAMPLE\nrefer: whois.verisign-grs.com\n"
    assert referral(text) == "whois.verisign-grs.com"
    assert referral("nichts hier") == ""


# --- CLI ------------------------------------------------------------------- #
def test_cli_reads_and_exports(capsys):
    pkts = [dissect(_ip("192.168.0.10", "1.1.1.1", 6,
                        struct.pack("!HHIIBBHHH", 50000, 443, 1, 0, 0x50, 0x18,
                                    64240, 0, 0)), 1.0, 1, LOCAL)]
    cap = os.path.join(tempfile.mkdtemp(), "c.pcap")
    write_pcap(cap, pkts)
    out_csv = os.path.join(tempfile.mkdtemp(), "out.csv")
    rc = run_cli(["--read", cap, "--export", out_csv, "--what", "packets"])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "1 Pakete gelesen" in printed
    assert os.path.getsize(out_csv) > 0
