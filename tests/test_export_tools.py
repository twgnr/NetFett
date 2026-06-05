"""Tests für CSV/JSON-Export und die reinen ICMP-Werkzeug-Bausteine."""
from __future__ import annotations

import json
import socket
import struct

from netfett.core.dissect import dissect
from netfett.core.export import (
    export_conversations, export_domains, export_packets,
)
from netfett.core.tools import (
    ICMP_ECHO, ICMP_ECHO_REPLY, ICMP_TIME_EXCEEDED, build_icmp_echo, checksum,
    parse_icmp_reply,
)

LOCAL = {"192.168.0.10"}


def _pkt(n, sp, dp, payload=b""):
    ipp = struct.pack("!BBHHHBBH", 0x45, 0, 40 + len(payload), 1, 0x4000,
                      64, 6, 0) + socket.inet_aton("192.168.0.10") \
        + socket.inet_aton("1.1.1.1")
    tcp = struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 0x50, 0x18, 64240, 0, 0)
    return dissect(ipp + tcp + payload, 1000.0 + n, n, LOCAL)


# --- Export ---------------------------------------------------------------- #
def test_export_packets_csv_has_header_and_rows():
    out = export_packets([_pkt(1, 50000, 443), _pkt(2, 50001, 80)], "csv")
    lines = out.strip().splitlines()
    assert lines[0].startswith("number,time,src,src_port")
    assert len(lines) == 3                         # Kopf + 2 Zeilen


def test_export_packets_json_roundtrip():
    out = export_packets([_pkt(1, 50000, 443)], "json")
    data = json.loads(out)
    assert isinstance(data, list) and data[0]["dst_port"] == 443
    assert data[0]["src"] == "192.168.0.10"


def test_export_conversations_csv():
    pkts = [_pkt(1, 50000, 443), _pkt(2, 50000, 443)]
    out = export_conversations(pkts, "csv")
    lines = out.strip().splitlines()
    assert lines[0].startswith("proto,endpoint_a,endpoint_b,packets")
    assert "192.168.0.10:50000" in out


def test_export_domains_json():
    pkts = [_pkt(1, 50000, 443, b"\x16\x03\x01\x00")]  # TLS ohne SNI -> keine Domain
    data = json.loads(export_domains(pkts, "json"))
    assert data == []                              # keine Domains -> leere Liste


# --- ICMP-Bausteine -------------------------------------------------------- #
def test_checksum_zero_for_complement_pair():
    # Prüfsumme über die eigene Prüfsumme + Daten ergibt 0 (Validierung).
    pkt = build_icmp_echo(0x1234, 1, b"abcd")
    assert checksum(pkt) == 0


def test_build_and_parse_echo_roundtrip():
    pkt = build_icmp_echo(0xBEEF, 7, b"hi")
    # Empfang über Raw-Socket hätte einen IPv4-Kopf davor – simulieren:
    fake_ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(pkt), 1, 0,
                          64, 1, 0) + b"\x7f\x00\x00\x01" * 2
    typ, code, ident, seq = parse_icmp_reply(fake_ip + _as_reply(pkt))
    assert typ == ICMP_ECHO_REPLY and ident == 0xBEEF and seq == 7


def test_parse_time_exceeded_extracts_embedded_seq():
    # Router-Antwort: ICMP Time Exceeded mit eingebettetem Original-Echo (seq=5).
    orig_echo = build_icmp_echo(0xAAAA, 5)
    orig_ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(orig_echo), 1, 0,
                          1, 1, 0) + b"\x0a\x00\x00\x01" + b"\x08\x08\x08\x08"
    te = struct.pack("!BBH", ICMP_TIME_EXCEEDED, 0, 0) + b"\x00\x00\x00\x00" \
        + orig_ip + orig_echo
    outer_ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(te), 1, 0,
                           64, 1, 0) + b"\xc0\xa8\x00\x01" + b"\x0a\x00\x00\x01"
    typ, code, ident, seq = parse_icmp_reply(outer_ip + te)
    assert typ == ICMP_TIME_EXCEEDED and seq == 5 and ident == 0xAAAA


def _as_reply(echo: bytes) -> bytes:
    """Macht aus einem Echo-Request (Typ 8) eine Echo-Reply (Typ 0)."""
    body = echo[4:]
    head = struct.pack("!BBH", ICMP_ECHO_REPLY, 0, 0)
    chk = checksum(head + body)
    return struct.pack("!BBH", ICMP_ECHO_REPLY, 0, chk) + body
