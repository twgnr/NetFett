"""Tests für Hersteller-Lookup, ARP-Parsing und NetBIOS-Namen."""
from __future__ import annotations

import struct

from netfett.core import oui
from netfett.core.arp import parse_ipnet_table
from netfett.core.netbios import build_query, parse_response


# --- OUI / Hersteller ------------------------------------------------------ #
def test_vendor_builtin():
    assert oui.vendor("b8:27:eb:11:22:33") == "Raspberry Pi"
    assert oui.vendor("00-26-B9-aa-bb-cc") == "Dell"


def test_vendor_locally_administered():
    # Bit 0x02 im ersten Oktett → zufällige/lokale MAC.
    assert oui.vendor("02:11:22:33:44:55") == "(zufällige MAC)"


def test_vendor_unknown_and_empty():
    # 0x0C: global verwaltet (Bit 0x02 frei), nicht in der Liste → leer.
    assert oui.vendor("0c:99:99:11:22:33") == ""
    assert oui.vendor("") == ""


def test_load_manuf(tmp_path):
    p = tmp_path / "manuf"
    p.write_text("# comment\n00:11:22\tAcme\tAcme Corp\n40:00:00/28\tMasked\n",
                 encoding="utf-8")
    n = oui.load_manuf(str(p))
    assert n == 1                                  # maskierter Eintrag übersprungen
    assert oui.vendor("00:11:22:33:44:55") == "Acme"


# --- ARP-Tabelle ----------------------------------------------------------- #
def test_parse_ipnet_table():
    # 1 Eintrag: index, physlen=6, phys[8], ip=192.168.0.5, type
    row = (struct.pack("<I", 12) + struct.pack("<I", 6)
           + bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0, 0])
           + bytes([192, 168, 0, 5]) + struct.pack("<I", 3))
    buf = struct.pack("<I", 1) + row
    table = parse_ipnet_table(buf)
    assert table == {"192.168.0.5": "aa:bb:cc:dd:ee:ff"}


# --- NetBIOS --------------------------------------------------------------- #
def test_netbios_query_format():
    q = build_query()
    assert len(q) == 12 + 1 + 32 + 1 + 4          # Header + kodierter Name + Typ/Klasse
    assert q[12] == 32                             # Längen-Byte des Namens


def test_netbios_parse_response():
    # Antwort mit einem eindeutigen Workstation-Namen "PCBOB".
    header = struct.pack("!HHHHHH", 0x4E42, 0x8400, 0, 1, 0, 0)
    question = bytes([32]) + b"A" * 32 + b"\x00" + struct.pack("!HH", 0x21, 1)
    ans_name = bytes([32]) + b"A" * 32 + b"\x00"
    fixed = struct.pack("!HHIH", 0x21, 1, 0, 0)   # Typ, Klasse, TTL, RDLen
    name = b"PCBOB".ljust(15, b" ")
    entry = name + bytes([0x00]) + struct.pack("!H", 0x0400)  # unique, suffix 0x00
    rdata = bytes([1]) + entry
    data = header + question + ans_name + fixed + rdata
    assert parse_response(data) == "PCBOB"
