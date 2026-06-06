"""Tests für mDNS-PTR- und SNMP-sysName-Builder/-Parser."""
from __future__ import annotations

import struct

from netfett.core import snmp
from netfett.core.mdns import build_ptr_query, parse_ptr_answer


# --- mDNS ------------------------------------------------------------------ #
def test_mdns_query_format():
    q = build_ptr_query("192.168.0.5")
    # Frage enthält die umgekehrte in-addr.arpa-Notation.
    assert b"\x015\x010\x03168\x03192" in q          # 5.0.168.192 (Labels)
    assert b"in-addr" in q and b"arpa" in q
    assert q[-4:] == struct.pack("!HH", 12, 0x8001)  # PTR, Unicast-Response


def _name(s: str) -> bytes:
    out = bytearray()
    for label in s.split("."):
        out.append(len(label))
        out += label.encode()
    out.append(0)
    return bytes(out)


def test_mdns_parse_ptr_answer():
    header = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    qname = _name("5.0.168.192.in-addr.arpa")
    question = qname + struct.pack("!HH", 12, 1)
    rdata = _name("MacBook.local")
    answer = qname + struct.pack("!HHIH", 12, 1, 0, len(rdata)) + rdata
    data = header + question + answer
    assert parse_ptr_answer(data) == "MacBook"       # „.local" entfernt


# --- SNMP ------------------------------------------------------------------ #
def test_snmp_build_get_is_sequence():
    msg = snmp.build_get("public", 7)
    assert msg[0] == 0x30                             # äußere SEQUENCE
    assert b"public" in msg
    assert snmp._oid(snmp._SYSNAME_OID) in msg        # sysName-OID enthalten


def test_snmp_parse_response():
    # GetResponse mit OID + OCTET STRING „router-eg".
    oid = snmp._oid(snmp._SYSNAME_OID)
    value = snmp._tlv(0x04, b"router-eg")
    varbind = snmp._tlv(0x30, oid + value)
    varbinds = snmp._tlv(0x30, varbind)
    pdu = snmp._tlv(0xA2, snmp._int(7) + snmp._int(0) + snmp._int(0) + varbinds)
    msg = snmp._tlv(0x30, snmp._int(0) + snmp._tlv(0x04, b"public") + pdu)
    assert snmp.parse_response(msg) == "router-eg"


def test_snmp_parse_no_match():
    assert snmp.parse_response(b"\x30\x03\x02\x01\x00") == ""
