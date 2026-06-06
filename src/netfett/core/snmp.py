"""Minimaler SNMPv1-GET für ``sysName.0`` – Gerätename per SNMP ermitteln.

Baut eine SNMPv1-GetRequest (BER/ASN.1) für die OID 1.3.6.1.2.1.1.5.0 und liest
den Namen aus der Antwort. Reine Standardbibliothek, ohne Adminrechte; klappt
nur, wenn SNMP aktiv ist und die Community (Standard „public") passt.
"""
from __future__ import annotations

import socket

_SYSNAME_OID = [1, 3, 6, 1, 2, 1, 1, 5, 0]


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        if body[0] & 0x80:                            # positiv erzwingen
            body = b"\x00" + body
    return _tlv(0x02, body)


def _oid(parts: list[int]) -> bytes:
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:                                         # base-128 (für vollständigkeit)
            chunks = []
            while p:
                chunks.insert(0, p & 0x7F)
                p >>= 7
            body += bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])
    return _tlv(0x06, body)


def build_get(community: str = "public", request_id: int = 1) -> bytes:
    varbind = _tlv(0x30, _oid(_SYSNAME_OID) + _tlv(0x05, b""))   # OID + NULL
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(0xA0, _int(request_id) + _int(0) + _int(0) + varbinds)  # GetRequest
    return _tlv(0x30, _int(0) + _tlv(0x04, community.encode()) + pdu)


def _read_tlv(data: bytes, pos: int):
    tag = data[pos]
    ln = data[pos + 1]
    pos += 2
    if ln & 0x80:
        nb = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + nb], "big")
        pos += nb
    return tag, data[pos:pos + ln], pos + ln


def parse_response(data: bytes) -> str:
    """Liest den OCTET-STRING-Wert nach der sysName-OID aus der Antwort."""
    target = _oid(_SYSNAME_OID)
    idx = data.find(target)
    if idx < 0:
        return ""
    pos = idx + len(target)
    if pos < len(data) and data[pos] == 0x04:        # OCTET STRING = Wert
        _tag, value, _ = _read_tlv(data, pos)
        return value.decode("utf-8", "replace").strip()
    return ""


def snmp_sysname(ip: str, community: str = "public", timeout: float = 0.8) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_get(community), (ip, 161))
        data, _addr = sock.recvfrom(2048)
        return parse_response(data)
    except OSError:
        return ""
    finally:
        sock.close()
