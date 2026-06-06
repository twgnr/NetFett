"""mDNS/Bonjour-Namensabfrage: den ``.local``-Hostnamen eines Geräts ermitteln.

Sendet eine (unicast) mDNS-Reverse-PTR-Anfrage an das Gerät (UDP/5353) und liest
den Hostnamen aus der Antwort. Reine Standardbibliothek, ohne Adminrechte;
funktioniert v. a. bei Apple-/IoT-/Linux-Geräten mit mDNS-Responder.
"""
from __future__ import annotations

import socket
import struct

from .analyze import _dns_name           # kompressionsfähiger DNS-Namens-Decoder


def _reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        lb = label.encode("ascii", "replace")[:63]
        out.append(len(lb))
        out += lb
    out.append(0)
    return bytes(out)


def build_ptr_query(ip: str, tid: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    # qtype PTR (12), qclass IN mit Unicast-Response-Bit (0x8001).
    question = _encode_name(_reverse_name(ip)) + struct.pack("!HH", 12, 0x8001)
    return header + question


def parse_ptr_answer(data: bytes) -> str:
    """Liefert den Hostnamen aus der PTR-Antwort (ohne ``.local``) oder „"."""
    if len(data) < 12:
        return ""
    qd, an = struct.unpack("!HH", data[4:8])
    pos = 12
    for _ in range(qd):
        _n, pos = _dns_name(data, pos)
        pos += 4
    for _ in range(an):
        _n, pos = _dns_name(data, pos)
        if pos + 10 > len(data):
            break
        atype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if atype == 12:                              # PTR
            name, _ = _dns_name(data, pos)
            name = name.rstrip(".")
            if name.endswith(".local"):
                name = name[:-6]
            return name
        pos += rdlen
    return ""


def mdns_name(ip: str, timeout: float = 0.8) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_ptr_query(ip), (ip, 5353))
        data, _addr = sock.recvfrom(4096)
        return parse_ptr_answer(data)
    except OSError:
        return ""
    finally:
        sock.close()
