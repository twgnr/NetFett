"""NetBIOS-Namensabfrage (NBSTAT, UDP/137) – Gerätename im LAN ermitteln.

Schickt eine NBSTAT-Anfrage an den Host und liest den (eindeutigen) Rechnernamen
aus der Antwort. Reine Standardbibliothek, ohne Adminrechte. Funktioniert nur,
wenn der NetBIOS-Namensdienst antwortet (meist Windows-/Samba-Geräte).
"""
from __future__ import annotations

import socket
import struct


def _encode_name(name: str = "*") -> bytes:
    padded = name.encode("ascii", "replace")[:16]
    padded = padded + b"\x00" * (16 - len(padded))
    out = bytearray()
    for b in padded:
        out.append(ord("A") + (b >> 4))
        out.append(ord("A") + (b & 0x0F))
    return bytes(out)


def build_query(tid: int = 0x4E42) -> bytes:
    header = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    enc = _encode_name("*")
    question = bytes([len(enc)]) + enc + b"\x00" + struct.pack("!HH", 0x0021, 0x0001)
    return header + question


def parse_response(data: bytes) -> str:
    """Liest den eindeutigen Rechnernamen aus einer NBSTAT-Antwort (oder „")."""
    # Header(12) + Frage(38) + Antwort-Name(34) + Typ(2)+Klasse(2)+TTL(4)+RDLen(2)
    pos = 12 + 38 + 34 + 2 + 2 + 4 + 2
    if pos >= len(data):
        return ""
    num = data[pos]
    pos += 1
    for _ in range(num):
        if pos + 18 > len(data):
            break
        name = data[pos:pos + 15].decode("latin-1", "replace").strip()
        suffix = data[pos + 15]
        flags = int.from_bytes(data[pos + 16:pos + 18], "big")
        pos += 18
        # Eindeutiger Name (kein Gruppen-Bit) mit Workstation-Suffix 0x00.
        if not (flags & 0x8000) and suffix == 0x00 and name:
            return name
    return ""


def netbios_name(ip: str, timeout: float = 0.8) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_query(), (ip, 137))
        data, _addr = sock.recvfrom(2048)
        return parse_response(data)
    except OSError:
        return ""
    finally:
        sock.close()
