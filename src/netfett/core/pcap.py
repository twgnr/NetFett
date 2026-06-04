"""Lesen/Schreiben von klassischen PCAP-Dateien (Link-Type RAW IPv4).

Da der Raw-Socket Pakete ab dem IPv4-Kopf liefert, verwenden wir den
Link-Layer-Typ ``LINKTYPE_RAW`` (101). Solche Dateien öffnet auch Wireshark.
"""
from __future__ import annotations

import struct

_MAGIC = 0xA1B2C3D4
_VERSION = (2, 4)
LINKTYPE_RAW = 101


def write_pcap(path: str, packets) -> int:
    """Schreibt Pakete (Objekte mit .raw und .ts) als PCAP. Gibt Anzahl zurück."""
    n = 0
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", _MAGIC, _VERSION[0], _VERSION[1],
                            0, 0, 65535, LINKTYPE_RAW))
        for pkt in packets:
            raw = pkt.raw
            ts = pkt.ts
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            f.write(raw)
            n += 1
    return n


def read_pcap(path: str):
    """Liest eine PCAP-Datei. Liefert Liste von (ts, raw)-Tupeln.

    Unterstützt Little-/Big-Endian und Link-Type RAW (101) sowie
    Ethernet (1, dann wird der 14-Byte-Ethernet-Kopf entfernt, sofern IPv4)."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("Datei zu kurz für PCAP.")
    magic = struct.unpack("<I", data[:4])[0]
    if magic == _MAGIC:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        raise ValueError("Keine gültige PCAP-Datei (falsche Magic-Number).")
    (_v1, _v2, _tz, _sig, _snap, linktype) = struct.unpack(
        endian + "HHiIII", data[4:24])
    out = []
    pos = 24
    strip = 14 if linktype == 1 else 0  # Ethernet-Kopf abschneiden
    while pos + 16 <= len(data):
        sec, usec, caplen, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        if pos + caplen > len(data):
            break
        raw = data[pos:pos + caplen]
        pos += caplen
        if strip and len(raw) > strip:
            raw = raw[strip:]
        out.append((sec + usec / 1_000_000, raw))
    return out
