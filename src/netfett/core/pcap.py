"""Lesen/Schreiben von klassischen PCAP-Dateien (Link-Type RAW IPv4).

Da der Raw-Socket Pakete ab dem IPv4-Kopf liefert, verwenden wir den
Link-Layer-Typ ``LINKTYPE_RAW`` (101). Solche Dateien öffnet auch Wireshark.
"""
from __future__ import annotations

import struct

_MAGIC = 0xA1B2C3D4
_VERSION = (2, 4)
LINKTYPE_RAW = 101


class PcapWriter:
    """Streaming-Writer: schreibt Pakete einzeln, sobald sie eintreffen.

    Für die Langzeit-Erfassung – so muss nicht der gesamte Mitschnitt im
    Speicher gehalten werden. Als Kontextmanager nutzbar."""

    def __init__(self, path: str, linktype: int = LINKTYPE_RAW) -> None:
        self._f = open(path, "wb")
        self._f.write(struct.pack("<IHHiIII", _MAGIC, _VERSION[0], _VERSION[1],
                                  0, 0, 65535, linktype))
        self._count = 0

    def write(self, ts: float, raw: bytes) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
        self._f.write(raw)
        self._count += 1

    def write_packet(self, pkt) -> None:
        self.write(pkt.ts, pkt.raw)

    def flush(self) -> None:
        if self._f is not None:
            self._f.flush()

    def close(self) -> None:
        if self._f is not None:
            self._f.close()
            self._f = None

    @property
    def count(self) -> int:
        return self._count

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def write_pcap(path: str, packets) -> int:
    """Schreibt Pakete (Objekte mit .raw und .ts) als PCAP. Gibt Anzahl zurück."""
    with PcapWriter(path) as w:
        for pkt in packets:
            w.write_packet(pkt)
        return w.count


# --------------------------------------------------------------------------- #
# PCAP Next Generation (.pcapng) – modernes Wireshark-Format
# --------------------------------------------------------------------------- #
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_EPB = 0x00000006
_PCAPNG_BOM = 0x1A2B3C4D


def _ng_block(block_type: int, body: bytes) -> bytes:
    """Rahmt einen pcapng-Block (Typ, Gesamtlänge, Body, Gesamtlänge)."""
    total = 12 + len(body)
    return (struct.pack("<II", block_type, total) + body
            + struct.pack("<I", total))


def write_pcapng(path: str, packets, linktype: int = LINKTYPE_RAW,
                 comments: dict | None = None) -> int:
    """Schreibt Pakete als ``.pcapng`` (Section Header + Interface + Pakete).

    Zeitstempel in Mikrosekunden. ``comments`` (Paketnummer → Text) werden als
    pcapng-``opt_comment`` je Paket geschrieben. Gibt die Anzahl zurück."""
    n = 0
    with open(path, "wb") as f:
        # Section Header Block: Byte-Order-Magic, Version 1.0, Section-Länge -1.
        f.write(_ng_block(_PCAPNG_SHB,
                          struct.pack("<IHHq", _PCAPNG_BOM, 1, 0, -1)))
        # Interface Description Block: Link-Type + Snaplen (0 = unbegrenzt).
        f.write(_ng_block(_PCAPNG_IDB, struct.pack("<HHI", linktype, 0, 0)))
        for pkt in packets:
            raw = pkt.raw
            ts_us = int(pkt.ts * 1_000_000)
            body = struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF,
                               len(raw), len(raw))
            body += raw + b"\x00" * (-len(raw) % 4)      # auf 4 Byte auffüllen
            comment = comments.get(getattr(pkt, "number", 0)) if comments else None
            if comment:
                cb = comment.encode("utf-8")
                body += struct.pack("<HH", 1, len(cb)) + cb + b"\x00" * (-len(cb) % 4)
                body += struct.pack("<HH", 0, 0)         # opt_endofopt
            f.write(_ng_block(_PCAPNG_EPB, body))
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


def read_pcapng(path: str):
    """Liest eine ``.pcapng``-Datei. Liefert Liste von (ts, raw)-Tupeln."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 12 or struct.unpack("<I", data[:4])[0] != _PCAPNG_SHB:
        raise ValueError("Keine gültige pcapng-Datei.")
    endian = "<" if data[8:12] == struct.pack("<I", _PCAPNG_BOM) else ">"
    interfaces: list[tuple[int, int]] = []     # (linktype, tsresol-Teiler)
    out = []
    pos = 0
    while pos + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[pos:pos + 4])[0] \
            if pos else _PCAPNG_SHB
        total = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        if total < 12 or pos + total > len(data):
            break
        body = data[pos + 8:pos + total - 4]
        if btype == _PCAPNG_IDB:
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            interfaces.append((linktype, 1_000_000))     # Default: µs
        elif btype == _PCAPNG_EPB:
            ifid, tsh, tsl, caplen = struct.unpack(endian + "IIII", body[0:16])
            raw = body[20:20 + caplen]
            _lt, divisor = interfaces[ifid] if ifid < len(interfaces) \
                else (LINKTYPE_RAW, 1_000_000)
            ts = ((tsh << 32) | tsl) / divisor
            if _lt == 1 and len(raw) > 14:                 # Ethernet abschneiden
                raw = raw[14:]
            out.append((ts, raw))
        pos += total
    return out


def read_capture(path: str):
    """Liest pcap **oder** pcapng (automatische Erkennung)."""
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == struct.pack("<I", _PCAPNG_SHB):
        return read_pcapng(path)
    return read_pcap(path)


def merge_captures(paths) -> list:
    """Liest mehrere Capture-Dateien und führt sie zeitlich sortiert zusammen."""
    records = []
    for p in paths:
        records.extend(read_capture(p))
    records.sort(key=lambda r: r[0])
    return records


class RotatingPcapWriter:
    """Schreibt fortlaufend PCAP und rotiert bei Überschreiten einer Größe.

    Hält höchstens ``keep`` Dateien (``base-001.pcap``, ``base-002.pcap`` …);
    ältere werden gelöscht. Schnittstelle wie :class:`PcapWriter`."""

    def __init__(self, base_path: str, max_bytes: int = 50 * 1024 * 1024,
                 keep: int = 5) -> None:
        import os
        self._dir = os.path.dirname(base_path) or "."
        stem = os.path.basename(base_path)
        self._stem = stem[:-5] if stem.endswith(".pcap") else stem
        self._max_bytes = max(64 * 1024, max_bytes)
        self._keep = max(1, keep)
        self._index = 0
        self._count = 0
        self._files: list[str] = []
        self._writer: PcapWriter | None = None
        self._open_next()

    def _open_next(self) -> None:
        import os
        if self._writer is not None:
            self._writer.close()
        self._index += 1
        path = os.path.join(self._dir, f"{self._stem}-{self._index:03d}.pcap")
        self._writer = PcapWriter(path)
        self._cur_path = path
        self._cur_bytes = 24
        self._files.append(path)
        while len(self._files) > self._keep:                # älteste entfernen
            old = self._files.pop(0)
            try:
                os.remove(old)
            except OSError:
                pass

    def write_packet(self, pkt) -> None:
        rec = 16 + len(pkt.raw)
        if self._cur_bytes + rec > self._max_bytes:
            self._open_next()
        self._writer.write_packet(pkt)
        self._cur_bytes += rec
        self._count += 1

    def write(self, ts: float, raw: bytes) -> None:
        rec = 16 + len(raw)
        if self._cur_bytes + rec > self._max_bytes:
            self._open_next()
        self._writer.write(ts, raw)
        self._cur_bytes += rec
        self._count += 1

    def flush(self) -> None:
        if self._writer is not None:
            self._writer.flush()

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None

    @property
    def count(self) -> int:
        return self._count
