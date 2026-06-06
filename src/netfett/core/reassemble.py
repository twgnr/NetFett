"""Reassemblierung fragmentierter IP-Datagramme (IPv4 und IPv6).

Sammelt Fragmente desselben Datagramms (gleiche Quelle/Ziel/Identification) und
gibt das vollständige Datagramm zurück, sobald alle Fragmente vorliegen. Rein
und unit-testbar. Bewahrt einen begrenzten Puffer offener Datagramme.

Verwendung (zustandsbehaftet, je Capture/Datei eine Instanz)::

    r = IPReassembler()
    state, data, count = r.add(raw)
    # state: "whole"        – nicht fragmentiert, ``data`` == raw
    #        "incomplete"   – Fragment gepuffert, ``data`` ist None
    #        "reassembled"  – komplett, ``data`` ist das volle Datagramm
"""
from __future__ import annotations


class IPReassembler:
    def __init__(self, max_datagrams: int = 4096) -> None:
        self._buf: dict = {}            # key → {header, frags{off:payload}, last_end, count}
        self._max = max_datagrams

    def add(self, raw: bytes) -> tuple[str, bytes | None, int]:
        if len(raw) < 1:
            return "whole", raw, 1
        version = raw[0] >> 4
        if version == 4:
            return self._add_v4(raw)
        if version == 6:
            return self._add_v6(raw)
        return "whole", raw, 1

    # --- IPv4 -------------------------------------------------------------- #
    def _add_v4(self, raw: bytes):
        if len(raw) < 20:
            return "whole", raw, 1
        ihl = max(20, min((raw[0] & 0x0F) * 4, len(raw)))
        flags_frag = int.from_bytes(raw[6:8], "big")
        mf = (flags_frag >> 13) & 1
        off = (flags_frag & 0x1FFF) * 8
        if mf == 0 and off == 0:
            return "whole", raw, 1
        key = ("4", raw[12:16], raw[16:20], raw[4:6], raw[9])
        ent = self._entry(key)
        ent["frags"][off] = raw[ihl:]
        ent["count"] += 1
        if off == 0:
            ent["header"] = raw[:ihl]
        if mf == 0:
            ent["last_end"] = off + len(raw[ihl:])
        full = self._complete(ent, ipv6=False)
        if full is not None:
            count = ent["count"]
            del self._buf[key]
            return "reassembled", full, count
        return "incomplete", None, ent["count"]

    # --- IPv6 -------------------------------------------------------------- #
    def _add_v6(self, raw: bytes):
        if len(raw) < 48 or raw[6] != 44:           # 44 = Fragment-Header
            return "whole", raw, 1
        fh_next = raw[40]
        off_flags = int.from_bytes(raw[42:44], "big")
        off = off_flags & 0xFFF8                     # Offset (Byte) in Bits 15..3
        mf = off_flags & 1
        ident = raw[44:48]
        if mf == 0 and off == 0:
            return "whole", raw, 1
        key = ("6", raw[8:24], raw[24:40], ident)
        ent = self._entry(key)
        ent["frags"][off] = raw[48:]
        ent["count"] += 1
        if off == 0:
            header = bytearray(raw[:40])
            header[6] = fh_next                       # Fragment-Header entfernen
            ent["header"] = bytes(header)
        if mf == 0:
            ent["last_end"] = off + len(raw[48:])
        full = self._complete(ent, ipv6=True)
        if full is not None:
            count = ent["count"]
            del self._buf[key]
            return "reassembled", full, count
        return "incomplete", None, ent["count"]

    # --- gemeinsam --------------------------------------------------------- #
    def _entry(self, key):
        ent = self._buf.get(key)
        if ent is None:
            if len(self._buf) >= self._max:           # ältestes offenes verwerfen
                self._buf.pop(next(iter(self._buf)))
            ent = {"header": None, "frags": {}, "last_end": None, "count": 0}
            self._buf[key] = ent
        return ent

    @staticmethod
    def _complete(ent, ipv6: bool) -> bytes | None:
        if ent["header"] is None or ent["last_end"] is None:
            return None
        expected = 0
        for o in sorted(ent["frags"]):
            if o > expected:
                return None                           # Lücke → noch unvollständig
            expected = max(expected, o + len(ent["frags"][o]))
        if expected < ent["last_end"]:
            return None
        body = bytearray(ent["last_end"])
        for o, payload in ent["frags"].items():
            end = min(o + len(payload), ent["last_end"])
            if o < ent["last_end"]:
                body[o:end] = payload[:end - o]
        header = bytearray(ent["header"])
        if ipv6:
            header[4:6] = len(body).to_bytes(2, "big")    # Payload-Länge
        else:
            total = len(header) + len(body)
            header[2:4] = total.to_bytes(2, "big")        # Total Length
            header[6:8] = b"\x00\x00"                      # Flags + Offset löschen
        return bytes(header) + bytes(body)
