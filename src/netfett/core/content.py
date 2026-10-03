"""Nutzdaten eines Pakets gewinnen und als Klartext oder Bytes einordnen.

Liefert die Anwendungs-Nutzdaten (nach TCP/UDP-Kopf) und entscheidet, ob sie
sich als **Klartext** darstellen lassen oder (verschlüsselt/binär) besser als
**Bytes**. Rein und unit-testbar.
"""
from __future__ import annotations

from ..i18n import tr

_V6_EXT = {0, 43, 60}          # Hop-by-Hop, Routing, Destination Options
_V6_FRAGMENT = 44


def l4_payload(raw: bytes) -> tuple[str, bytes]:
    """(L4-Protokoll, Nutzdaten) eines Pakets – TCP/UDP, IPv4 und IPv6."""
    if len(raw) < 1:
        return "", b""
    version = raw[0] >> 4
    if version == 4:
        if len(raw) < 20:
            return "", b""
        proto = raw[9]
        ihl = max(20, min((raw[0] & 0x0F) * 4, len(raw)))
        rest = raw[ihl:]
    elif version == 6:
        if len(raw) < 40:
            return "", b""
        proto = raw[6]
        rest = raw[40:]
        while rest and (proto in _V6_EXT or proto == _V6_FRAGMENT):
            ext_len = 8 if proto == _V6_FRAGMENT else (rest[1] + 1) * 8 \
                if len(rest) >= 2 else 0
            if ext_len <= 0 or ext_len > len(rest):
                break
            proto = rest[0]
            rest = rest[ext_len:]
    else:
        return "", b""

    if proto == 6:                                   # TCP
        if len(rest) < 20:
            return "TCP", b""
        data_off = max(20, min((rest[12] >> 4) * 4, len(rest)))
        return "TCP", rest[data_off:]
    if proto == 17:                                  # UDP
        if len(rest) < 8:
            return "UDP", b""
        return "UDP", rest[8:]
    return "", b""


def is_tls_record(payload: bytes) -> bool:
    """True, wenn die Nutzdaten wie ein TLS-Record beginnen (verschlüsselt)."""
    return (len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17)
            and payload[1] == 0x03)


def is_mostly_text(data: bytes) -> bool:
    """Heuristik: überwiegend druckbare ASCII-Zeichen (inkl. \\t \\r \\n)?"""
    if not data:
        return False
    sample = data[:1024]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) >= 0.85


def content_view(raw: bytes) -> tuple[str, bool, bytes]:
    """(Beschriftung, ist_Klartext, Nutzdaten) für die Inhalts-Ansicht."""
    _proto, payload = l4_payload(raw)
    if not payload:
        return tr("Keine Nutzdaten"), True, b""
    if is_tls_record(payload):
        return tr("Verschlüsselt (TLS) – Bytes"), False, payload
    if is_mostly_text(payload):
        return tr("Klartext"), True, payload
    return tr("Binär/verschlüsselt – Bytes"), False, payload


def as_text(data: bytes) -> str:
    """Druckbare Darstellung: Steuerzeichen außer Tab/CR/LF werden zu „.»."""
    return "".join(chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else "."
                   for b in data)
