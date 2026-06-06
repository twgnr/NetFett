"""Lesen der ARP-Tabelle des Systems (IP → MAC) – Windows ``GetIpNetTable``.

Liefert die vom Betriebssystem bereits aufgelösten MAC-Adressen; nach einem
Ping-Sweep ist die Tabelle für antwortende Geräte gefüllt. Kein Adminrecht nötig.
"""
from __future__ import annotations

import socket
import struct
import sys

_WIN = sys.platform == "win32"
_ROW = 24                                  # sizeof(MIB_IPNETROW)

if _WIN:
    import ctypes
    import ctypes.wintypes as wt
    _iphlpapi = ctypes.WinDLL("iphlpapi")
    _iphlpapi.GetIpNetTable.restype = wt.DWORD


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_ipnet_table(buf: bytes) -> dict[str, str]:
    """Zerlegt einen MIB_IPNETTABLE-Puffer in ``{ip: mac}`` (testbar)."""
    if len(buf) < 4:
        return {}
    num = struct.unpack_from("<I", buf, 0)[0]
    out: dict[str, str] = {}
    for i in range(num):
        base = 4 + i * _ROW
        if base + _ROW > len(buf):
            break
        phys_len = struct.unpack_from("<I", buf, base + 4)[0]
        phys = buf[base + 8:base + 8 + min(phys_len, 8)]
        ip = socket.inet_ntoa(buf[base + 16:base + 20])
        if phys_len:
            out[ip] = _format_mac(phys)
    return out


def arp_table() -> dict[str, str]:
    """IP → MAC aus der System-ARP-Tabelle (leer außerhalb Windows / bei Fehler)."""
    if not _WIN:
        return {}
    size = wt.DWORD(0)
    _iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
    if size.value == 0:
        return {}
    buf = ctypes.create_string_buffer(size.value)
    if _iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False) != 0:
        return {}
    return parse_ipnet_table(buf.raw[:size.value])
