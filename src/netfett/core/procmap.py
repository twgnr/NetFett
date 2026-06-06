"""Zuordnung von Netzwerkverkehr zu Programmen (nur Windows, reines ctypes).

Der Raw-Socket liefert keine Prozessinfo. Über die Windows-Verbindungstabellen
(``GetExtendedTcpTable`` / ``GetExtendedUdpTable``) bauen wir eine Abbildung
**lokaler Port → (PID, Programmname)**; ein Paket wird dann anhand seines lokalen
Ports zugeordnet. Funktioniert nur bei Live-Erfassung (bei geladenen PCAPs sind
die Verbindungen nicht mehr aktiv) und am vollständigsten mit Administratorrechten.

Die reinen Teile (:func:`process_for_packet`, :func:`aggregate_processes`) sind
ohne Betriebssystem testbar; die Tabellen-Abfrage ist Windows-spezifisch.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
from dataclasses import dataclass

from .models import DIR_IN, DIR_OUT, Packet

_WIN = sys.platform == "win32"
_AF_INET = 2
_TCP_TABLE_OWNER_PID_ALL = 5
_UDP_TABLE_OWNER_PID = 1
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

if _WIN:
    import ctypes
    import ctypes.wintypes as wt

    _iphlpapi = ctypes.WinDLL("iphlpapi")
    _kernel32 = ctypes.WinDLL("kernel32")
    _iphlpapi.GetExtendedTcpTable.restype = wt.DWORD
    _iphlpapi.GetExtendedUdpTable.restype = wt.DWORD

_pid_name_cache: dict[int, str] = {}


def _pid_name(pid: int) -> str:
    if pid in (0, 4):
        return "System"
    cached = _pid_name_cache.get(pid)
    if cached is not None:
        return cached
    name = ""
    if _WIN:
        handle = _kernel32.OpenProcess(
            _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            buf = ctypes.create_unicode_buffer(512)
            size = wt.DWORD(512)
            if _kernel32.QueryFullProcessImageNameW(
                    handle, 0, buf, ctypes.byref(size)):
                name = os.path.basename(buf.value)
            _kernel32.CloseHandle(handle)
    # Ohne Rechte ist der Name oft nicht lesbar → wenigstens die PID zeigen.
    name = name or f"PID {pid}"
    _pid_name_cache[pid] = name
    return name


def _extended_table(func, table_class: int, row_size: int,
                    port_field: int, pid_field: int):
    """Liest eine Owner-PID-Tabelle und liefert (port, pid)-Paare (IPv4)."""
    size = wt.DWORD(0)
    func(None, ctypes.byref(size), False, _AF_INET, table_class, 0)
    if size.value == 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    if func(buf, ctypes.byref(size), False, _AF_INET, table_class, 0) != 0:
        return []
    num = struct.unpack_from("I", buf, 0)[0]
    rows = []
    for i in range(num):
        base = 4 + i * row_size
        fields = struct.unpack_from(f"{row_size // 4}I", buf, base)
        port = socket.ntohs(fields[port_field] & 0xFFFF)
        pid = fields[pid_field]
        if port:
            rows.append((port, pid))
    return rows


def port_process_map() -> dict[tuple[str, int], tuple[int, str]]:
    """Abbildung ``(L4, lokaler Port) -> (PID, Programmname)`` (leer außer Windows)."""
    if not _WIN:
        return {}
    result: dict[tuple[str, int], tuple[int, str]] = {}
    try:
        # MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid (6 DWORD)
        for port, pid in _extended_table(_iphlpapi.GetExtendedTcpTable,
                                         _TCP_TABLE_OWNER_PID_ALL, 24, 2, 5):
            result.setdefault(("TCP", port), (pid, _pid_name(pid)))
        # MIB_UDPROW_OWNER_PID: laddr, lport, pid (3 DWORD)
        for port, pid in _extended_table(_iphlpapi.GetExtendedUdpTable,
                                         _UDP_TABLE_OWNER_PID, 12, 1, 2):
            result.setdefault(("UDP", port), (pid, _pid_name(pid)))
    except OSError:
        return result
    return result


# --- reine, testbare Logik ------------------------------------------------- #
def process_for_packet(pkt: Packet, port_map: dict, local_ips: set[str]) -> str:
    """Programmname für ein Paket anhand seines lokalen Ports (oder „")."""
    if pkt.l4 not in ("TCP", "UDP"):
        return ""
    if pkt.src in local_ips:
        local_port = pkt.src_port
    elif pkt.dst in local_ips:
        local_port = pkt.dst_port
    else:
        return ""
    if local_port is None:
        return ""
    entry = port_map.get((pkt.l4, local_port))
    return entry[1] if entry else ""


@dataclass(slots=True)
class ProcStat:
    name: str
    packets: int = 0
    bytes: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0


def aggregate_processes(packets: list[Packet]) -> list[ProcStat]:
    """Aggregiert Volumen je Programm (``pkt.process``); leer → „unbekannt"."""
    table: dict[str, ProcStat] = {}
    for pkt in packets:
        name = pkt.process or "unbekannt"
        s = table.setdefault(name, ProcStat(name))
        s.packets += 1
        s.bytes += pkt.length
        if pkt.direction == DIR_OUT:
            s.tx_bytes += pkt.length
        elif pkt.direction == DIR_IN:
            s.rx_bytes += pkt.length
    return sorted(table.values(), key=lambda s: s.bytes, reverse=True)
