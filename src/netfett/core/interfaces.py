"""Lokale IPv4-Adressen (Netzwerk-Schnittstellen) ermitteln – ohne Fremd-Deps."""
from __future__ import annotations

import socket


def local_ipv4_addresses() -> list[str]:
    """Alle lokalen IPv4-Adressen (für die Schnittstellen-Auswahl)."""
    addrs: set[str] = set()
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    # Primäre Route-Adresse zusätzlich über den UDP-Connect-Trick.
    primary = primary_ipv4()
    if primary:
        addrs.add(primary)
    addrs.discard("0.0.0.0")
    return sorted(addrs, key=_sort_key)


def primary_ipv4() -> str:
    """Die Adresse, über die der Rechner „nach außen" routet (kein Traffic)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def _sort_key(ip: str):
    # 127.* nach hinten, sonst lexikografisch nach Oktetten.
    try:
        parts = tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (9, ip)
    loopback = 1 if parts and parts[0] == 127 else 0
    return (loopback, parts)
