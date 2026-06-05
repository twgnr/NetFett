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


def local_ipv6_addresses() -> list[str]:
    """Alle nutzbaren lokalen IPv6-Adressen (ohne Link-local ``fe80::``)."""
    addrs: set[str] = set()
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET6):
            addr = info[4][0].split("%", 1)[0]      # Zone-ID abschneiden
            addrs.add(addr)
    except OSError:
        pass
    primary = primary_ipv6()
    if primary:
        addrs.add(primary)
    # Link-local und „unspezifiziert" verwerfen.
    return sorted(a for a in addrs
                  if not a.lower().startswith("fe80") and a not in ("::", ""))


def primary_ipv6() -> str:
    """Die IPv6-Adresse, über die der Rechner nach außen routet (kein Traffic)."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.connect(("2001:4860:4860::8888", 80))
        return s.getsockname()[0].split("%", 1)[0]
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
