"""Aktiver IP-Scanner: ICMP-Ping-Sweep des lokalen Subnetzes.

Erfordert (wie Ping/Traceroute) einen Raw-Socket und damit Administratorrechte.
Die reine Adress-Berechnung (:func:`subnet_hosts`) ist ohne Netzwerk testbar.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import time
from dataclasses import dataclass

from . import oui
from .mdns import mdns_name
from .netbios import netbios_name
from .snmp import snmp_sysname
from .tools import ICMP_ECHO_REPLY, build_icmp_echo, parse_icmp_reply


@dataclass(slots=True)
class ScannedHost:
    ip: str
    alive: bool
    rtt_ms: float | None = None
    mac: str = ""
    vendor: str = ""
    name: str = ""
    web: str = ""


def subnet_hosts(ip: str, prefix: int = 24, limit: int = 1024) -> list[str]:
    """Alle Host-Adressen im Subnetz von ``ip`` (Standard /24), gedeckelt."""
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return []
    out = []
    for host in net.hosts():
        out.append(str(host))
        if len(out) >= limit:
            break
    return out


def ping_sweep(hosts, timeout: float = 1.0, on_result=None) -> list[ScannedHost]:
    """Pingt alle ``hosts`` (eine Salve) und sammelt die Antworten.

    ``on_result(ip, rtt_ms)`` wird je antwortendem Host aufgerufen (im
    aufrufenden Thread). Benötigt Administratorrechte (Raw-Socket)."""
    ident = os.getpid() & 0xFFFF
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    send_at: dict[str, float] = {}
    alive: dict[str, float] = {}
    try:
        for i, host in enumerate(hosts):
            try:
                sock.sendto(build_icmp_echo(ident, i & 0xFFFF), (host, 0))
                send_at[host] = time.time()
            except OSError:
                continue
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            reply = parse_icmp_reply(data)
            if reply and reply[0] == ICMP_ECHO_REPLY:
                ip = addr[0]
                if ip in send_at and ip not in alive:
                    alive[ip] = (time.time() - send_at[ip]) * 1000.0
                    if on_result is not None:
                        on_result(ip, alive[ip])
    finally:
        sock.close()
    return [ScannedHost(h, h in alive, alive.get(h)) for h in hosts]


_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def probe_web(ip: str, timeout: float = 0.6) -> str:
    """Prüft Port 80/443; bei 80 wird zusätzlich der Seitentitel geholt."""
    for port, scheme in ((80, "http"), (443, "https")):
        try:
            with socket.create_connection((ip, port), timeout) as sock:
                if port == 80:
                    try:
                        sock.sendall(
                            f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                        sock.settimeout(timeout)
                        data = sock.recv(4096)
                        m = _TITLE.search(data)
                        if m:
                            title = m.group(1).decode("latin-1", "replace").strip()
                            return f"http://{ip}/  ({title[:60]})"
                    except OSError:
                        pass
                return f"{scheme}://{ip}/"
        except OSError:
            continue
    return ""


def enrich_host(host: ScannedHost, arp: dict, timeout: float = 0.8) -> ScannedHost:
    """Ergänzt MAC/Hersteller (ARP), Gerätenamen und Web-Adresse.

    Name-Quellen in dieser Reihenfolge: NetBIOS → mDNS/Bonjour → SNMP sysName.
    """
    host.mac = arp.get(host.ip, "")
    host.vendor = oui.vendor(host.mac)
    host.name = (netbios_name(host.ip, timeout)
                 or mdns_name(host.ip, timeout)
                 or snmp_sysname(host.ip, "public", timeout))
    host.web = probe_web(host.ip, min(timeout, 0.6))
    return host
