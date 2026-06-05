"""Offline-Klassifizierung von IP-Adressen – ohne Fremd-Dependencies.

Statt einer (mitzuliefernden) GeoIP-/ASN-Datenbank ordnet dieses Modul Adressen
ihren **Sonderbereichen** (RFC-reserviert, privat, CGNAT, Multicast, Dokumentation
…) zu und erkennt einige **bekannte öffentliche Dienste** (DNS-Resolver) an ihrer
exakten Adresse. Das ist vollständig offline und unit-testbar.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache

# Bekannte öffentliche Dienste (exakte Adressen).
WELL_KNOWN = {
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS", "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "2001:4860:4860::8888": "Google Public DNS",
    "2001:4860:4860::8844": "Google Public DNS",
    "2606:4700:4700::1111": "Cloudflare DNS",
    "2620:fe::fe": "Quad9 DNS",
}

# Sonderbereiche (Reihenfolge: spezifisch vor allgemein).
_SPECIAL = [
    ("0.0.0.0/8", "Dieses Netz"),
    ("10.0.0.0/8", "Privates Netz (LAN)"),
    ("100.64.0.0/10", "CGNAT (Carrier-NAT)"),
    ("127.0.0.0/8", "Loopback"),
    ("169.254.0.0/16", "Link-local"),
    ("172.16.0.0/12", "Privates Netz (LAN)"),
    ("192.0.2.0/24", "Dokumentation (TEST-NET-1)"),
    ("192.168.0.0/16", "Privates Netz (LAN)"),
    ("198.18.0.0/15", "Benchmark"),
    ("198.51.100.0/24", "Dokumentation (TEST-NET-2)"),
    ("203.0.113.0/24", "Dokumentation (TEST-NET-3)"),
    ("224.0.0.0/4", "Multicast"),
    ("240.0.0.0/4", "Reserviert"),
    ("255.255.255.255/32", "Broadcast"),
    ("::1/128", "Loopback"),
    ("::/128", "Unspezifiziert"),
    ("64:ff9b::/96", "NAT64"),
    ("2001:db8::/32", "Dokumentation"),
    ("2002::/16", "6to4"),
    ("fc00::/7", "Privat (ULA)"),
    ("fe80::/10", "Link-local"),
    ("ff00::/8", "Multicast"),
]
_NETWORKS = [(ipaddress.ip_network(cidr), label) for cidr, label in _SPECIAL]


@lru_cache(maxsize=4096)
def classify(ip: str) -> str:
    """Liefert eine kurze Einordnung der Adresse (oder „" bei ungültiger IP)."""
    if ip in WELL_KNOWN:
        return WELL_KNOWN[ip]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for network, label in _NETWORKS:
        if addr.version == network.version and addr in network:
            return label
    return "Öffentlich (Internet)"


def is_public(ip: str) -> bool:
    return classify(ip) == "Öffentlich (Internet)"
