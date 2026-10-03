"""IOC-/Threat-Abgleich gegen eine Offline-Blockliste (IPs, CIDRs, Domains).

Liest eine einfache Textdatei (eine Angabe je Zeile, ``#`` = Kommentar) und
gleicht Pakete dagegen ab: IP/Netz gegen Quelle/Ziel, Domain (Suffix) gegen die
kontaktierte Domain. Rein und unit-testbar.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..i18n import tr
from .analyze import Finding, SEV_ERROR
from .models import Packet


@dataclass(slots=True)
class IocSet:
    ips: set[str] = field(default_factory=set)
    nets: list = field(default_factory=list)        # ip_network-Objekte
    domains: set[str] = field(default_factory=set)   # Suffixe, klein

    @classmethod
    def from_text(cls, text: str) -> "IocSet":
        s = cls()
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if "/" in line:
                try:
                    s.nets.append(ipaddress.ip_network(line, strict=False))
                    continue
                except ValueError:
                    pass
            try:
                ipaddress.ip_address(line)
                s.ips.add(line)
            except ValueError:
                s.domains.add(line.lower().lstrip("."))
        return s

    def __bool__(self) -> bool:
        return bool(self.ips or self.nets or self.domains)

    def _ip_hit(self, ip: str) -> str:
        if ip in self.ips:
            return ip
        if self.nets:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return ""
            for net in self.nets:
                if addr.version == net.version and addr in net:
                    return str(net)
        return ""

    def _domain_hit(self, domain: str) -> str:
        if not domain:
            return ""
        d = domain.lower()
        for suffix in self.domains:
            if d == suffix or d.endswith("." + suffix):
                return suffix
        return ""

    def match(self, pkt: Packet) -> str:
        """Liefert den getroffenen Indikator (oder „")."""
        return (self._ip_hit(pkt.src) or self._ip_hit(pkt.dst)
                or self._domain_hit(pkt.domain))


def ioc_findings(packets: list[Packet], iocs: IocSet) -> list[Finding]:
    """Erzeugt Experten-Befunde für alle Pakete, die einen IOC treffen."""
    out: list[Finding] = []
    for pkt in packets:
        hit = iocs.match(pkt)
        if hit:
            out.append(Finding(
                SEV_ERROR, "IOC",
                tr("Treffer auf {hit}: {src} → {dst}").format(
                    hit=hit, src=pkt.src, dst=pkt.dst)
                + (f" ({pkt.domain})" if pkt.domain else ""),
                pkt.number))
    return out
