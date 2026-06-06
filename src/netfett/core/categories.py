"""Einordnung des Verkehrs in Kategorien (Browser, Kommunikation, System …).

Primär anhand des zugeordneten Programms (``pkt.process``), ersatzweise – wenn
kein Programm bekannt ist – anhand des Dienst-Ports. Rein und unit-testbar.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import protocols as P
from .models import DIR_IN, DIR_OUT, Packet

# Programm (Basisname ohne „.exe", klein) → Kategorie. Auch Teil-Treffer.
_PROCESS_CATEGORY: dict[str, str] = {
    # Browser
    "firefox": "Browser", "chrome": "Browser", "msedge": "Browser",
    "opera": "Browser", "brave": "Browser", "vivaldi": "Browser",
    "iexplore": "Browser", "safari": "Browser", "tor": "Browser",
    # Kommunikation / Telefon / Video
    "teams": "Kommunikation", "ms-teams": "Kommunikation",
    "zoom": "Kommunikation", "skype": "Kommunikation", "discord": "Kommunikation",
    "slack": "Kommunikation", "whatsapp": "Kommunikation",
    "signal": "Kommunikation", "telegram": "Kommunikation",
    "webex": "Kommunikation", " webexmta": "Kommunikation",
    "facetime": "Kommunikation",
    # E-Mail
    "outlook": "E-Mail", "thunderbird": "E-Mail", "hxoutlook": "E-Mail",
    "mailbird": "E-Mail", "em client": "E-Mail",
    # Cloud / Synchronisierung
    "dropbox": "Cloud/Sync", "onedrive": "Cloud/Sync",
    "googledrivefs": "Cloud/Sync", "megasync": "Cloud/Sync",
    "nextcloud": "Cloud/Sync", "backupandsync": "Cloud/Sync",
    # Medien / Streaming
    "spotify": "Medien", "vlc": "Medien", "wmplayer": "Medien",
    "itunes": "Medien", "netflix": "Medien", "musik": "Medien",
    # Spiele
    "steam": "Spiele", "epicgameslauncher": "Spiele", "battle.net": "Spiele",
    "leagueclient": "Spiele", "riotclientservices": "Spiele",
    # Entwicklung / Tools
    "code": "Entwicklung", "python": "Entwicklung", "git": "Entwicklung",
    "ssh": "Fernzugriff", "putty": "Fernzugriff", "node": "Entwicklung",
    "docker": "Entwicklung",
    # System / Windows
    "system": "System", "svchost": "System", "services": "System",
    "lsass": "System", "ntoskrnl": "System", "msmpeng": "System",
    "searchapp": "System", "runtimebroker": "System", "wuauclt": "System",
    "backgroundtaskhost": "System", "smartscreen": "System",
    "dashost": "System", "wininit": "System", "spoolsv": "System",
}

# Dienst (aus :func:`protocols.port_app`) → Kategorie (Fallback ohne Programm).
_SERVICE_CATEGORY: dict[str, str] = {
    "HTTP": "Web", "HTTPS": "Web", "HTTP-ALT": "Web", "HTTPS-ALT": "Web",
    "HTTP-PROXY": "Web",
    "DNS": "Netz/System", "DHCP": "Netz/System", "NTP": "Netz/System",
    "mDNS": "Netz/System", "SSDP": "Netz/System", "NETBIOS": "Netz/System",
    "SMB": "Netz/System", "SNMP": "Netz/System", "LDAP": "Netz/System",
    "SMTP": "E-Mail", "SMTPS": "E-Mail", "IMAP": "E-Mail", "IMAPS": "E-Mail",
    "POP3": "E-Mail", "POP3S": "E-Mail",
    "SIP": "Kommunikation",
    "SSH": "Fernzugriff", "RDP": "Fernzugriff", "VNC": "Fernzugriff",
    "TELNET": "Fernzugriff",
}


def _by_process(process: str) -> str:
    if not process:
        return ""
    name = process.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name in _PROCESS_CATEGORY:
        return _PROCESS_CATEGORY[name]
    for key, cat in _PROCESS_CATEGORY.items():     # Teil-Treffer (z. B. „ms-teams")
        if key in name:
            return cat
    return ""


def _by_service(sport: int | None, dport: int | None) -> str:
    for port in (dport, sport):
        if port is None:
            continue
        cat = _SERVICE_CATEGORY.get(P.port_app(port))
        if cat:
            return cat
    return ""


def categorize(process: str = "", sport: int | None = None,
               dport: int | None = None) -> str:
    """Kategorie eines Pakets: erst nach Programm, sonst nach Dienst-Port."""
    return _by_process(process) or _by_service(sport, dport) or "Sonstige"


@dataclass(slots=True)
class CategoryStat:
    name: str
    packets: int = 0
    bytes: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0


def aggregate_categories(packets: list[Packet]) -> list[CategoryStat]:
    """Aggregiert das Volumen je Verkehrs-Kategorie."""
    table: dict[str, CategoryStat] = {}
    for pkt in packets:
        cat = categorize(pkt.process, pkt.src_port, pkt.dst_port)
        s = table.setdefault(cat, CategoryStat(cat))
        s.packets += 1
        s.bytes += pkt.length
        if pkt.direction == DIR_OUT:
            s.tx_bytes += pkt.length
        elif pkt.direction == DIR_IN:
            s.rx_bytes += pkt.length
    return sorted(table.values(), key=lambda s: s.bytes, reverse=True)
