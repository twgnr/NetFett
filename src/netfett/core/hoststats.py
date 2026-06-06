"""Laufende Durchsatz-Statistik **pro Host-IP** (für die Geräte-Übersicht).

Je IP werden gesendete/empfangene Bytes als rollende Sekunden-Historie geführt –
analog zu :mod:`netfett.core.stats`, aber getrennt nach Gerät. „gesendet"
bedeutet: die IP war Quelle; „empfangen": die IP war Ziel.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .models import Packet


@dataclass(slots=True)
class HostSeries:
    ip: str
    in_bps: deque = field(default_factory=lambda: deque([0] * 60, maxlen=60))
    out_bps: deque = field(default_factory=lambda: deque([0] * 60, maxlen=60))
    total_in: int = 0
    total_out: int = 0
    packets: int = 0
    _cur_in: int = 0
    _cur_out: int = 0

    @property
    def total(self) -> int:
        return self.total_in + self.total_out


class HostMonitor:
    def __init__(self, window: int = 60) -> None:
        self.window = window
        self._hosts: dict[str, HostSeries] = {}

    def add(self, pkt: Packet) -> None:
        if pkt.src:
            h = self._host(pkt.src)
            h._cur_out += pkt.length
            h.total_out += pkt.length
            h.packets += 1
        if pkt.dst:
            h = self._host(pkt.dst)
            h._cur_in += pkt.length
            h.total_in += pkt.length
            h.packets += 1

    def _host(self, ip: str) -> HostSeries:
        h = self._hosts.get(ip)
        if h is None:
            h = HostSeries(ip, deque([0] * self.window, maxlen=self.window),
                           deque([0] * self.window, maxlen=self.window))
            self._hosts[ip] = h
        return h

    def tick(self) -> None:
        """Sekundengrenze: aktuelle Akkumulatoren in die Historie schieben."""
        for h in self._hosts.values():
            h.in_bps.append(h._cur_in)
            h.out_bps.append(h._cur_out)
            h._cur_in = h._cur_out = 0

    def get(self, ip: str) -> HostSeries | None:
        return self._hosts.get(ip)

    def ensure(self, ip: str) -> HostSeries:
        """Legt (z. B. für ein gescanntes Gerät ohne Verkehr) einen Eintrag an."""
        return self._host(ip)

    def hosts(self) -> list[HostSeries]:
        """Alle Hosts, nach Gesamtvolumen absteigend."""
        return sorted(self._hosts.values(), key=lambda h: h.total, reverse=True)

    def clear(self) -> None:
        self._hosts.clear()
