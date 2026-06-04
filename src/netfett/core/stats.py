"""Laufende Statistik: Durchsatz (ein/aus), Pakete/s und Protokollverteilung.

Wird je Sekunde „getaktet" (:meth:`Stats.tick`); die GUI liest danach die
rollenden Fenster für die Graphen aus.
"""
from __future__ import annotations

from collections import deque

from .models import DIR_IN, DIR_OUT, Packet


class Stats:
    def __init__(self, window: int = 60) -> None:
        self.window = window
        # Pro-Sekunden-Akkumulatoren (werden bei tick() in die Historie geschoben).
        self._cur_in_bytes = 0
        self._cur_out_bytes = 0
        self._cur_in_pkts = 0
        self._cur_out_pkts = 0
        # Rollende Historie der letzten `window` Sekunden.
        self.in_bps: deque[int] = deque([0] * window, maxlen=window)
        self.out_bps: deque[int] = deque([0] * window, maxlen=window)
        self.in_pps: deque[int] = deque([0] * window, maxlen=window)
        self.out_pps: deque[int] = deque([0] * window, maxlen=window)
        # Gesamtsummen.
        self.total_packets = 0
        self.total_bytes = 0
        self.total_in_bytes = 0
        self.total_out_bytes = 0
        # Protokoll- und Talker-Verteilung: name -> [pakete, bytes].
        self.proto_counts: dict[str, list[int]] = {}
        self.talkers: dict[str, list[int]] = {}

    def add(self, pkt: Packet) -> None:
        self.total_packets += 1
        self.total_bytes += pkt.length
        if pkt.direction == DIR_OUT:
            self._cur_out_bytes += pkt.length
            self._cur_out_pkts += 1
            self.total_out_bytes += pkt.length
        elif pkt.direction == DIR_IN:
            self._cur_in_bytes += pkt.length
            self._cur_in_pkts += 1
            self.total_in_bytes += pkt.length
        pc = self.proto_counts.setdefault(pkt.protocol or "?", [0, 0])
        pc[0] += 1
        pc[1] += pkt.length
        if pkt.src and pkt.dst:
            key = f"{pkt.src} ⇄ {pkt.dst}"
            tk = self.talkers.setdefault(key, [0, 0])
            tk[0] += 1
            tk[1] += pkt.length

    def tick(self) -> None:
        """Sekundengrenze: aktuelle Akkumulatoren in die Historie schieben."""
        self.in_bps.append(self._cur_in_bytes)
        self.out_bps.append(self._cur_out_bytes)
        self.in_pps.append(self._cur_in_pkts)
        self.out_pps.append(self._cur_out_pkts)
        self._cur_in_bytes = self._cur_out_bytes = 0
        self._cur_in_pkts = self._cur_out_pkts = 0

    def reset(self) -> None:
        self.__init__(self.window)

    def top_protocols(self, limit: int = 12) -> list[tuple[str, int, int]]:
        items = [(n, c[0], c[1]) for n, c in self.proto_counts.items()]
        items.sort(key=lambda x: x[2], reverse=True)
        return items[:limit]

    def top_talkers(self, limit: int = 10) -> list[tuple[str, int, int]]:
        items = [(n, c[0], c[1]) for n, c in self.talkers.items()]
        items.sort(key=lambda x: x[2], reverse=True)
        return items[:limit]
