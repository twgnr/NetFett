"""Tabellenmodell der Paketliste (skaliert auf viele tausend Zeilen)."""
from __future__ import annotations

import datetime
from collections.abc import Callable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor, QFont

from ..core.models import DIR_IN, DIR_OUT, Packet
from .theme import THEME

COLUMNS = ["Nr.", "Zeit", "Quelle", "Ziel", "Protokoll", "Länge", "Ri.",
           "Info", "Name", "Programm"]
NAME_COL = COLUMNS.index("Name")
PROC_COL = COLUMNS.index("Programm")

# Hintergrundfarbe je Protokoll (Wireshark-ähnliche, dezente Tönung).
_PROTO_BG = {
    "TCP": "#1d2b1d", "TLS": "#16242c", "HTTP": "#2a2410", "DNS": "#26172a",
    "mDNS": "#26172a", "UDP": "#101c2a", "ICMP": "#2a1414", "HTTPS": "#16242c",
}
_DIR_FG = {DIR_OUT: "#ffb454", DIR_IN: "#5aa9ff"}
_DIR_GLYPH = {DIR_OUT: "▲", DIR_IN: "▼"}
_MARK_BG = "#3a2f0a"          # Hintergrund markierter Zeilen (amber)
_NO_MATCH = object()          # Sentinel: „Regeln geprüft, kein Treffer"

# Zeitdarstellung: relativ zum ersten Paket, Tageszeit, oder absolut (Epoch).
TIME_REL, TIME_OFDAY, TIME_ABS = "rel", "tod", "abs"


class PacketModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._all: list[Packet] = []
        self._view: list[Packet] = []
        self._filter: Callable[[Packet], bool] | None = None
        self._t0: float | None = None
        self._marked: set[int] = set()      # markierte Paketnummern
        self._time_mode: str = TIME_REL
        self._max: int = 0                   # Ringpuffer-Grenze (0 = unbegrenzt)
        self._name_provider = None           # Callable[str, str|None] für Reverse-DNS
        self._rules = None                   # RuleSet für Einfärbe-Regeln
        self._rule_cache: dict[int, object] = {}
        self._expert: dict[int, str] = {}    # Paketnummer → TCP-Expert-Flag
        self._comments: dict[int, str] = {}  # Paketnummer → Kommentar

    # --- Qt-Schnittstelle --------------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._view)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        pkt = self._view[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            return self._cell(pkt, col)
        if role == Qt.ForegroundRole:
            rc = self._rule_colors(pkt)
            if rc and rc[0]:
                return QBrush(QColor(rc[0]))
            if col == 6:
                return QBrush(QColor(_DIR_FG.get(pkt.direction, "#9aa4b2")))
        if role == Qt.BackgroundRole:
            if pkt.number in self._marked:          # Markierung hat Vorrang
                return QBrush(QColor(_MARK_BG if THEME.dark else "#fff8c5"))
            rc = self._rule_colors(pkt)
            if rc and rc[1]:
                return QBrush(QColor(rc[1]))
            if pkt.number in self._expert:          # TCP-Auffälligkeit
                return QBrush(QColor("#3a2a10" if THEME.dark else "#fff1c2"))
            if THEME.dark:                          # dezente Tönung nur im Dunkeln
                bg = _PROTO_BG.get(pkt.protocol)
                if bg:
                    return QBrush(QColor(bg))
        if role == Qt.FontRole and pkt.number in self._marked:
            f = QFont()
            f.setBold(True)
            return f
        if role == Qt.ToolTipRole:
            tips = []
            if pkt.number in self._expert:
                tips.append(f"TCP: {self._expert[pkt.number]}")
            if pkt.number in self._comments:
                tips.append(f"💬 {self._comments[pkt.number]}")
            return "\n".join(tips) or None
        if role == Qt.TextAlignmentRole and col in (0, 5):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None

    def _cell(self, pkt: Packet, col: int) -> str:
        if col == 0:
            return str(pkt.number)
        if col == 1:
            return self._format_time(pkt)
        if col == 2:
            return pkt.src + (f":{pkt.src_port}" if pkt.src_port else "")
        if col == 3:
            return pkt.dst + (f":{pkt.dst_port}" if pkt.dst_port else "")
        if col == 4:
            return pkt.protocol
        if col == 5:
            return str(pkt.length)
        if col == 6:
            return _DIR_GLYPH.get(pkt.direction, "·")
        if col == 7:
            return pkt.info
        if col == NAME_COL:
            if self._name_provider is None:
                return ""
            return self._name_provider(self._remote_ip(pkt)) or ""
        if col == PROC_COL:
            return pkt.process
        return ""

    @staticmethod
    def _remote_ip(pkt: Packet) -> str:
        """Die nicht-lokale Gegenstelle des Pakets (für die Namensauflösung)."""
        if pkt.direction == DIR_OUT:
            return pkt.dst
        if pkt.direction == DIR_IN:
            return pkt.src
        return pkt.dst

    def _format_time(self, pkt: Packet) -> str:
        if self._time_mode == TIME_ABS:
            return f"{pkt.ts:.6f}"
        if self._time_mode == TIME_OFDAY:
            dt = datetime.datetime.fromtimestamp(pkt.ts)
            return dt.strftime("%H:%M:%S.") + f"{dt.microsecond:06d}"
        rel = pkt.ts - (self._t0 or pkt.ts)
        return f"{rel:.6f}"

    # --- Zeitformat & Markierungen ----------------------------------------
    def set_time_mode(self, mode: str) -> None:
        if mode == self._time_mode or mode not in (TIME_REL, TIME_OFDAY, TIME_ABS):
            return
        self._time_mode = mode
        if self._view:
            self.dataChanged.emit(self.index(0, 1),
                                  self.index(len(self._view) - 1, 1),
                                  [Qt.DisplayRole])

    @property
    def time_mode(self) -> str:
        return self._time_mode

    def toggle_mark(self, row: int) -> None:
        if not 0 <= row < len(self._view):
            return
        num = self._view[row].number
        self._marked.discard(num) if num in self._marked else self._marked.add(num)
        self.dataChanged.emit(self.index(row, 0),
                              self.index(row, self.columnCount() - 1))

    def set_expert_flags(self, flags: dict) -> None:
        self._expert = dict(flags)
        self._repaint_all()

    @property
    def expert_count(self) -> int:
        return len(self._expert)

    def set_comment(self, number: int, text: str) -> None:
        if text:
            self._comments[number] = text
        else:
            self._comments.pop(number, None)
        self._repaint_all()

    def comment(self, number: int) -> str:
        return self._comments.get(number, "")

    @property
    def comments(self) -> dict:
        return dict(self._comments)

    def _repaint_all(self) -> None:
        if self._view:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(len(self._view) - 1,
                                             self.columnCount() - 1))

    def add_marks(self, numbers) -> None:
        """Markiert die angegebenen Paketnummern (z. B. IOC-Treffer)."""
        self._marked.update(numbers)
        if self._view:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(len(self._view) - 1,
                                             self.columnCount() - 1))

    def clear_marks(self) -> None:
        if not self._marked:
            return
        self._marked.clear()
        if self._view:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(len(self._view) - 1,
                                             self.columnCount() - 1))

    def next_marked_row(self, start: int) -> int:
        """Erste markierte Zeile ab ``start`` (mit Umlauf) oder -1."""
        n = len(self._view)
        if not self._marked or n == 0:
            return -1
        start = max(0, start)
        for row in list(range(start, n)) + list(range(0, start)):
            if self._view[row].number in self._marked:
                return row
        return -1

    @property
    def marked_count(self) -> int:
        return len(self._marked)

    # --- Daten/Filter ------------------------------------------------------
    def add_batch(self, batch: list[Packet]) -> None:
        if not batch:
            return
        if self._t0 is None:
            self._t0 = batch[0].ts
        self._all.extend(batch)
        passing = [p for p in batch if self._filter is None or self._filter(p)]
        if passing:
            start = len(self._view)
            self.beginInsertRows(QModelIndex(), start, start + len(passing) - 1)
            self._view.extend(passing)
            self.endInsertRows()
        self._enforce_limit()

    def set_max_packets(self, n: int) -> None:
        """Ringpuffer-Grenze: max. Pakete im Speicher (0 = unbegrenzt)."""
        self._max = max(0, int(n))
        self._enforce_limit()

    @property
    def max_packets(self) -> int:
        return self._max

    # --- Einfärbe-Regeln ---------------------------------------------------
    def set_color_rules(self, ruleset) -> None:
        self._rules = ruleset
        self._rule_cache.clear()
        if self._view:
            self.dataChanged.emit(self.index(0, 0),
                                  self.index(len(self._view) - 1,
                                             self.columnCount() - 1))

    def _rule_colors(self, pkt: Packet):
        if self._rules is None:
            return None
        cached = self._rule_cache.get(pkt.number)
        if cached is not None:
            return None if cached is _NO_MATCH else cached
        res = self._rules.match(pkt)
        self._rule_cache[pkt.number] = res if res is not None else _NO_MATCH
        return res

    # --- Reverse-DNS-Spalte ------------------------------------------------
    def set_name_provider(self, provider) -> None:
        """Setzt die Funktion ``ip -> Name|None`` für die Namensspalte."""
        self._name_provider = provider

    def remote_ips(self) -> set[str]:
        """Alle nicht-lokalen Gegenstellen-IPs (für die Auflösung)."""
        return {ip for ip in (self._remote_ip(p) for p in self._all) if ip}

    def refresh_names(self) -> None:
        if self._view:
            self.dataChanged.emit(self.index(0, NAME_COL),
                                  self.index(len(self._view) - 1, NAME_COL),
                                  [Qt.DisplayRole])

    def _enforce_limit(self) -> None:
        """Verwirft die ältesten Pakete, sobald die Grenze überschritten ist."""
        if self._max <= 0 or len(self._all) <= self._max:
            return
        overflow = len(self._all) - self._max
        dropped_ids = {id(p) for p in self._all[:overflow]}
        del self._all[:overflow]
        # Aus der (geordneten) Ansicht die betroffenen vordersten Zeilen lösen.
        k = 0
        while k < len(self._view) and id(self._view[k]) in dropped_ids:
            k += 1
        if k:
            self.beginRemoveRows(QModelIndex(), 0, k - 1)
            del self._view[:k]
            self.endRemoveRows()

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:
        """Sortiert die aktuelle Ansicht nach einer Spalte (Auswahl bleibt)."""
        key = self._sort_key(column)
        if key is None or not self._view:
            return
        self.layoutAboutToBeChanged.emit()
        old = [(idx, self._view[idx.row()]) for idx in self.persistentIndexList()]
        self._view.sort(key=key, reverse=(order == Qt.DescendingOrder))
        pos = {id(p): r for r, p in enumerate(self._view)}
        self.changePersistentIndexList(
            [idx for idx, _p in old],
            [self.index(pos[id(p)], idx.column()) for idx, p in old])
        self.layoutChanged.emit()

    def _sort_key(self, col: int):
        keys = {
            0: lambda p: p.number,
            1: lambda p: p.ts,
            2: lambda p: (p.src, p.src_port or 0),
            3: lambda p: (p.dst, p.dst_port or 0),
            4: lambda p: p.protocol,
            5: lambda p: p.length,
            6: lambda p: p.direction,
            7: lambda p: p.info,
        }
        if col == NAME_COL:
            prov = self._name_provider
            return (lambda p: (prov(self._remote_ip(p)) or "")) if prov \
                else (lambda p: "")
        if col == PROC_COL:
            return lambda p: p.process
        return keys.get(col)

    def set_filter(self, func: Callable[[Packet], bool] | None) -> None:
        self.beginResetModel()
        self._filter = func
        self._view = ([p for p in self._all if func(p)] if func else list(self._all))
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._all.clear()
        self._view.clear()
        self._marked.clear()
        self._rule_cache.clear()
        self._expert.clear()
        self._comments.clear()
        self._t0 = None
        self.endResetModel()

    def packet_at(self, row: int) -> Packet | None:
        if 0 <= row < len(self._view):
            return self._view[row]
        return None

    @property
    def all_packets(self) -> list[Packet]:
        return self._all

    @property
    def view_packets(self) -> list[Packet]:
        """Aktuell sichtbare (gefilterte) Pakete (Kopie)."""
        return list(self._view)

    @property
    def shown(self) -> int:
        return len(self._view)
