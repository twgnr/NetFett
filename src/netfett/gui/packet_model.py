"""Tabellenmodell der Paketliste (skaliert auf viele tausend Zeilen)."""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor

from ..core.models import DIR_IN, DIR_OUT, Packet

COLUMNS = ["Nr.", "Zeit", "Quelle", "Ziel", "Protokoll", "Länge", "Ri.", "Info"]

# Hintergrundfarbe je Protokoll (Wireshark-ähnliche, dezente Tönung).
_PROTO_BG = {
    "TCP": "#1d2b1d", "TLS": "#16242c", "HTTP": "#2a2410", "DNS": "#26172a",
    "mDNS": "#26172a", "UDP": "#101c2a", "ICMP": "#2a1414", "HTTPS": "#16242c",
}
_DIR_FG = {DIR_OUT: "#ffb454", DIR_IN: "#5aa9ff"}
_DIR_GLYPH = {DIR_OUT: "▲", DIR_IN: "▼"}


class PacketModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._all: list[Packet] = []
        self._view: list[Packet] = []
        self._filter: Callable[[Packet], bool] | None = None
        self._t0: float | None = None

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
        if role == Qt.ForegroundRole and col == 6:
            return QBrush(QColor(_DIR_FG.get(pkt.direction, "#9aa4b2")))
        if role == Qt.BackgroundRole:
            bg = _PROTO_BG.get(pkt.protocol)
            if bg:
                return QBrush(QColor(bg))
        if role == Qt.TextAlignmentRole and col in (0, 5):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None

    def _cell(self, pkt: Packet, col: int) -> str:
        if col == 0:
            return str(pkt.number)
        if col == 1:
            rel = pkt.ts - (self._t0 or pkt.ts)
            return f"{rel:.6f}"
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
        return ""

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

    def set_filter(self, func: Callable[[Packet], bool] | None) -> None:
        self.beginResetModel()
        self._filter = func
        self._view = ([p for p in self._all if func(p)] if func else list(self._all))
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._all.clear()
        self._view.clear()
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
    def shown(self) -> int:
        return len(self._view)
