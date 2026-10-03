"""Eigene, leichtgewichtige Diagramm-Widgets (reiner QPainter, keine Extra-Deps).

* :class:`DonutChart` – Ringdiagramm einer Verteilung (z. B. Protokolle) mit
  Legende und Gesamtwert in der Mitte.
* :class:`BarChart` – horizontale Balken einer Rangliste (z. B. Top-Talkers).

Beide nehmen ihre Daten über ``set_data`` entgegen und zeichnen selbst – im
Stil von :mod:`netfett.gui.graph_widget`.
"""
from __future__ import annotations

import math
from collections.abc import Sequence

from PySide6.QtCore import QPointF, QRect, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from .graph_widget import human
from ..i18n import tr
from .theme import THEME

# Lebhafte Palette für Diagramme (kontrastreich auf dunklem Grund).
PALETTE = ["#5aa9ff", "#ffb454", "#7ee787", "#f778ba", "#a371f7", "#ff7b72",
           "#79c0ff", "#d29922", "#56d364", "#db61a2", "#e3b341", "#8b949e"]

# Feste Farben für gängige Protokolle (sonst Palette nach Reihenfolge).
PROTO_COLORS = {
    "TCP": "#5aa9ff", "TLS": "#56d364", "HTTP": "#ffb454", "HTTPS": "#56d364",
    "DNS": "#a371f7", "mDNS": "#d2a8ff", "UDP": "#79c0ff", "ICMP": "#ff7b72",
    "IGMP": "#f778ba", "ARP": "#e3b341",
}

def _bg() -> QColor:
    return QColor(THEME.bg)


def _text() -> QColor:
    return QColor(THEME.text)


def _muted() -> QColor:
    return QColor(THEME.muted)


def color_for(label: str, index: int) -> QColor:
    """Stabile Farbe für ein Label (feste Protokollfarbe oder Palette)."""
    return QColor(PROTO_COLORS.get(label, PALETTE[index % len(PALETTE)]))


class DonutChart(QWidget):
    """Ringdiagramm einer (Label, Wert)-Verteilung mit Legende.

    Ein Klick auf ein Segment oder einen Legendeneintrag löst ``sliceClicked``
    mit dem jeweiligen Label aus (z. B. zum Setzen eines Filters)."""

    sliceClicked = Signal(str)

    def __init__(self, title: str = "", unit: str = "B", parent=None) -> None:
        super().__init__(parent)
        self._title = title
        self._unit = unit
        self._data: list[tuple[str, int]] = []
        # Trefferflächen für Klicks (je Neuzeichnen aktualisiert).
        self._legend_hits: list[tuple[QRect, str]] = []
        self._slices: list[tuple[str, float, float]] = []   # (label, start°, span°)
        self._cx = self._cy = 0
        self._r_in = self._r_out = 0.0
        self.setMinimumHeight(150)
        self.setCursor(Qt.PointingHandCursor)
        self.setAttribute(Qt.WA_StyledBackground, True)

    def set_data(self, data: Sequence[tuple[str, int]]) -> None:
        """Daten als Folge von (Label, Wert); nicht-positive Werte werden ignoriert."""
        self._data = [(n, v) for n, v in data if v > 0]
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), _bg())

        pad_t = 18 if self._title else 6
        if self._title:
            p.setFont(QFont("Segoe UI", 8, QFont.Bold))
            p.setPen(_text())
            p.drawText(8, 13, self._title)

        total = sum(v for _, v in self._data)
        if total <= 0:
            p.setPen(_muted())
            p.setFont(QFont("Segoe UI", 8))
            p.drawText(self.rect(), Qt.AlignCenter, tr("keine Daten"))
            p.end()
            return

        # Ring links, Legende rechts.
        area_h = h - pad_t - 6
        side = min(area_h, int(w * 0.5))
        ring = max(10, int(side * 0.22))
        cx = 6 + side // 2
        cy = pad_t + area_h // 2
        rect = QRectF(cx - side / 2 + ring / 2, cy - side / 2 + ring / 2,
                      side - ring, side - ring)

        self._slices = []
        self._cx, self._cy = cx, cy
        self._r_out = side / 2
        self._r_in = (side - 2 * ring) / 2
        start = 90 * 16              # bei 12 Uhr beginnen
        for i, (label, value) in enumerate(self._data):
            span = -int(360 * 16 * value / total)   # im Uhrzeigersinn
            pen = QPen(color_for(label, i), ring)
            pen.setCapStyle(Qt.FlatCap)
            p.setPen(pen)
            p.drawArc(rect, start, span)
            self._slices.append((label, start / 16.0, span / 16.0))
            start += span

        # Gesamtwert in der Mitte.
        p.setPen(_text())
        p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.drawText(QRectF(cx - side / 2, cy - 12, side, 16),
                   Qt.AlignCenter, human(total, self._unit))
        p.setPen(_muted())
        p.setFont(QFont("Segoe UI", 7))
        p.drawText(QRectF(cx - side / 2, cy + 4, side, 12),
                   Qt.AlignCenter, tr("gesamt"))

        # Legende.
        lx = 6 + side + 10
        ly = pad_t + 4
        p.setFont(QFont("Segoe UI", 8))
        line_h = 16
        max_rows = max(1, area_h // line_h)
        self._legend_hits = []
        for i, (label, value) in enumerate(self._data[:max_rows]):
            sw = color_for(label, i)
            p.fillRect(lx, ly + 2, 9, 9, sw)
            p.setPen(_text())
            pct = 100 * value / total
            text = f"{tr(label)}  {pct:.0f}%  ({human(value, self._unit)})"
            p.drawText(lx + 14, ly + 10, text)
            self._legend_hits.append((QRect(lx, ly, w - lx, line_h), label))
            ly += line_h
        p.end()

    def mousePressEvent(self, event) -> None:
        pos = event.position().toPoint()
        for rect, label in self._legend_hits:       # erst die Legende
            if rect.contains(pos):
                self.sliceClicked.emit(label)
                return
        if self._r_out > 0:                          # dann die Ringsegmente
            dx = pos.x() - self._cx
            dy = self._cy - pos.y()                   # Bildschirm-y zeigt nach unten
            radius = math.hypot(dx, dy)
            if self._r_in <= radius <= self._r_out:
                theta = math.degrees(math.atan2(dy, dx)) % 360
                for label, start_deg, span_deg in self._slices:
                    if 0 <= (start_deg - theta) % 360 <= -span_deg:
                        self.sliceClicked.emit(label)
                        return
        super().mousePressEvent(event)


class BarChart(QWidget):
    """Horizontale Balken einer (Label, Wert)-Rangliste."""

    def __init__(self, title: str = "", unit: str = "B", parent=None) -> None:
        super().__init__(parent)
        self._title = title
        self._unit = unit
        self._data: list[tuple[str, int]] = []
        self.setMinimumHeight(120)
        self.setAttribute(Qt.WA_StyledBackground, True)

    def set_data(self, data: Sequence[tuple[str, int]]) -> None:
        self._data = [(n, v) for n, v in data if v > 0]
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), _bg())

        pad_t = 18 if self._title else 4
        if self._title:
            p.setFont(QFont("Segoe UI", 8, QFont.Bold))
            p.setPen(_text())
            p.drawText(8, 13, self._title)

        if not self._data:
            p.setPen(_muted())
            p.setFont(QFont("Segoe UI", 8))
            p.drawText(self.rect(), Qt.AlignCenter, tr("keine Daten"))
            p.end()
            return

        peak = max(v for _, v in self._data)
        rows = self._data
        row_h = max(14, min(26, (h - pad_t - 4) // max(1, len(rows))))
        label_w = int(w * 0.40)
        bar_x = 8 + label_w
        bar_w_max = w - bar_x - 8
        fm_font = QFont("Segoe UI", 8)
        p.setFont(fm_font)
        y = pad_t

        for i, (label, value) in enumerate(rows):
            if y + row_h > h:
                break
            color = color_for(label, i)
            # Label links (gekürzt).
            p.setPen(_text())
            elided = _elide(p, tr(label), label_w - 6)
            p.drawText(8, y, label_w - 6, row_h,
                       int(Qt.AlignLeft | Qt.AlignVCenter), elided)
            # Balken.
            bw = max(1, int(bar_w_max * value / peak))
            bar_rect = QRectF(bar_x, y + row_h * 0.18, bw, row_h * 0.64)
            fill = QColor(color)
            fill.setAlpha(200)
            p.fillRect(bar_rect, fill)
            # Wert am Balkenende.
            p.setPen(_muted())
            vtext = human(value, self._unit)
            tw = p.fontMetrics().horizontalAdvance(vtext)
            tx = bar_x + bw + 4
            if tx + tw > w - 2:               # passt nicht dahinter -> in den Balken
                tx = bar_x + bw - tw - 4
                p.setPen(_bg())
            p.drawText(int(tx), y, tw + 8, row_h,
                       int(Qt.AlignLeft | Qt.AlignVCenter), vtext)
            y += row_h
        p.end()


class MultiLineChart(QWidget):
    """Mehrere Zeitreihen als farbige Linien mit Legende (z. B. je Programm)."""

    def __init__(self, title: str = "", unit: str = "B/s", parent=None) -> None:
        super().__init__(parent)
        self._title = title
        self._unit = unit
        self._series: dict[str, list[int]] = {}
        self.setMinimumHeight(120)
        self.setAttribute(Qt.WA_StyledBackground, True)

    def set_series(self, series: dict) -> None:
        self._series = {k: list(v) for k, v in series.items()}
        self.update()

    @staticmethod
    def _color(label: str) -> QColor:
        # Deterministische Farbe je Label (stabil innerhalb der Sitzung).
        return QColor(PALETTE[sum(label.encode()) % len(PALETTE)])

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), _bg())

        pad_t = 18 if self._title else 6
        if self._title:
            p.setFont(QFont("Segoe UI", 8, QFont.Bold))
            p.setPen(_text())
            p.drawText(8, 13, self._title)

        gx, gy = 8, pad_t
        gw, gh = max(1, w - 16), max(1, h - pad_t - 6)
        peak = max([1, *(v for vals in self._series.values() for v in vals)])

        grid = QColor(THEME.grid)
        p.setFont(QFont("Segoe UI", 7))
        for frac in (0.0, 0.5, 1.0):
            y = gy + gh - gh * frac
            p.setPen(QPen(grid, 1))
            p.drawLine(int(gx), int(y), int(gx + gw), int(y))
            p.setPen(_muted())
            p.drawText(int(gx + 2), int(y - 2), human(peak * frac, self._unit))

        legend_y = pad_t
        for label, vals in self._series.items():
            color = self._color(label)
            if len(vals) >= 2:
                step = gw / (len(vals) - 1)
                pts = [QPointF(gx + i * step, gy + gh - (v / peak) * gh)
                       for i, v in enumerate(vals)]
                p.setPen(QPen(color, 1.5))
                for a, b in zip(pts, pts[1:]):
                    p.drawLine(a, b)
            # Legende rechts oben.
            text = _elide_str(tr(label), 18)
            p.fillRect(w - 130, legend_y, 8, 8, color)
            p.setPen(_text())
            p.setFont(QFont("Segoe UI", 7))
            p.drawText(w - 118, legend_y + 8, text)
            legend_y += 13
        p.end()


def _elide_str(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n - 1] + "…"


def _elide(p: QPainter, text: str, width: int) -> str:
    fm = p.fontMetrics()
    if fm.horizontalAdvance(text) <= width:
        return text
    return fm.elidedText(text, Qt.ElideMiddle, width)
