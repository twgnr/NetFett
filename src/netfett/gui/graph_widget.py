"""Live-Graph (eigener QPainter): zwei überlagerte Flächen für ein/aus."""
from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from .theme import THEME


def human(n: float, unit: str = "B") -> str:
    f = float(n)
    for pre in ("", "K", "M", "G", "T"):
        if f < 1024 or pre == "T":
            return f"{f:.0f} {pre}{unit}" if pre == "" else f"{f:.1f} {pre}{unit}"
        f /= 1024
    return f"{f:.1f} T{unit}"


class GraphWidget(QWidget):
    """Zeichnet zwei Zeitreihen (eingehend/ausgehend) als gefüllte Kurven."""

    IN_COLOR = QColor("#5aa9ff")
    OUT_COLOR = QColor("#ffb454")

    def __init__(self, title: str, unit: str = "B/s", parent=None) -> None:
        super().__init__(parent)
        self._title = title
        self._unit = unit
        self._in: Sequence[int] = []
        self._out: Sequence[int] = []
        self.setMinimumHeight(120)
        self.setAttribute(Qt.WA_StyledBackground, True)

    def set_series(self, in_seq: Sequence[int], out_seq: Sequence[int]) -> None:
        self._in = list(in_seq)
        self._out = list(out_seq)
        self.update()

    def set_title(self, title: str) -> None:
        self._title = title
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), QColor(THEME.bg))

        pad_l, pad_t, pad_b, pad_r = 8, 22, 18, 8
        gx, gy = pad_l, pad_t
        gw, gh = max(1, w - pad_l - pad_r), max(1, h - pad_t - pad_b)

        peak = max([1, *self._in, *self._out])
        # Gitterlinien + y-Beschriftung
        grid = QColor(THEME.grid)
        p.setFont(QFont("Segoe UI", 7))
        for frac in (0.0, 0.5, 1.0):
            y = gy + gh - gh * frac
            p.setPen(QPen(grid, 1))
            p.drawLine(int(gx), int(y), int(gx + gw), int(y))
            p.setPen(QColor(THEME.muted))
            p.drawText(int(gx + 2), int(y - 2), human(peak * frac, self._unit))

        self._draw_series(p, self._out, gx, gy, gw, gh, peak, self.OUT_COLOR)
        self._draw_series(p, self._in, gx, gy, gw, gh, peak, self.IN_COLOR)

        # Titel + aktuelle Werte (letzter Wert der Reihe)
        cur_in = self._in[-1] if self._in else 0
        cur_out = self._out[-1] if self._out else 0
        p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        p.setPen(QColor(THEME.text))
        p.drawText(int(gx), 14, self._title)
        p.setFont(QFont("Segoe UI", 8))
        legend = f"▼ {human(cur_in, self._unit)}    ▲ {human(cur_out, self._unit)}"
        p.setPen(QColor(THEME.muted))
        p.drawText(w - pad_r - p.fontMetrics().horizontalAdvance(legend), 14, legend)
        p.end()

    def _draw_series(self, p, series, gx, gy, gw, gh, peak, color) -> None:
        if not series:
            return
        n = len(series)
        step = gw / max(1, n - 1)
        path = QPainterPath()
        path.moveTo(gx, gy + gh)
        for i, v in enumerate(series):
            x = gx + i * step
            y = gy + gh - (v / peak) * gh
            path.lineTo(x, y)
        path.lineTo(gx + (n - 1) * step, gy + gh)
        path.closeSubpath()

        grad = QLinearGradient(0, gy, 0, gy + gh)
        fill = QColor(color)
        fill.setAlpha(90)
        grad.setColorAt(0.0, fill)
        end = QColor(color)
        end.setAlpha(10)
        grad.setColorAt(1.0, end)
        p.fillPath(path, grad)

        p.setPen(QPen(color, 1.5))
        pts = [QPointF(gx + i * step, gy + gh - (v / peak) * gh)
               for i, v in enumerate(series)]
        for a, b in zip(pts, pts[1:]):
            p.drawLine(a, b)
