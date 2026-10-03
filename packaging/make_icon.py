"""Erzeugt das NetFett-Icon (``src/netfett/gui/netfett.ico``) mit Qt.

Das Icon enthält mehrere Größen (16–256 px) als PNG-Einträge, damit Windows
in Explorer, Taskleiste und Titelleiste jeweils eine scharfe Variante findet.

Aufruf:  python packaging/make_icon.py
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPen,
)

SIZES = (16, 24, 32, 48, 64, 128, 256)
TARGET = Path(__file__).resolve().parent.parent / "src" / "netfett" / "gui" / "netfett.ico"


def _render(size: int) -> bytes:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    s = size / 256                                  # auf 256er-Raster zeichnen
    p.scale(s, s)

    # Hintergrund: abgerundetes Quadrat mit Blau-Verlauf.
    grad = QLinearGradient(0, 0, 256, 256)
    grad.setColorAt(0, QColor("#1f6feb"))
    grad.setColorAt(1, QColor("#0b2a5b"))
    p.setPen(Qt.NoPen)
    p.setBrush(grad)
    p.drawRoundedRect(QRectF(8, 8, 240, 240), 52, 52)

    # Netzwerk-Graph: Knoten und Kanten.
    nodes = [QPointF(70, 78), QPointF(186, 70), QPointF(128, 140),
             QPointF(62, 190), QPointF(194, 186)]
    edges = [(0, 2), (1, 2), (2, 3), (2, 4), (0, 1), (3, 4)]
    p.setPen(QPen(QColor(255, 255, 255, 170), 12, Qt.SolidLine, Qt.RoundCap))
    for a, b in edges:
        p.drawLine(nodes[a], nodes[b])
    p.setPen(Qt.NoPen)
    for i, n in enumerate(nodes):
        p.setBrush(QColor("#3fb950") if i == 2 else QColor("#ffffff"))
        r = 30 if i == 2 else 22
        p.drawEllipse(n, r, r)
    p.end()

    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return bytes(data)


def write_ico(path: Path) -> None:
    images = [(size, _render(size)) for size in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, png in images:
        dim = 0 if size >= 256 else size            # 0 bedeutet 256 px
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32,
                               len(png), offset + len(blobs))
        blobs += png
    path.write_bytes(header + entries + blobs)


if __name__ == "__main__":
    app = QGuiApplication(sys.argv)
    write_ico(TARGET)
    print(f"Icon geschrieben: {TARGET}")
