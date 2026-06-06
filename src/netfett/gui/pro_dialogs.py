"""Profi-Dialoge: Einfärbe-Regeln, IO-Graph, IOC-Abgleich, Topologie."""
from __future__ import annotations

import math

from PySide6.QtCore import QPoint, QPointF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor, QFont, QImage, QPainter, QPen, QPixmap, QPolygonF,
)
from PySide6.QtWidgets import (
    QCheckBox, QColorDialog, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QGridLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox,
    QPlainTextEdit, QPushButton, QScrollArea, QSplitter, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..core.analyze import io_timeline, tcp_trace
from ..core.coloring import ColorRule
from ..core.displayfilter import FilterError, compile_filter
from ..core.extract import suggest_filename
from ..core.ioc import IocSet, ioc_findings
from .charts import MultiLineChart
from .graph_widget import human
from .theme import THEME

_MONO = QFont("Consolas", 9)
_SEV_COLOR = {"info": "#8b949e", "note": "#58a6ff", "warn": "#d29922",
              "error": "#f85149"}


# --------------------------------------------------------------------------- #
class RuleEditDialog(QDialog):
    """Bearbeitet eine einzelne Einfärbe-Regel."""

    def __init__(self, rule: ColorRule, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Regel bearbeiten")
        self.resize(420, 200)
        self._fg = rule.fg
        self._bg = rule.bg
        grid = QGridLayout(self)
        grid.addWidget(QLabel("Name:"), 0, 0)
        self.name = QLineEdit(rule.name, self)
        grid.addWidget(self.name, 0, 1, 1, 2)
        grid.addWidget(QLabel("Filter:"), 1, 0)
        self.filter = QLineEdit(rule.filter_text, self)
        self.filter.setPlaceholderText("z. B.  tcp dst port 443")
        grid.addWidget(self.filter, 1, 1, 1, 2)

        self.chk_bg = QCheckBox("Hintergrund", self)
        self.chk_bg.setChecked(bool(rule.bg))
        self.btn_bg = QPushButton("Farbe…", self)
        self.btn_bg.clicked.connect(lambda: self._pick("bg"))
        grid.addWidget(self.chk_bg, 2, 0)
        grid.addWidget(self.btn_bg, 2, 1)
        self.chk_fg = QCheckBox("Schriftfarbe", self)
        self.chk_fg.setChecked(bool(rule.fg))
        self.btn_fg = QPushButton("Farbe…", self)
        self.btn_fg.clicked.connect(lambda: self._pick("fg"))
        grid.addWidget(self.chk_fg, 3, 0)
        grid.addWidget(self.btn_fg, 3, 1)
        self._swatches()

        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        grid.addWidget(box, 4, 0, 1, 3)

    def _pick(self, which: str) -> None:
        start = QColor(getattr(self, f"_{which}") or "#888888")
        col = QColorDialog.getColor(start, self, "Farbe wählen")
        if col.isValid():
            setattr(self, f"_{which}", col.name())
            (self.chk_bg if which == "bg" else self.chk_fg).setChecked(True)
            self._swatches()

    def _swatches(self) -> None:
        self.btn_bg.setStyleSheet(f"background:{self._bg or '#444'};")
        self.btn_fg.setStyleSheet(f"background:{self._fg or '#444'};")

    def result_rule(self) -> ColorRule:
        return ColorRule(
            self.name.text().strip() or "Regel", self.filter.text().strip(),
            self._fg if self.chk_fg.isChecked() else "",
            self._bg if self.chk_bg.isChecked() else "", True)


class ColoringRulesDialog(QDialog):
    """Liste der Einfärbe-Regeln mit Editor und Reihenfolge."""

    def __init__(self, rules: list[ColorRule], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Einfärbe-Regeln")
        self.resize(560, 420)
        self._rules = [ColorRule(r.name, r.filter_text, r.fg, r.bg, r.enabled)
                       for r in rules]
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Erste passende Regel bestimmt die Farbe "
                             "(von oben nach unten)."))
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Aktiv", "Name", "Filter"])
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        self.tree.itemChanged.connect(self._on_item_changed)
        self.tree.itemDoubleClicked.connect(lambda *_: self._edit())
        lay.addWidget(self.tree)

        row = QHBoxLayout()
        for label, slot in (("Neu", self._new), ("Bearbeiten", self._edit),
                            ("Entfernen", self._remove), ("▲", self._up),
                            ("▼", self._down)):
            b = QPushButton(label, self)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addWidget(box)
        self._rebuild()

    def _rebuild(self) -> None:
        self.tree.blockSignals(True)
        self.tree.clear()
        for r in self._rules:
            it = QTreeWidgetItem(["", r.name, r.filter_text])
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(0, Qt.Checked if r.enabled else Qt.Unchecked)
            if r.bg:
                it.setBackground(1, QColor(r.bg))
            if r.fg:
                it.setForeground(1, QColor(r.fg))
            self.tree.addTopLevelItem(it)
        self.tree.blockSignals(False)
        for c in range(3):
            self.tree.resizeColumnToContents(c)

    def _on_item_changed(self, item, _col) -> None:
        row = self.tree.indexOfTopLevelItem(item)
        if 0 <= row < len(self._rules):
            self._rules[row].enabled = item.checkState(0) == Qt.Checked

    def _sel(self) -> int:
        items = self.tree.selectedItems()
        return self.tree.indexOfTopLevelItem(items[0]) if items else -1

    def _new(self) -> None:
        dlg = RuleEditDialog(ColorRule("Neue Regel", "", bg="#2a2a10"), self)
        if dlg.exec():
            self._rules.append(dlg.result_rule())
            self._rebuild()

    def _edit(self) -> None:
        i = self._sel()
        if i < 0:
            return
        dlg = RuleEditDialog(self._rules[i], self)
        if dlg.exec():
            self._rules[i] = dlg.result_rule()
            self._rebuild()

    def _remove(self) -> None:
        i = self._sel()
        if i >= 0:
            del self._rules[i]
            self._rebuild()

    def _up(self) -> None:
        i = self._sel()
        if i > 0:
            self._rules[i - 1], self._rules[i] = self._rules[i], self._rules[i - 1]
            self._rebuild()
            self.tree.setCurrentItem(self.tree.topLevelItem(i - 1))

    def _down(self) -> None:
        i = self._sel()
        if 0 <= i < len(self._rules) - 1:
            self._rules[i + 1], self._rules[i] = self._rules[i], self._rules[i + 1]
            self._rebuild()
            self.tree.setCurrentItem(self.tree.topLevelItem(i + 1))

    def result_rules(self) -> list[ColorRule]:
        return self._rules


# --------------------------------------------------------------------------- #
class IoGraphDialog(QDialog):
    """Globaler IO-Verlauf mit mehreren Filter-Linien."""

    def __init__(self, model, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("IO-Graph")
        self.resize(820, 560)
        self._model = model
        lay = QVBoxLayout(self)

        self.chart = MultiLineChart("Durchsatz", "B/s", self)
        self.chart.setMinimumHeight(220)
        lay.addWidget(self.chart, 1)

        grid = QGridLayout()
        grid.addWidget(QLabel("Filter-Linien (leer = alles):"), 0, 0, 1, 2)
        self._edits: list[QLineEdit] = []
        for i in range(5):
            e = QLineEdit(self)
            e.setPlaceholderText(f"Filter {i + 1}, z. B. tcp / dns / host 1.1.1.1")
            e.returnPressed.connect(self._refresh)
            grid.addWidget(e, i + 1, 0, 1, 2)
            self._edits.append(e)
        if self._edits:
            self._edits[0].setText("")
        lay.addLayout(grid)

        row = QHBoxLayout()
        row.addWidget(QLabel("Einheit:"))
        self.metric = QComboBox(self)
        self.metric.addItems(["Bytes/s", "Pakete/s"])
        self.metric.currentIndexChanged.connect(self._refresh)
        row.addWidget(self.metric)
        btn = QPushButton("Aktualisieren", self)
        btn.clicked.connect(self._refresh)
        row.addWidget(btn)
        row.addStretch(1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        row.addWidget(close)
        lay.addLayout(row)

        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()
        self._refresh()

    def _refresh(self) -> None:
        labels, preds = [], []
        for e in self._edits:
            text = e.text().strip()
            if not text:
                continue
            try:
                preds.append(compile_filter(text))
                labels.append(text)
                e.setStyleSheet("")
            except FilterError:
                e.setStyleSheet("background:#3a1414;")
        if not preds:
            preds = [None]
            labels = ["Alle"]
        by_pkt = self.metric.currentIndex() == 1
        self.chart._unit = "P/s" if by_pkt else "B/s"
        _n, series = io_timeline(self._model.all_packets, preds,
                                 by_packets=by_pkt)
        self.chart.set_series({labels[i]: series[i] for i in range(len(labels))})

    def closeEvent(self, event) -> None:
        self._timer.stop()
        super().closeEvent(event)


# --------------------------------------------------------------------------- #
class IocDialog(QDialog):
    """IOC-Abgleich gegen eine geladene Blockliste."""
    jumpToPacket = Signal(int)
    markRequested = Signal(set)

    def __init__(self, packets, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("IOC-Abgleich")
        self.resize(760, 460)
        self._packets = packets
        self._findings = []
        lay = QVBoxLayout(self)

        row = QHBoxLayout()
        self.btn_load = QPushButton("Blockliste laden…", self)
        self.btn_load.clicked.connect(self._load)
        row.addWidget(self.btn_load)
        self.info = QLabel("Liste laden (eine IP/CIDR/Domain je Zeile, # = "
                           "Kommentar).")
        row.addWidget(self.info, 1)
        lay.addLayout(row)

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Schwere", "Indikator/Beschreibung", "Paket"])
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        self.tree.itemDoubleClicked.connect(self._double)
        lay.addWidget(self.tree)

        row2 = QHBoxLayout()
        self.btn_mark = QPushButton("Treffer markieren", self)
        self.btn_mark.setEnabled(False)
        self.btn_mark.clicked.connect(self._mark)
        row2.addWidget(self.btn_mark)
        row2.addStretch(1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        row2.addWidget(close)
        lay.addLayout(row2)

    def _load(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Blockliste laden", "",
            "Textdateien (*.txt *.ioc *.csv);;Alle Dateien (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                iocs = IocSet.from_text(f.read())
        except OSError as exc:
            QMessageBox.critical(self, "NetFett – Fehler", str(exc))
            return
        if not iocs:
            QMessageBox.information(self, "NetFett", "Keine Indikatoren gefunden.")
            return
        self._findings = ioc_findings(self._packets, iocs)
        self._show()

    def _show(self) -> None:
        self.tree.clear()
        for f in self._findings:
            it = QTreeWidgetItem([f.severity.upper(), f.summary,
                                  str(f.packet) if f.packet else "—"])
            it.setForeground(0, QColor(_SEV_COLOR.get(f.severity, "#c9d1d9")))
            it.setData(0, Qt.UserRole, f.packet)
            self.tree.addTopLevelItem(it)
        for c in range(3):
            self.tree.resizeColumnToContents(c)
        self.info.setText(f"{len(self._findings)} Treffer.")
        self.btn_mark.setEnabled(bool(self._findings))

    def _double(self, item, _col) -> None:
        pkt = item.data(0, Qt.UserRole)
        if pkt:
            self.jumpToPacket.emit(int(pkt))

    def _mark(self) -> None:
        nums = {f.packet for f in self._findings if f.packet}
        if nums:
            self.markRequested.emit(nums)
            self.info.setText(f"{len(nums)} Treffer markiert.")


# --------------------------------------------------------------------------- #
class _TopologyView(QWidget):
    """Zeichnet Hosts als Knoten auf einem Kreis, Verbindungen als Kanten."""

    def __init__(self, nodes, edges, parent=None) -> None:
        super().__init__(parent)
        self._nodes = nodes
        self._edges = edges
        self.setMinimumSize(560, 520)
        self.setAttribute(Qt.WA_StyledBackground, True)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor(THEME.bg))
        if not self._nodes:
            p.setPen(QColor(THEME.muted))
            p.drawText(self.rect(), Qt.AlignCenter, "keine Daten")
            p.end()
            return
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2 - 70
        n = len(self._nodes)
        pos = {}
        for i, node in enumerate(self._nodes):
            ang = 2 * math.pi * i / n - math.pi / 2
            pos[node.ip] = (cx + radius * math.cos(ang),
                            cy + radius * math.sin(ang))

        max_eb = max((e.bytes for e in self._edges), default=1)
        for e in self._edges:
            if e.a not in pos or e.b not in pos:
                continue
            x1, y1 = pos[e.a]
            x2, y2 = pos[e.b]
            width = 1 + 5 * (e.bytes / max_eb)
            col = QColor("#5aa9ff")
            col.setAlpha(70 + int(150 * e.bytes / max_eb))
            p.setPen(QPen(col, width))
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        max_nb = max((node.bytes for node in self._nodes), default=1)
        p.setFont(QFont("Segoe UI", 7))
        for node in self._nodes:
            x, y = pos[node.ip]
            r = 6 + 14 * math.sqrt(node.bytes / max_nb)
            color = QColor("#ffb454") if node.is_local else QColor("#56d364")
            p.setBrush(color)
            p.setPen(QPen(QColor(THEME.bg), 1))
            p.drawEllipse(QPointF(x, y), r, r)
            p.setPen(QColor(THEME.text))
            label = f"{node.ip}  ({human(node.bytes)})"
            tw = p.fontMetrics().horizontalAdvance(label)
            tx = x - tw / 2
            ty = y + r + 11 if y < cy else y - r - 4
            p.drawText(int(tx), int(ty), label)
        p.end()


class TopologyDialog(QDialog):
    """Netzwerk-Topologie als Knoten-Kanten-Diagramm."""

    def __init__(self, nodes, edges, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Netzwerk-Topologie")
        self.resize(720, 640)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"{len(nodes)} Hosts, {len(edges)} Verbindungen  "
                             "(gelb = lokal, grün = entfernt; Kantendicke = Volumen)"))
        area = QScrollArea(self)
        area.setWidgetResizable(True)
        area.setWidget(_TopologyView(nodes, edges, self))
        lay.addWidget(area, 1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)


# --------------------------------------------------------------------------- #
class ObjectExtractDialog(QDialog):
    """Aus HTTP-Strömen extrahierte Objekte ansehen und speichern."""

    def __init__(self, objects, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Extrahierte Objekte")
        self.resize(820, 560)
        self._objects = objects
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"{len(objects)} Objekt(e) aus dem HTTP-Verkehr"))

        split = QSplitter(Qt.Horizontal, self)
        self.tree = QTreeWidget(split)
        self.tree.setHeaderLabels(["#", "URL/Quelle", "Typ", "Größe"])
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        for i, o in enumerate(objects):
            it = QTreeWidgetItem([str(i + 1), o.url or o.source, o.content_type,
                                  human(o.size)])
            it.setData(0, Qt.UserRole, i)
            self.tree.addTopLevelItem(it)
        for c in range(4):
            self.tree.resizeColumnToContents(c)
        self.tree.currentItemChanged.connect(self._preview)
        split.addWidget(self.tree)

        self.preview = QPlainTextEdit(split)
        self.preview.setReadOnly(True)
        self.preview.setFont(_MONO)
        self.img = QLabel(split)
        self.img.setAlignment(Qt.AlignCenter)
        self.img.hide()
        split.addWidget(self.preview)
        split.setSizes([420, 380])
        lay.addWidget(split, 1)

        row = QHBoxLayout()
        b1 = QPushButton("Speichern…", self)
        b1.clicked.connect(self._save_one)
        b2 = QPushButton("Alle speichern…", self)
        b2.clicked.connect(self._save_all)
        row.addWidget(b1)
        row.addWidget(b2)
        row.addStretch(1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        row.addWidget(close)
        lay.addLayout(row)
        if objects:
            self.tree.setCurrentItem(self.tree.topLevelItem(0))

    def _sel(self):
        it = self.tree.currentItem()
        return self._objects[it.data(0, Qt.UserRole)] if it else None

    def _preview(self, *_a) -> None:
        o = self._sel()
        if o is None:
            return
        if o.content_type.startswith("image/"):
            img = QImage.fromData(o.data)
            if not img.isNull():
                self.preview.hide()
                self.img.show()
                self.img.setPixmap(QPixmap.fromImage(img).scaled(
                    360, 360, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                return
        self.img.hide()
        self.preview.show()
        self.preview.setPlainText(o.data[:8192].decode("latin-1", "replace"))

    def _save_one(self) -> None:
        o = self._sel()
        if o is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Objekt speichern",
                                              suggest_filename(o))
        if path:
            self._write(path, o.data)

    def _save_all(self) -> None:
        import os
        folder = QFileDialog.getExistingDirectory(self, "Zielordner wählen")
        if not folder:
            return
        for i, o in enumerate(self._objects):
            self._write(os.path.join(folder, f"{i + 1:03d}_{suggest_filename(o)}"),
                        o.data)

    def _write(self, path: str, data: bytes) -> None:
        try:
            with open(path, "wb") as f:
                f.write(data)
        except OSError as exc:
            QMessageBox.critical(self, "NetFett – Fehler", str(exc))


# --------------------------------------------------------------------------- #
class _TraceView(QWidget):
    """Zeichnet TCP-Trace-Daten (Sequenz/Durchsatz/Window) als Punkte."""

    def __init__(self, samples, parent=None) -> None:
        super().__init__(parent)
        self._samples = samples
        self._mode = "Sequenznummer"
        self.setMinimumHeight(320)
        self.setAttribute(Qt.WA_StyledBackground, True)

    def set_mode(self, mode: str) -> None:
        self._mode = mode
        self.update()

    def _series(self):
        cli, srv = [], []
        if self._mode == "Durchsatz (B/s)":
            buckets: dict = {}
            for s in self._samples:
                buckets[(s.from_client, int(s.t))] = \
                    buckets.get((s.from_client, int(s.t)), 0) + s.length
            for (fc, sec), v in buckets.items():
                (cli if fc else srv).append((float(sec), v))
        else:
            for s in self._samples:
                y = s.seq if self._mode == "Sequenznummer" else s.window
                (cli if s.from_client else srv).append((s.t, y))
        return cli, srv

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor(THEME.bg))
        cli, srv = self._series()
        allpts = cli + srv
        if not allpts:
            p.setPen(QColor(THEME.muted))
            p.drawText(self.rect(), Qt.AlignCenter, "keine Daten")
            p.end()
            return
        w, h = self.width(), self.height()
        gx, gy, gw, gh = 56, 10, w - 70, h - 34
        tmax = max(t for t, _ in allpts) or 1.0
        ymax = max(y for _, y in allpts) or 1
        for f in (0.0, 0.25, 0.5, 0.75, 1.0):
            yy = gy + gh - gh * f
            p.setPen(QPen(QColor(THEME.grid), 1))
            p.drawLine(gx, int(yy), gx + gw, int(yy))
            p.setPen(QColor(THEME.muted))
            p.setFont(QFont("Segoe UI", 7))
            p.drawText(4, int(yy + 3), human(ymax * f, ""))

        def plot(pts, color):
            p.setPen(QColor(color))
            p.setBrush(QColor(color))
            for t, y in pts:
                x = gx + gw * (t / tmax)
                yy = gy + gh - gh * (y / ymax)
                p.drawEllipse(QPoint(int(x), int(yy)), 2, 2)

        plot(cli, "#5aa9ff")
        plot(srv, "#ffb454")
        p.setPen(QColor(THEME.muted))
        p.drawText(gx, h - 8, f"0 … {tmax:.2f} s   (blau=Client, orange=Server)")
        p.end()


class StreamGraphDialog(QDialog):
    """TCP-Stream-Graph (Sequenznummer / Durchsatz / Window über Zeit)."""

    def __init__(self, packets, conv, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("TCP-Stream-Graph")
        self.resize(760, 460)
        samples = tcp_trace(packets, conv.a, conv.a_port, conv.b, conv.b_port)
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Darstellung:"))
        self.mode = QComboBox(self)
        self.mode.addItems(["Sequenznummer", "Durchsatz (B/s)", "Window"])
        row.addWidget(self.mode)
        row.addStretch(1)
        lay.addLayout(row)
        self.view = _TraceView(samples, self)
        self.mode.currentTextChanged.connect(self.view.set_mode)
        lay.addWidget(self.view, 1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)


# --------------------------------------------------------------------------- #
class DecodeAsDialog(QDialog):
    """Port→Protokoll-Overrides verwalten (Decode As)."""

    def __init__(self, mapping: dict, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Decode As")
        self.resize(420, 360)
        self._map = dict(mapping)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Port wird als gewähltes Protokoll zerlegt:"))
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Port", "Protokoll"])
        self.tree.setRootIsDecorated(False)
        lay.addWidget(self.tree)
        row = QHBoxLayout()
        b1 = QPushButton("Hinzufügen", self)
        b1.clicked.connect(self._add)
        b2 = QPushButton("Entfernen", self)
        b2.clicked.connect(self._remove)
        row.addWidget(b1)
        row.addWidget(b2)
        row.addStretch(1)
        lay.addLayout(row)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addWidget(box)
        self._rebuild()

    def _rebuild(self) -> None:
        self.tree.clear()
        for port, proto in sorted(self._map.items()):
            self.tree.addTopLevelItem(QTreeWidgetItem([str(port), proto]))

    def _add(self) -> None:
        port, ok = QInputDialog.getInt(self, "Decode As", "Port:", 8443, 1, 65535)
        if not ok:
            return
        proto, ok = QInputDialog.getItem(self, "Decode As", "Als Protokoll:",
                                         ["tls", "http", "dns"], 0, False)
        if ok:
            self._map[port] = proto
            self._rebuild()

    def _remove(self) -> None:
        it = self.tree.currentItem()
        if it:
            self._map.pop(int(it.text(0)), None)
            self._rebuild()

    def result_map(self) -> dict:
        return self._map


# --------------------------------------------------------------------------- #
from .charts import color_for  # noqa: E402


class _FlowView(QWidget):
    """Globaler Flow-Graph: Hosts als Spalten, Pakete als Pfeile über die Zeit."""

    ROW_H = 20
    TOP = 60

    def __init__(self, hosts: list[str], events: list, parent=None) -> None:
        super().__init__(parent)
        self._hosts = hosts
        self._events = events            # [(ts, src, dst, proto, label)]
        self._col = {ip: i for i, ip in enumerate(hosts)}
        self.setMinimumWidth(max(560, 40 + len(hosts) * 150))
        self.setMinimumHeight(self.TOP + len(events) * self.ROW_H + 20)
        self.setAttribute(Qt.WA_StyledBackground, True)

    def _x(self, ip: str, w: int) -> float:
        n = max(1, len(self._hosts))
        margin = 80
        span = (w - 2 * margin) / max(1, n - 1) if n > 1 else 0
        return margin + self._col.get(ip, 0) * span

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor(THEME.bg))
        if not self._events:
            p.setPen(QColor(THEME.muted))
            p.drawText(self.rect(), Qt.AlignCenter, "keine Daten")
            p.end()
            return
        w, h = self.width(), self.height()
        # Lebenslinien + Kopf.
        p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        for ip in self._hosts:
            x = self._x(ip, w)
            p.setPen(QPen(QColor(THEME.grid), 1, Qt.DashLine))
            p.drawLine(int(x), self.TOP - 10, int(x), h - 6)
            p.setPen(QColor(THEME.text))
            p.drawText(int(x) - 70, 16, 140, 30, int(Qt.AlignHCenter | Qt.TextWordWrap), ip)
        p.setFont(QFont("Consolas", 8))
        t0 = self._events[0][0]
        for i, (ts, src, dst, proto, label) in enumerate(self._events):
            y = self.TOP + i * self.ROW_H + 10
            if src not in self._col or dst not in self._col:
                continue
            x1, x2 = self._x(src, w), self._x(dst, w)
            color = color_for(proto, hash(proto) % 12)
            p.setPen(QColor(THEME.muted))
            p.drawText(4, int(y + 4), f"{ts - t0:7.3f}")
            p.setPen(QPen(color, 1.4))
            p.drawLine(QPointF(x1, y), QPointF(x2, y))
            head = QPolygonF([QPointF(x2, y),
                              QPointF(x2 - (6 if x2 > x1 else -6), y - 3),
                              QPointF(x2 - (6 if x2 > x1 else -6), y + 3)])
            p.setBrush(color)
            p.setPen(Qt.NoPen)
            p.drawPolygon(head)
            p.setPen(QColor(THEME.text))
            mid = (x1 + x2) / 2
            tw = p.fontMetrics().horizontalAdvance(label)
            p.drawText(int(mid - tw / 2), int(y - 4), label)
        p.end()


class FlowGraphDialog(QDialog):
    """Globaler Flow-Graph aller Verbindungen (Top-Hosts als Spalten)."""

    def __init__(self, packets, max_hosts: int = 6, max_events: int = 400,
                 parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Flow-Graph")
        self.resize(820, 640)
        # Top-Hosts nach Volumen bestimmen.
        vol: dict = {}
        for p in packets:
            for ip in (p.src, p.dst):
                if ip:
                    vol[ip] = vol.get(ip, 0) + p.length
        hosts = sorted(vol, key=lambda ip: vol[ip], reverse=True)[:max_hosts]
        keep = set(hosts)
        events = []
        for p in sorted(packets, key=lambda x: (x.ts, x.number)):
            if p.src in keep and p.dst in keep and p.src != p.dst:
                label = f"{p.protocol}"
                if p.dst_port:
                    label += f" :{p.dst_port}"
                events.append((p.ts, p.src, p.dst, p.protocol or "?", label))
            if len(events) >= max_events:
                break
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"{len(events)} Pakete zwischen {len(hosts)} "
                             f"Top-Hosts (max. {max_events})"))
        area = QScrollArea(self)
        area.setWidgetResizable(True)
        area.setWidget(_FlowView(hosts, events, self))
        lay.addWidget(area, 1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)
