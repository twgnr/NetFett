"""Hauptfenster von NetFett: verdrahtet Capture, Paketliste, Detail-/Hex-Ansicht,
Live-Graphen, Statistik, Anzeigefilter und PCAP-Öffnen/Speichern.

Das Fenster bleibt bewusst dünn – die eigentliche Arbeit steckt im ``core``-Layer
(rein, getestet) und in den GUI-Bausteinen :class:`PacketModel`,
:class:`CaptureController` und :class:`GraphWidget`.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QComboBox, QDockWidget, QFileDialog, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QSplitter, QStatusBar,
    QTableView, QTextEdit, QToolBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)

from ..core.analyze import Conversation
from ..core.dissect import dissect
from ..core.displayfilter import FilterError, compile_filter
from ..core.interfaces import local_ipv4_addresses, primary_ipv4
from ..core.models import Packet
from ..core.pcap import read_pcap, write_pcap
from ..core.stats import Stats
from .analysis_dialogs import (
    ConversationsDialog, ExpertInfoDialog, FollowStreamDialog,
)
from .capture_controller import CaptureController
from .graph_widget import GraphWidget, human
from .packet_model import _PROTO_BG, PacketModel

_MONO = QFont("Consolas", 9)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NetFett – Netzwerk-Monitor")
        self.resize(1180, 760)

        self.model = PacketModel(self)
        self.stats = Stats(window=60)
        self.controller = CaptureController(self)
        self._current_packet: Packet | None = None

        self._build_menubar()
        self._build_toolbar()
        self._build_central()
        self._build_stats_dock()
        self._build_statusbar()

        # 1-Sekunden-Takt für Statistik/Graphen.
        self._sec_timer = QTimer(self)
        self._sec_timer.setInterval(1000)
        self._sec_timer.timeout.connect(self._on_second)

        self.controller.batchReady.connect(self._on_batch)
        self.controller.error.connect(self._on_error)
        self.controller.started.connect(self._on_started)
        self.controller.stopped.connect(self._on_stopped)

        self._populate_interfaces()
        self._refresh_graphs()

    # --- Aufbau ------------------------------------------------------------
    def _build_menubar(self) -> None:
        menu = self.menuBar().addMenu("&Analyse")
        act_conv = QAction("Verbindungen…", self)
        act_conv.triggered.connect(self._show_conversations)
        menu.addAction(act_conv)
        act_exp = QAction("Experten-Infos…", self)
        act_exp.triggered.connect(self._show_expert_info)
        menu.addAction(act_exp)

    def _build_toolbar(self) -> None:
        tb = QToolBar("Steuerung", self)
        tb.setMovable(False)
        self.addToolBar(tb)

        self.iface_combo = QComboBox(self)
        self.iface_combo.setMinimumWidth(160)
        tb.addWidget(QLabel(" Schnittstelle: "))
        tb.addWidget(self.iface_combo)

        self.act_start = QAction("▶ Start", self)
        self.act_start.triggered.connect(self._start)
        tb.addAction(self.act_start)

        self.act_stop = QAction("■ Stopp", self)
        self.act_stop.setEnabled(False)
        self.act_stop.triggered.connect(self.controller.stop)
        tb.addAction(self.act_stop)

        self.act_clear = QAction("Leeren", self)
        self.act_clear.triggered.connect(self._clear)
        tb.addAction(self.act_clear)

        self.act_follow = QAction("⤓ Auto-Scroll", self)
        self.act_follow.setCheckable(True)
        self.act_follow.setChecked(True)
        self.act_follow.setToolTip("Bei Live-Erfassung der neuesten Zeile folgen")
        tb.addAction(self.act_follow)

        self.act_stats = QAction("Statistik", self)
        self.act_stats.setCheckable(True)
        self.act_stats.setChecked(True)
        self.act_stats.setToolTip("Top-Protokolle und Top-Talkers ein-/ausblenden")
        tb.addAction(self.act_stats)

        tb.addSeparator()
        self.act_open = QAction("PCAP öffnen…", self)
        self.act_open.triggered.connect(self._open_pcap)
        tb.addAction(self.act_open)
        self.act_save = QAction("PCAP speichern…", self)
        self.act_save.triggered.connect(self._save_pcap)
        tb.addAction(self.act_save)

        tb.addSeparator()
        tb.addWidget(QLabel(" Filter: "))
        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText(
            "z. B.  tcp dst port 443    |    dns or mdns    |    host 192.168.0.10")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.returnPressed.connect(self._apply_filter)
        self.filter_edit.textChanged.connect(self._on_filter_text)
        tb.addWidget(self.filter_edit)

    def _build_central(self) -> None:
        # Vertikaler Hauptsplitter: Graphen | Paketliste | Detail+Hex.
        outer = QSplitter(Qt.Vertical, self)

        graphs = QWidget(self)
        gl = QVBoxLayout(graphs)
        gl.setContentsMargins(0, 0, 0, 0)
        gl.setSpacing(2)
        self.graph_bps = GraphWidget("Durchsatz", "B/s", self)
        self.graph_pps = GraphWidget("Pakete", "P/s", self)
        gl.addWidget(self.graph_bps)
        gl.addWidget(self.graph_pps)
        outer.addWidget(graphs)

        self.table = QTableView(self)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setFont(_MONO)
        hh = self.table.horizontalHeader()
        hh.setStretchLastSection(True)
        for col, mode in {
            0: QHeaderView.ResizeToContents, 1: QHeaderView.ResizeToContents,
            5: QHeaderView.ResizeToContents, 6: QHeaderView.ResizeToContents,
        }.items():
            hh.setSectionResizeMode(col, mode)
        self.table.selectionModel().currentRowChanged.connect(self._on_row)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_menu)
        outer.addWidget(self.table)

        bottom = QSplitter(Qt.Horizontal, self)
        self.detail = QTreeWidget(self)
        self.detail.setHeaderLabels(["Feld", "Wert"])
        self.detail.setFont(_MONO)
        self.detail.itemSelectionChanged.connect(self._on_detail_selection)
        bottom.addWidget(self.detail)

        self.hex = QPlainTextEdit(self)
        self.hex.setReadOnly(True)
        self.hex.setFont(_MONO)
        self.hex.setLineWrapMode(QPlainTextEdit.NoWrap)
        bottom.addWidget(self.hex)
        bottom.setSizes([520, 560])
        outer.addWidget(bottom)

        outer.setStretchFactor(0, 0)
        outer.setStretchFactor(1, 3)
        outer.setStretchFactor(2, 2)
        outer.setSizes([150, 360, 250])
        self.setCentralWidget(outer)

    def _build_stats_dock(self) -> None:
        """Rechtes Andock-Panel: Top-Protokolle und Top-Talkers (1 s aktualisiert)."""
        dock = QDockWidget("Statistik", self)
        dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        body = QWidget(dock)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(6)

        lay.addWidget(self._dock_caption("Protokolle (nach Volumen)"))
        self.proto_tree = QTreeWidget(body)
        self.proto_tree.setHeaderLabels(["Protokoll", "Pakete", "Bytes", "%"])
        self.proto_tree.setRootIsDecorated(False)
        self.proto_tree.setFont(_MONO)
        lay.addWidget(self.proto_tree, 1)

        lay.addWidget(self._dock_caption("Top-Talkers (Quelle ⇄ Ziel)"))
        self.talker_tree = QTreeWidget(body)
        self.talker_tree.setHeaderLabels(["Verbindung", "Pakete", "Bytes"])
        self.talker_tree.setRootIsDecorated(False)
        self.talker_tree.setFont(_MONO)
        lay.addWidget(self.talker_tree, 1)

        dock.setWidget(body)
        dock.setMinimumWidth(280)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)
        self._stats_dock = dock
        # Toolbar-Schalter <-> Dock-Sichtbarkeit beidseitig koppeln.
        self.act_stats.toggled.connect(dock.setVisible)
        dock.visibilityChanged.connect(self.act_stats.setChecked)
        dock.visibilityChanged.connect(self._on_dock_visibility)

    def _on_dock_visibility(self, visible: bool) -> None:
        if visible:
            self._refresh_stats_panel()

    @staticmethod
    def _dock_caption(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color:#8b949e; font-weight:bold; padding:2px 0;")
        return lbl

    def _build_statusbar(self) -> None:
        sb = QStatusBar(self)
        self.setStatusBar(sb)
        self.lbl_state = QLabel("Bereit")
        self.lbl_counts = QLabel("")
        sb.addWidget(self.lbl_state, 1)
        sb.addPermanentWidget(self.lbl_counts)

    # --- Schnittstellen / Start / Stopp ------------------------------------
    def _populate_interfaces(self) -> None:
        self.iface_combo.clear()
        addrs = local_ipv4_addresses()
        for a in addrs:
            self.iface_combo.addItem(a)
        primary = primary_ipv4()
        if primary and primary in addrs:
            self.iface_combo.setCurrentText(primary)

    def _start(self) -> None:
        host = self.iface_combo.currentText().strip()
        if not host:
            QMessageBox.warning(self, "NetFett", "Keine Schnittstelle gewählt.")
            return
        self._current_packet = None
        try:
            self.controller.start(host)
        except Exception as exc:  # CaptureError u. a. – Meldung anzeigen
            self._on_error(str(exc))

    def _on_started(self) -> None:
        self.act_start.setEnabled(False)
        self.act_stop.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.lbl_state.setText(
            f"Erfassung läuft auf {self.iface_combo.currentText()} …")
        self._sec_timer.start()

    def _on_stopped(self) -> None:
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self._sec_timer.stop()
        self.lbl_state.setText("Gestoppt")

    def _on_error(self, msg: str) -> None:
        self._sec_timer.stop()
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.lbl_state.setText("Fehler")
        QMessageBox.critical(self, "NetFett – Fehler", msg)

    # --- Datenfluss --------------------------------------------------------
    def _on_batch(self, batch: list[Packet]) -> None:
        for pkt in batch:
            self.stats.add(pkt)
        self.model.add_batch(batch)
        self._update_counts()
        if self.act_follow.isChecked() and self.model.shown:
            self.table.scrollToBottom()

    def _on_second(self) -> None:
        self.stats.tick()
        self._refresh_graphs()
        self._refresh_stats_panel()

    def _refresh_graphs(self) -> None:
        self.graph_bps.set_series(self.stats.in_bps, self.stats.out_bps)
        self.graph_pps.set_series(self.stats.in_pps, self.stats.out_pps)

    def _refresh_stats_panel(self) -> None:
        if not self._stats_dock.isVisible():
            return
        total = self.stats.total_bytes or 1
        self.proto_tree.clear()
        for name, pkts, byts in self.stats.top_protocols(12):
            pct = f"{100 * byts / total:.1f}"
            it = QTreeWidgetItem([name, str(pkts), human(byts), pct])
            for col in (1, 2, 3):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            bg = _PROTO_BG.get(name)
            if bg:
                it.setBackground(0, QColor(bg))
            self.proto_tree.addTopLevelItem(it)
        for col in range(4):
            self.proto_tree.resizeColumnToContents(col)

        self.talker_tree.clear()
        for name, pkts, byts in self.stats.top_talkers(10):
            it = QTreeWidgetItem([name, str(pkts), human(byts)])
            for col in (1, 2):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            self.talker_tree.addTopLevelItem(it)
        self.talker_tree.resizeColumnToContents(0)

    def _update_counts(self) -> None:
        total = self.stats.total_packets
        shown = self.model.shown
        self.lbl_counts.setText(
            f"Pakete: {shown}/{total}   "
            f"▼ {human(self.stats.total_in_bytes)}   "
            f"▲ {human(self.stats.total_out_bytes)}")

    def _clear(self) -> None:
        self.model.clear()
        self.stats.reset()
        self.detail.clear()
        self.hex.clear()
        self.proto_tree.clear()
        self.talker_tree.clear()
        self._current_packet = None
        self._refresh_graphs()
        self._update_counts()

    # --- Filter ------------------------------------------------------------
    def _on_filter_text(self, _text: str) -> None:
        # Visuelles Feedback: rot bei ungültigem Filter, sonst neutral.
        try:
            compile_filter(self.filter_edit.text())
            self.filter_edit.setStyleSheet("")
        except FilterError:
            self.filter_edit.setStyleSheet("background:#3a1414;")

    def _apply_filter(self) -> None:
        try:
            func = compile_filter(self.filter_edit.text())
        except FilterError as exc:
            self.lbl_state.setText(f"Filterfehler: {exc}")
            return
        self.model.set_filter(func)
        self.lbl_state.setText(
            "Filter aktiv" if func else "Filter gelöscht")
        self._update_counts()

    # --- Auswahl: Detail-Baum + Hex ---------------------------------------
    def _on_row(self, current, _previous) -> None:
        pkt = self.model.packet_at(current.row()) if current.isValid() else None
        self._current_packet = pkt
        self._show_detail(pkt)
        self._show_hex(pkt.raw if pkt else b"")

    def _show_detail(self, pkt: Packet | None) -> None:
        self.detail.clear()
        if pkt is None:
            return
        for layer in pkt.layers:
            head = f"{layer.name}"
            top = QTreeWidgetItem([head, layer.summary])
            # Byte-Bereich der Schicht für Hex-Hervorhebung mitführen.
            top.setData(0, Qt.UserRole, (layer.start, layer.length))
            for label, value in layer.fields:
                top.addChild(QTreeWidgetItem([label, value]))
            self.detail.addTopLevelItem(top)
            top.setExpanded(True)
        self.detail.resizeColumnToContents(0)

    def _on_detail_selection(self) -> None:
        items = self.detail.selectedItems()
        if not items:
            return
        item = items[0]
        # Bereich der Top-Level-Schicht heranziehen (auch bei Feld-Auswahl).
        span = item.data(0, Qt.UserRole)
        if span is None and item.parent() is not None:
            span = item.parent().data(0, Qt.UserRole)
        if span:
            self._highlight_hex(*span)

    def _show_hex(self, raw: bytes) -> None:
        self.hex.setExtraSelections([])
        self.hex.setPlainText(_hexdump(raw))

    def _highlight_hex(self, start: int, length: int) -> None:
        """Hebt den Byte-Bereich [start, start+length) in Hex UND ASCII hervor.

        Nutzt das feste Spaltenraster des Hexdumps (16 Bytes/Zeile, jede volle
        Zeile 72 Zeichen inkl. Zeilenumbruch) zur exakten Zeichenposition.
        """
        raw = self._current_packet.raw if self._current_packet else b""
        end = min(start + length, len(raw))
        if start < 0 or end <= start:
            self.hex.setExtraSelections([])
            return

        doc = self.hex.document()
        sels: list[QTextEdit.ExtraSelection] = []
        first_line = start // 16
        last_line = (end - 1) // 16
        for line in range(first_line, last_line + 1):
            base = line * 72              # Zeichenoffset des Zeilenanfangs
            row0 = line * 16
            ca = max(start, row0) - row0  # erste Spalte in dieser Zeile
            cb = min(end, row0 + 16) - row0  # exklusiv
            # Hex-Spalten (3 Zeichen/Byte) ohne nachlaufendes Leerzeichen.
            sels.append(self._sel(doc, base + 6 + ca * 3, base + 6 + cb * 3 - 1))
            # ASCII-Spalten (1 Zeichen/Byte) ab fester Position 55.
            sels.append(self._sel(doc, base + 55 + ca, base + 55 + cb))
        self.hex.setExtraSelections(sels)

        cursor = QTextCursor(doc)
        cursor.setPosition(first_line * 72)
        self.hex.setTextCursor(cursor)
        self.hex.ensureCursorVisible()

    @staticmethod
    def _sel(doc, pos_from: int, pos_to: int) -> "QTextEdit.ExtraSelection":
        sel = QTextEdit.ExtraSelection()
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("#1f6feb"))
        fmt.setForeground(QColor("#ffffff"))
        sel.format = fmt
        cur = QTextCursor(doc)
        cur.setPosition(pos_from)
        cur.setPosition(pos_to, QTextCursor.KeepAnchor)
        sel.cursor = cur
        return sel

    # --- PCAP --------------------------------------------------------------
    def _save_pcap(self) -> None:
        packets = self.model.all_packets
        if not packets:
            QMessageBox.information(self, "NetFett", "Keine Pakete zum Speichern.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "PCAP speichern", "netfett.pcap", "PCAP-Dateien (*.pcap)")
        if not path:
            return
        try:
            n = write_pcap(path, packets)
        except OSError as exc:
            QMessageBox.critical(self, "NetFett – Fehler", str(exc))
            return
        self.lbl_state.setText(f"{n} Pakete gespeichert → {path}")

    def _open_pcap(self) -> None:
        if self.controller.running:
            QMessageBox.information(
                self, "NetFett", "Bitte zuerst die laufende Erfassung stoppen.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "PCAP öffnen", "", "PCAP-Dateien (*.pcap *.cap);;Alle Dateien (*)")
        if not path:
            return
        try:
            records = read_pcap(path)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "NetFett – Fehler", str(exc))
            return
        self._clear()
        local = set(local_ipv4_addresses())
        batch = [dissect(raw, ts, i + 1, local)
                 for i, (ts, raw) in enumerate(records)]
        self._on_batch(batch)
        self.stats.tick()
        self._refresh_graphs()
        self._refresh_stats_panel()
        self.lbl_state.setText(f"{len(batch)} Pakete geladen ← {path}")

    # --- Analyse -----------------------------------------------------------
    def _show_conversations(self) -> None:
        pkts = self.model.all_packets
        if not pkts:
            QMessageBox.information(self, "NetFett", "Keine Pakete zum Analysieren.")
            return
        dlg = ConversationsDialog(pkts, self)
        dlg.followRequested.connect(self._follow_stream)
        dlg.filterRequested.connect(self._set_filter)
        dlg.exec()

    def _show_expert_info(self) -> None:
        pkts = self.model.all_packets
        if not pkts:
            QMessageBox.information(self, "NetFett", "Keine Pakete zum Analysieren.")
            return
        dlg = ExpertInfoDialog(pkts, self)
        dlg.jumpToPacket.connect(self._jump_to_packet)
        dlg.exec()

    def _follow_stream(self, conv: Conversation) -> None:
        FollowStreamDialog(self.model.all_packets, conv, self).exec()

    def _set_filter(self, text: str) -> None:
        self.filter_edit.setText(text)
        self._apply_filter()

    def _jump_to_packet(self, number: int) -> None:
        for row in range(self.model.shown):
            pkt = self.model.packet_at(row)
            if pkt is not None and pkt.number == number:
                self.table.setCurrentIndex(self.model.index(row, 0))
                self.table.scrollTo(self.model.index(row, 0),
                                    QTableView.PositionAtCenter)
                self.raise_()
                self.activateWindow()
                return
        self.lbl_state.setText(
            f"Paket {number} nicht sichtbar (evtl. vom Filter ausgeblendet).")

    def _table_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        pkt = self.model.packet_at(index.row()) if index.isValid() else None
        if pkt is None:
            return
        menu = QMenu(self)
        if (pkt.l4 == "TCP" or pkt.protocol == "TCP") and pkt.src_port and pkt.dst_port:
            act = menu.addAction("TCP-Stream folgen…")
            act.triggered.connect(lambda: self._follow_stream(
                Conversation(proto="TCP", a=pkt.src, a_port=pkt.src_port,
                             b=pkt.dst, b_port=pkt.dst_port)))
            menu.addSeparator()
        menu.addAction("Als Filter: diese Verbindung").triggered.connect(
            lambda: self._set_filter(f"host {pkt.src} host {pkt.dst}"))
        menu.addAction(f"Als Filter: host {pkt.src}").triggered.connect(
            lambda: self._set_filter(f"host {pkt.src}"))
        menu.addAction(f"Als Filter: host {pkt.dst}").triggered.connect(
            lambda: self._set_filter(f"host {pkt.dst}"))
        if pkt.dst_port:
            menu.addAction(f"Als Filter: port {pkt.dst_port}").triggered.connect(
                lambda: self._set_filter(f"port {pkt.dst_port}"))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    # --- Lebenszyklus ------------------------------------------------------
    def closeEvent(self, event) -> None:
        if self.controller.running:
            self.controller.stop()
        super().closeEvent(event)


def _hexdump(raw: bytes) -> str:
    """Klassischer Hexdump: Offset | 16 Hex-Bytes | ASCII."""
    lines = []
    for off in range(0, len(raw), 16):
        chunk = raw[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = f"{hex_part:<47}"  # 16*3-1 = 47 Zeichen
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hex_part}  {ascii_part}")
    return "\n".join(lines)
