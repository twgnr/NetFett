"""Hauptfenster von NetFett: verdrahtet Capture, Paketliste, Detail-/Hex-Ansicht,
Live-Graphen, Statistik, Anzeigefilter und PCAP-Öffnen/Speichern.

Das Fenster bleibt bewusst dünn – die eigentliche Arbeit steckt im ``core``-Layer
(rein, getestet) und in den GUI-Bausteinen :class:`PacketModel`,
:class:`CaptureController` und :class:`GraphWidget`.
"""
from __future__ import annotations

import json
import os
import sys

from PySide6.QtCore import QProcess, QSettings, QStringListModel, Qt, QTimer
from PySide6.QtGui import (
    QAction, QActionGroup, QColor, QFont, QGuiApplication, QKeySequence,
    QTextCharFormat, QTextCursor,
)
from PySide6.QtWidgets import (
    QComboBox, QCompleter, QDockWidget, QFileDialog, QHeaderView, QInputDialog,
    QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
    QSplitter, QStatusBar, QTableView, QTabWidget, QTextEdit, QToolBar,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..core import geoip
from ..core.analyze import Conversation
from ..core.categories import aggregate_categories
from ..core.coloring import RuleSet, default_rules
from ..core.content import as_text, content_view
from ..core.analyze import topology as build_topology
from ..elevate import is_admin, relaunch_as_admin
from ..i18n import LANGUAGES, SETTINGS_KEY, language, tr
from ..core.dissect import dissect
from ..core.displayfilter import FilterError, compile_filter
from ..core.interfaces import local_ipv4_addresses, primary_ipv4
from ..core.models import DIR_IN, DIR_OUT, Packet
from ..core.procmap import aggregate_processes
from ..core.export import (
    export_conversations, export_domains, export_packets,
)
from ..core.pcap import (
    merge_captures, read_capture, write_pcap, write_pcapng,
)
from ..core.reassemble import IPReassembler
from ..core.resolve import NameResolver
from ..core.tlskeys import parse_keylog
from ..core.stats import Stats
from ..core.analyze import tcp_expert_flags
from .analysis_dialogs import (
    ConnectionStatesDialog, ConversationsDialog, DnsAnalysisDialog,
    DomainsDialog, EndpointsDialog, ExpertInfoDialog, FollowStreamDialog,
    ProcessTrafficDialog, ProtocolHierarchyDialog, RtpStreamsDialog, SrtDialog,
    TcpHealthDialog,
)
from ..core.hoststats import HostMonitor
from .capture_controller import CaptureController
from .devices_dialog import DevicesDialog
from .charts import BarChart, DonutChart
from .graph_widget import GraphWidget, human
from .packet_model import COLUMNS, NAME_COL, PROC_COL, _PROTO_BG, PacketModel
from .pro_dialogs import (
    ColoringRulesDialog, FlowGraphDialog, IocDialog, IoGraphDialog,
    TopologyDialog,
)
from .theme import apply as apply_theme
from .tools_dialogs import (
    DnsLookupDialog, PingDialog, TracerouteDialog, WhoisDialog,
)
from .help_dialog import HelpDialog, about_text

_MONO = QFont("Consolas", 9)
_LABEL_ROLE = Qt.UserRole + 1     # Original-Feldlabel im Detail-Baum


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        title = tr("NetFett – Netzwerk-Monitor")
        if is_admin():
            title += "  (Administrator)"
        self.setWindowTitle(title)
        self.resize(1180, 760)

        self.model = PacketModel(self)
        self.stats = Stats(window=60)
        self.host_monitor = HostMonitor(window=60)   # Durchsatz je Gerät
        self.controller = CaptureController(self)
        self._current_packet: Packet | None = None
        self._find_term: str = ""
        self.resolver = NameResolver()      # Reverse-DNS-Cache (geteilt)
        self._name_timer = QTimer(self)     # pollt den Cache für die Namensspalte
        self._name_timer.setInterval(400)
        self._name_timer.timeout.connect(self._poll_names)
        self.ruleset = RuleSet(default_rules())   # Einfärbe-Regeln
        self.model.set_color_rules(self.ruleset)
        self.keylog: dict = {}                     # TLS-Secrets (SSLKEYLOGFILE)
        self._autoload_keylog()

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
        self._settings = QSettings("NetFett", "NetFett")
        self._load_settings()
        self._update_recent_menu()

    # --- Aufbau ------------------------------------------------------------
    def _build_menubar(self) -> None:
        menu = self.menuBar().addMenu(tr("&Analyse"))
        act_conv = QAction(tr("Verbindungen…"), self)
        act_conv.triggered.connect(self._show_conversations)
        menu.addAction(act_conv)
        act_exp = QAction(tr("Experten-Infos…"), self)
        act_exp.triggered.connect(self._show_expert_info)
        menu.addAction(act_exp)
        act_health = QAction(tr("TCP-Gesundheit…"), self)
        act_health.triggered.connect(self._show_tcp_health)
        menu.addAction(act_health)
        act_hier = QAction(tr("Protokoll-Hierarchie…"), self)
        act_hier.triggered.connect(self._show_hierarchy)
        menu.addAction(act_hier)
        act_dom = QAction(tr("Besuchte Domains…"), self)
        act_dom.triggered.connect(self._show_domains)
        menu.addAction(act_dom)
        act_dns = QAction(tr("DNS-Analyse…"), self)
        act_dns.triggered.connect(self._show_dns)
        menu.addAction(act_dns)
        act_ep = QAction(tr("Endpunkte & Ports…"), self)
        act_ep.triggered.connect(self._show_endpoints)
        menu.addAction(act_ep)
        act_conn = QAction(tr("Verbindungs-Status…"), self)
        act_conn.triggered.connect(self._show_conn_states)
        menu.addAction(act_conn)
        act_rtp = QAction(tr("RTP-Streams…"), self)
        act_rtp.triggered.connect(self._show_rtp)
        menu.addAction(act_rtp)
        act_proc = QAction(tr("Programmverkehr…"), self)
        act_proc.triggered.connect(self._show_processes)
        menu.addAction(act_proc)
        act_topo = QAction(tr("Netzwerk-Topologie…"), self)
        act_topo.triggered.connect(self._show_topology)
        menu.addAction(act_topo)
        act_dev = QAction(tr("Geräte-Übersicht / IP-Scan…"), self)
        act_dev.triggered.connect(self._show_devices)
        menu.addAction(act_dev)
        act_io = QAction(tr("IO-Graph…"), self)
        act_io.triggered.connect(self._show_io_graph)
        menu.addAction(act_io)
        act_ioc = QAction(tr("IOC-Abgleich…"), self)
        act_ioc.triggered.connect(self._show_ioc)
        menu.addAction(act_ioc)
        act_srt = QAction(tr("Service-Response-Time…"), self)
        act_srt.triggered.connect(self._show_srt)
        menu.addAction(act_srt)
        act_flow = QAction(tr("Flow-Graph…"), self)
        act_flow.triggered.connect(self._show_flowgraph)
        menu.addAction(act_flow)
        self.act_tcpflags = QAction(tr("TCP-Probleme markieren"), self, checkable=True)
        self.act_tcpflags.toggled.connect(self._toggle_tcp_flags)
        menu.addAction(self.act_tcpflags)
        act_goto = QAction(tr("Gehe zu Paket…"), self)
        act_goto.setShortcut(QKeySequence("Ctrl+G"))
        act_goto.triggered.connect(self._goto_packet)
        menu.addAction(act_goto)
        self.addAction(act_goto)
        menu.addSeparator()
        act_find = QAction(tr("Suchen…"), self)
        act_find.setShortcut(QKeySequence.Find)            # Strg+F
        act_find.triggered.connect(self._find)
        menu.addAction(act_find)
        act_next = QAction(tr("Weitersuchen"), self)
        act_next.setShortcut(QKeySequence(Qt.Key_F3))       # F3
        act_next.triggered.connect(self._find_next)
        menu.addAction(act_next)
        menu.addSeparator()
        exp = menu.addMenu(tr("Exportieren"))
        for label, kind in (("Pakete…", "packets"),
                            ("Verbindungen…", "conversations"),
                            ("Domains…", "domains")):
            a = QAction(tr(label), self)
            a.triggered.connect(lambda _c, k=kind: self._export(k))
            exp.addAction(a)

        tools_menu = self.menuBar().addMenu(tr("&Werkzeuge"))
        for label, cls in (("Ping…", PingDialog),
                          ("Traceroute…", TracerouteDialog),
                          ("DNS-Lookup…", DnsLookupDialog),
                          ("WHOIS…", WhoisDialog)):
            a = QAction(tr(label), self)
            a.triggered.connect(lambda _c, c=cls: c(self).exec())
            tools_menu.addAction(a)
        tools_menu.addSeparator()
        act_keys = QAction(tr("TLS-Schlüssel laden (SSLKEYLOGFILE)…"), self)
        act_keys.triggered.connect(self._load_keylog)
        tools_menu.addAction(act_keys)
        act_geo = QAction(tr("GeoIP-Datenbank laden (GeoLite2 .mmdb)…"), self)
        act_geo.triggered.connect(self._load_geoip)
        tools_menu.addAction(act_geo)

        view = self.menuBar().addMenu(tr("&Ansicht"))
        tmenu = view.addMenu(tr("Zeitformat"))
        self._time_group = QActionGroup(self)
        for label, mode in (("Relativ (seit Start)", "rel"),
                            ("Uhrzeit (Tageszeit)", "tod"),
                            ("Absolut (Epoch)", "abs")):
            act = QAction(tr(label), self, checkable=True)
            act.setChecked(mode == self.model.time_mode)
            act.triggered.connect(lambda _c, m=mode: self.model.set_time_mode(m))
            self._time_group.addAction(act)
            tmenu.addAction(act)

        view.addSeparator()
        act_mark = QAction(tr("Markierung umschalten"), self)
        act_mark.setShortcut(QKeySequence("Ctrl+M"))
        act_mark.triggered.connect(self._toggle_mark)
        view.addAction(act_mark)
        act_nmark = QAction(tr("Nächste Markierung"), self)
        act_nmark.setShortcut(QKeySequence(Qt.Key_F8))
        act_nmark.triggered.connect(self._next_mark)
        view.addAction(act_nmark)
        act_cmark = QAction(tr("Alle Markierungen löschen"), self)
        act_cmark.triggered.connect(self._clear_marks)
        view.addAction(act_cmark)
        view.addSeparator()
        self.act_names = QAction(tr("Namensspalte (Reverse-DNS)"), self,
                                 checkable=True)
        self.act_names.toggled.connect(self._toggle_name_column)
        view.addAction(self.act_names)
        self.act_proc = QAction(tr("Programmspalte"), self, checkable=True)
        self.act_proc.toggled.connect(self._toggle_proc_column)
        view.addAction(self.act_proc)
        view.addSeparator()
        act_colors = QAction(tr("Einfärbe-Regeln…"), self)
        act_colors.triggered.connect(self._edit_color_rules)
        view.addAction(act_colors)
        self.act_filtered_stats = QAction(tr("Statistik nur auf Filter"), self,
                                          checkable=True)
        view.addAction(self.act_filtered_stats)
        act_decode = QAction(tr("Decode As…"), self)
        act_decode.triggered.connect(self._edit_decode_as)
        view.addAction(act_decode)
        view.addSeparator()
        prof = view.addMenu(tr("Profile"))
        prof.addAction(tr("Profil speichern unter…")).triggered.connect(self._profile_save)
        prof.addAction(tr("Profil laden…")).triggered.connect(self._profile_load)
        prof.addAction(tr("Profil löschen…")).triggered.connect(self._profile_delete)
        view.addSeparator()
        self.act_light = QAction(tr("Helles Design"), self, checkable=True)
        self.act_light.toggled.connect(self._toggle_light)
        view.addAction(self.act_light)
        lmenu = view.addMenu("Sprache / Language")
        self._lang_group = QActionGroup(self)
        for code, name in LANGUAGES.items():
            act = QAction(name, self, checkable=True)
            act.setChecked(code == language())
            act.triggered.connect(lambda _c, c=code: self._set_language(c))
            self._lang_group.addAction(act)
            lmenu.addAction(act)
        # Shortcuts auch ohne offenes Menü aktiv halten.
        for a in (act_mark, act_nmark):
            self.addAction(a)

        cap = self.menuBar().addMenu(tr("Auf&nahme"))
        self.act_record = QAction(tr("Mitschnitt in Datei…"), self, checkable=True)
        self.act_record.setToolTip(tr("Pakete live in eine PCAP-Datei schreiben"))
        self.act_record.toggled.connect(self._toggle_recording)
        cap.addAction(self.act_record)
        act_limit = QAction(tr("Paketlimit (Ringpuffer)…"), self)
        act_limit.triggered.connect(self._set_packet_limit)
        cap.addAction(act_limit)
        act_capf = QAction(tr("Aufnahme-Filter…"), self)
        act_capf.triggered.connect(self._set_capture_filter)
        cap.addAction(act_capf)
        act_rot = QAction(tr("Mitschnitt mit Rotation…"), self)
        act_rot.triggered.connect(self._start_rotating)
        cap.addAction(act_rot)
        cap.addSeparator()
        self._recent_menu = cap.addMenu(tr("Zuletzt geöffnet"))
        if sys.platform == "win32" and not is_admin():
            cap.addSeparator()
            act_elev = QAction(tr("Als Administrator neu starten…"), self)
            act_elev.setToolTip(tr("Für die Live-Erfassung nötig (Raw-Socket)"))
            act_elev.triggered.connect(self._relaunch_admin)
            cap.addAction(act_elev)

        helpm = self.menuBar().addMenu(tr("&Hilfe"))
        act_manual = QAction(tr("Handbuch"), self)
        act_manual.setShortcut(QKeySequence.HelpContents)    # F1
        act_manual.triggered.connect(lambda: HelpDialog(self).exec())
        helpm.addAction(act_manual)
        act_about = QAction(tr("Über NetFett"), self)
        act_about.triggered.connect(
            lambda: QMessageBox.about(self, tr("Über NetFett"), about_text()))
        helpm.addAction(act_about)

    def _build_toolbar(self) -> None:
        tb = QToolBar(tr("Steuerung"), self)
        tb.setMovable(False)
        self.addToolBar(tb)

        self.iface_combo = QComboBox(self)
        self.iface_combo.setMinimumWidth(160)
        tb.addWidget(QLabel(tr(" Schnittstelle: ")))
        tb.addWidget(self.iface_combo)

        self.act_start = QAction(tr("▶ Start"), self)
        self.act_start.triggered.connect(self._start)
        tb.addAction(self.act_start)

        self.act_stop = QAction(tr("■ Stopp"), self)
        self.act_stop.setEnabled(False)
        self.act_stop.triggered.connect(self.controller.stop)
        tb.addAction(self.act_stop)

        self.act_clear = QAction(tr("Leeren"), self)
        self.act_clear.triggered.connect(self._clear)
        tb.addAction(self.act_clear)

        self.act_follow = QAction("⤓ Auto-Scroll", self)
        self.act_follow.setCheckable(True)
        self.act_follow.setChecked(True)
        self.act_follow.setToolTip(tr("Bei Live-Erfassung der neuesten Zeile folgen"))
        tb.addAction(self.act_follow)

        self.act_stats = QAction(tr("Statistik"), self)
        self.act_stats.setCheckable(True)
        self.act_stats.setChecked(True)
        self.act_stats.setToolTip(tr("Top-Protokolle und Top-Talkers ein-/ausblenden"))
        tb.addAction(self.act_stats)

        tb.addSeparator()
        self.act_open = QAction(tr("PCAP öffnen…"), self)
        self.act_open.triggered.connect(self._open_pcap)
        tb.addAction(self.act_open)
        self.act_save = QAction(tr("PCAP speichern…"), self)
        self.act_save.triggered.connect(self._save_pcap)
        tb.addAction(self.act_save)

        tb.addSeparator()
        tb.addWidget(QLabel(" Filter: "))
        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText(
            tr("z. B.  tcp dst port 443    |    dns or mdns    |    host 192.168.0.10"))
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.returnPressed.connect(self._apply_filter)
        self.filter_edit.textChanged.connect(self._on_filter_text)
        # Filter-Historie: ▼-Taste zeigt zuletzt genutzte Filter.
        self._filter_history: list[str] = []
        self._filter_hist_model = QStringListModel(self)
        completer = QCompleter(self._filter_hist_model, self)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        completer.setCompletionMode(QCompleter.UnfilteredPopupCompletion)
        self.filter_edit.setCompleter(completer)
        tb.addWidget(self.filter_edit)

    def _build_central(self) -> None:
        # Vertikaler Hauptsplitter: Graphen | Paketliste | Detail+Hex.
        outer = QSplitter(Qt.Vertical, self)

        graphs = QWidget(self)
        gl = QVBoxLayout(graphs)
        gl.setContentsMargins(0, 0, 0, 0)
        gl.setSpacing(2)
        self.graph_bps = GraphWidget(tr("Durchsatz"), "B/s", self)
        self.graph_pps = GraphWidget(tr("Pakete"), "P/s", self)
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
        hh.setStretchLastSection(False)
        for col, mode in {
            0: QHeaderView.ResizeToContents, 1: QHeaderView.ResizeToContents,
            5: QHeaderView.ResizeToContents, 6: QHeaderView.ResizeToContents,
            7: QHeaderView.Stretch,                  # Info füllt den Rest
            NAME_COL: QHeaderView.ResizeToContents,  # Name (Reverse-DNS)
            PROC_COL: QHeaderView.ResizeToContents,  # Programm
        }.items():
            hh.setSectionResizeMode(col, mode)
        # Reverse-DNS- und Programm-Spalte zunächst aus.
        self.model.set_name_provider(self.resolver.cached)
        self.table.setColumnHidden(NAME_COL, True)
        self.table.setColumnHidden(PROC_COL, True)
        # Sortierung per Spaltenkopf; Rechtsklick auf den Kopf blendet Spalten ein/aus.
        self.table.setSortingEnabled(True)
        hh.setSortIndicatorShown(True)
        hh.setContextMenuPolicy(Qt.CustomContextMenu)
        hh.customContextMenuRequested.connect(self._header_menu)
        self.table.selectionModel().currentRowChanged.connect(self._on_row)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_menu)
        outer.addWidget(self.table)

        bottom = QSplitter(Qt.Horizontal, self)
        self.detail = QTreeWidget(self)
        self.detail.setHeaderLabels([tr("Feld"), tr("Wert")])
        self.detail.setFont(_MONO)
        self.detail.itemSelectionChanged.connect(self._on_detail_selection)
        self.detail.setContextMenuPolicy(Qt.CustomContextMenu)
        self.detail.customContextMenuRequested.connect(self._detail_menu)
        bottom.addWidget(self.detail)

        self.hex = QPlainTextEdit(self)
        self.hex.setReadOnly(True)
        self.hex.setFont(_MONO)
        self.hex.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.content = QPlainTextEdit(self)
        self.content.setReadOnly(True)
        self.content.setFont(_MONO)
        # Rechts: umschaltbar zwischen Hex-Ansicht und Inhalt (Klartext/Bytes).
        self.right_tabs = QTabWidget(self)
        self.right_tabs.addTab(self.hex, "Hex")
        self.right_tabs.addTab(self.content, tr("Inhalt"))
        bottom.addWidget(self.right_tabs)
        bottom.setSizes([520, 560])
        outer.addWidget(bottom)

        outer.setStretchFactor(0, 0)
        outer.setStretchFactor(1, 3)
        outer.setStretchFactor(2, 2)
        outer.setSizes([150, 360, 250])
        self.setCentralWidget(outer)

    def _build_stats_dock(self) -> None:
        """Rechtes Andock-Panel: Top-Protokolle und Top-Talkers (1 s aktualisiert)."""
        dock = QDockWidget(tr("Statistik"), self)
        dock.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        body = QWidget(dock)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(6)

        # Umschaltbare Verteilung: Protokolle oder Programme.
        self.dist_mode = QComboBox(body)
        self.dist_mode.addItems([tr("Protokolle (nach Volumen)"),
                                 tr("Programme (nach Volumen)"),
                                 tr("Kategorien (nach Volumen)")])
        self.dist_mode.currentIndexChanged.connect(self._refresh_stats_panel)
        lay.addWidget(self.dist_mode)
        self.proto_donut = DonutChart("", "B", body)
        self.proto_donut.setMinimumHeight(150)
        self.proto_donut.sliceClicked.connect(self._filter_by_protocol)
        lay.addWidget(self.proto_donut)
        self.proto_tree = QTreeWidget(body)
        self.proto_tree.setHeaderLabels([tr("Protokoll"), tr("Pakete"), "Bytes", "%"])
        self.proto_tree.setRootIsDecorated(False)
        self.proto_tree.setFont(_MONO)
        lay.addWidget(self.proto_tree, 1)

        lay.addWidget(self._dock_caption(tr("Top-Talkers (Quelle ⇄ Ziel)")))
        self.talker_bars = BarChart("", "B", body)
        self.talker_bars.setMinimumHeight(130)
        lay.addWidget(self.talker_bars)
        self.talker_tree = QTreeWidget(body)
        self.talker_tree.setHeaderLabels([tr("Verbindung"), tr("Pakete"), "Bytes"])
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

    def _filter_by_protocol(self, label: str) -> None:
        """Klick auf ein Donut-Segment: nach Protokoll bzw. Programm filtern."""
        if self.dist_mode.currentIndex() == 2:       # Kategorien sind kein Filter
            self.lbl_state.setText(
                tr("Kategorie: {label} (kein direkter Filter)").format(label=label))
            return
        self._set_filter(label.lower())

    @staticmethod
    def _dock_caption(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color:#8b949e; font-weight:bold; padding:2px 0;")
        return lbl

    def _build_statusbar(self) -> None:
        sb = QStatusBar(self)
        self.setStatusBar(sb)
        self.lbl_state = QLabel(tr("Bereit"))
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
            QMessageBox.warning(self, "NetFett", tr("Keine Schnittstelle gewählt."))
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
            tr("Erfassung läuft auf {iface} …").format(
                iface=self.iface_combo.currentText()))
        self._sec_timer.start()

    def _on_stopped(self) -> None:
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self._sec_timer.stop()
        # Mitschnitt wurde vom Controller mit beendet → Menüpunkt enthaken.
        if self.act_record.isChecked():
            self.act_record.blockSignals(True)
            self.act_record.setChecked(False)
            self.act_record.blockSignals(False)
        self.lbl_state.setText(tr("Gestoppt"))

    def _on_error(self, msg: str) -> None:
        self._sec_timer.stop()
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.lbl_state.setText(tr("Fehler"))
        QMessageBox.critical(self, tr("NetFett – Fehler"), msg)

    # --- Datenfluss --------------------------------------------------------
    def _on_batch(self, batch: list[Packet]) -> None:
        for pkt in batch:
            self.stats.add(pkt)
            self.host_monitor.add(pkt)
        self.model.add_batch(batch)
        self._update_counts()
        if self.act_follow.isChecked() and self.model.shown:
            self.table.scrollToBottom()
        if self.act_names.isChecked():       # neue Gegenstellen mitauflösen
            self.resolver.resolve_async(
                {self.model._remote_ip(p) for p in batch if self.model._remote_ip(p)})
            if not self._name_timer.isActive():
                self._name_timer.start()

    def _on_second(self) -> None:
        self.stats.tick()
        self.host_monitor.tick()
        self._refresh_graphs()
        self._refresh_stats_panel()

    def _refresh_graphs(self) -> None:
        self.graph_bps.set_series(self.stats.in_bps, self.stats.out_bps)
        self.graph_pps.set_series(self.stats.in_pps, self.stats.out_pps)

    def _refresh_stats_panel(self) -> None:
        if not self._stats_dock.isVisible():
            return
        total = self.stats.total_bytes or 1
        mode = self.dist_mode.currentIndex()
        if mode == 1:                                # Programme
            rows = [(s.name, s.packets, s.bytes)
                    for s in aggregate_processes(self.model.all_packets)[:12]]
            header = tr("Programm")
        elif mode == 2:                              # Kategorien
            rows = [(s.name, s.packets, s.bytes)
                    for s in aggregate_categories(self.model.all_packets)[:12]]
            header = tr("Kategorie")
        else:                                        # Protokolle
            rows = list(self.stats.top_protocols(12))
            header = tr("Protokoll")
        self.proto_tree.setHeaderLabels([header, tr("Pakete"), "Bytes", "%"])
        if mode == 2:                                # Kategorie-Namen anzeigen
            rows = [(tr(n), p, b) for n, p, b in rows]
        self.proto_donut.set_data([(n, b) for n, _p, b in rows])
        self.proto_tree.clear()
        for name, pkts, byts in rows:
            pct = f"{100 * byts / total:.1f}"
            it = QTreeWidgetItem([name, str(pkts), human(byts), pct])
            for col in (1, 2, 3):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            if mode == 0:
                bg = _PROTO_BG.get(name)
                if bg:
                    it.setBackground(0, QColor(bg))
            self.proto_tree.addTopLevelItem(it)
        for col in range(4):
            self.proto_tree.resizeColumnToContents(col)

        talkers = self.stats.top_talkers(10)
        self.talker_bars.set_data([(n, b) for n, _p, b in talkers])
        self.talker_tree.clear()
        for name, pkts, byts in talkers:
            it = QTreeWidgetItem([name, str(pkts), human(byts)])
            for col in (1, 2):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            self.talker_tree.addTopLevelItem(it)
        self.talker_tree.resizeColumnToContents(0)

    def _update_counts(self) -> None:
        total = self.stats.total_packets
        shown = self.model.shown
        parts = [tr("Pakete: {shown}/{total}").format(shown=shown, total=total)]
        if self.model.max_packets:
            parts.append(tr("(Ring {n})").format(n=self.model.max_packets))
        if self.controller.dropped:
            parts.append(tr("verworfen {n}").format(n=self.controller.dropped))
        parts.append(f"▼ {human(self.stats.total_in_bytes)}")
        parts.append(f"▲ {human(self.stats.total_out_bytes)}")
        self.lbl_counts.setText("   ".join(parts))

    def _clear(self) -> None:
        self.model.clear()
        self.stats.reset()
        self.host_monitor.clear()
        self.detail.clear()
        self.hex.clear()
        self.content.clear()
        self.proto_tree.clear()
        self.talker_tree.clear()
        self.proto_donut.set_data([])
        self.talker_bars.set_data([])
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
        text = self.filter_edit.text()
        try:
            func = compile_filter(text)
        except FilterError as exc:
            self.lbl_state.setText(tr("Filterfehler: {exc}").format(exc=exc))
            return
        self.model.set_filter(func)
        self.lbl_state.setText(tr("Filter aktiv") if func else tr("Filter gelöscht"))
        self._remember_filter(text)
        self._update_counts()

    def _remember_filter(self, text: str) -> None:
        text = text.strip()
        if not text:
            return
        if text in self._filter_history:
            self._filter_history.remove(text)
        self._filter_history.insert(0, text)
        del self._filter_history[20:]            # auf 20 Einträge begrenzen
        self._filter_hist_model.setStringList(self._filter_history)

    # --- Auswahl: Detail-Baum + Hex ---------------------------------------
    def _on_row(self, current, _previous) -> None:
        pkt = self.model.packet_at(current.row()) if current.isValid() else None
        self._current_packet = pkt
        self._show_detail(pkt)
        self._show_hex(pkt.raw if pkt else b"")
        self._show_content(pkt)

    def _show_content(self, pkt: Packet | None) -> None:
        if pkt is None:
            self.content.clear()
            return
        kind, is_text, payload = content_view(pkt.raw)
        if pkt.direction == DIR_OUT:
            dlabel = tr("ausgehend ▲")
        elif pkt.direction == DIR_IN:
            dlabel = tr("eingehend ▼")
        else:
            dlabel = tr("Richtung ?")
        header = (tr("[{dir}]  {kind}  ({n} Bytes)").format(
            dir=dlabel, kind=tr(kind), n=len(payload)) + f"\n{'─' * 60}\n")
        body = as_text(payload) if is_text else _hexdump(payload)
        self.content.setPlainText(header + body)
        self.content.setLineWrapMode(
            QPlainTextEdit.WidgetWidth if is_text else QPlainTextEdit.NoWrap)

    def _show_detail(self, pkt: Packet | None) -> None:
        self.detail.clear()
        if pkt is None:
            return
        for layer in pkt.layers:
            head = tr(layer.name)
            top = QTreeWidgetItem([head, layer.summary])
            # Byte-Bereich der Schicht für Hex-Hervorhebung mitführen.
            top.setData(0, Qt.UserRole, (layer.start, layer.length))
            for label, value in layer.fields:
                child = QTreeWidgetItem([tr(label), value])
                # Originales (deutsches) Label für _field_filter merken.
                child.setData(0, _LABEL_ROLE, label)
                top.addChild(child)
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
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Speichern."))
            return
        # Bei aktivem Filter wählen lassen: alle oder nur angezeigte Pakete.
        if self.model.shown < len(packets):
            box = QMessageBox(self)
            box.setWindowTitle(tr("PCAP speichern"))
            box.setText(tr("{shown} von {total} Paketen sind durch den Filter "
                           "sichtbar.").format(shown=self.model.shown,
                                               total=len(packets)))
            box.setInformativeText(tr("Welche Pakete sollen gespeichert werden?"))
            b_shown = box.addButton(tr("Nur angezeigte"), QMessageBox.AcceptRole)
            box.addButton(tr("Alle"), QMessageBox.AcceptRole)
            box.addButton(QMessageBox.Cancel)
            box.exec()
            clicked = box.clickedButton()
            if clicked is None or box.buttonRole(clicked) == QMessageBox.RejectRole:
                return
            if clicked is b_shown:
                packets = self.model.view_packets
        path, selected = QFileDialog.getSaveFileName(
            self, tr("PCAP speichern"), "netfett.pcap",
            "PCAP (*.pcap);;PCAP-NG (*.pcapng)")
        if not path:
            return
        ng = path.lower().endswith(".pcapng") or "pcapng" in selected.lower()
        try:
            n = (write_pcapng(path, packets, comments=self.model.comments) if ng
                 else write_pcap(path, packets))
        except OSError as exc:
            QMessageBox.critical(self, tr("NetFett – Fehler"), str(exc))
            return
        fmt = "PCAP-NG" if ng else "PCAP"
        self.lbl_state.setText(tr("{n} Pakete als {fmt} gespeichert → {path}").format(
            n=n, fmt=fmt, path=path))

    def _open_pcap(self) -> None:
        if self.controller.running:
            QMessageBox.information(
                self, "NetFett", tr("Bitte zuerst die laufende Erfassung stoppen."))
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self, tr("PCAP/PCAPNG öffnen (Mehrfachauswahl = zusammenführen)"), "",
            tr("Capture-Dateien (*.pcap *.pcapng *.cap);;Alle Dateien (*)"))
        if paths:
            self._load_capture(paths)

    def _load_capture(self, paths: list) -> None:
        if self.controller.running:
            QMessageBox.information(
                self, "NetFett", tr("Bitte zuerst die laufende Erfassung stoppen."))
            return
        try:
            records = merge_captures(paths) if len(paths) > 1 \
                else read_capture(paths[0])
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, tr("NetFett – Fehler"), str(exc))
            return
        self._clear()
        local = set(local_ipv4_addresses())
        reasm = IPReassembler()
        batch = []
        for i, (ts, raw) in enumerate(records):
            state, full, count = reasm.add(raw)
            pkt = dissect(full if state == "reassembled" else raw, ts, i + 1, local)
            if state == "reassembled":
                pkt.info = tr("[reassembliert: {count} Fragmente]").format(
                    count=count) + f" {pkt.info}"
            batch.append(pkt)
        self._on_batch(batch)
        self.stats.tick()
        self._refresh_graphs()
        self._refresh_stats_panel()
        for p in paths:
            self._add_recent(p)
        src = paths[0] if len(paths) == 1 else tr("{n} Dateien").format(n=len(paths))
        self.lbl_state.setText(tr("{n} Pakete geladen ← {src}").format(n=len(batch), src=src))

    # --- Zuletzt geöffnete Dateien ----------------------------------------
    def _add_recent(self, path: str) -> None:
        recent = self._settings.value("recentFiles", [], type=list) or []
        recent = [p for p in recent if p != path]
        recent.insert(0, path)
        del recent[8:]
        self._settings.setValue("recentFiles", recent)
        self._update_recent_menu()

    def _update_recent_menu(self) -> None:
        self._recent_menu.clear()
        recent = self._settings.value("recentFiles", [], type=list) or []
        if not recent:
            self._recent_menu.addAction(tr("(keine)")).setEnabled(False)
            return
        for path in recent:
            self._recent_menu.addAction(path).triggered.connect(
                lambda _c=False, p=path: self._load_capture([p]))

    # --- Profile (benannte Einstellungs-Sätze) -----------------------------
    def _profile_keys(self) -> dict:
        return {
            "light": self.act_light.isChecked(),
            "autoScroll": self.act_follow.isChecked(),
            "nameColumn": self.act_names.isChecked(),
            "procColumn": self.act_proc.isChecked(),
            "statsDock": self.act_stats.isChecked(),
            "maxPackets": self.model.max_packets,
            "colorRules": json.dumps(self.ruleset.to_list()),
        }

    def _profile_save(self) -> None:
        name, ok = QInputDialog.getText(self, tr("Profil speichern"), tr("Name:"))
        if not ok or not name.strip():
            return
        self._settings.beginGroup(f"profiles/{name.strip()}")
        for key, value in self._profile_keys().items():
            self._settings.setValue(key, value)
        self._settings.endGroup()
        self.lbl_state.setText(tr("Profil {name} gespeichert.").format(name=name.strip()))

    def _profile_names(self) -> list:
        self._settings.beginGroup("profiles")
        names = self._settings.childGroups()
        self._settings.endGroup()
        return names

    def _profile_load(self) -> None:
        names = self._profile_names()
        if not names:
            QMessageBox.information(self, "NetFett", tr("Keine Profile gespeichert."))
            return
        name, ok = QInputDialog.getItem(self, tr("Profil laden"), tr("Profil:"),
                                        names, 0, False)
        if not ok:
            return
        s = self._settings
        s.beginGroup(f"profiles/{name}")
        self.act_light.setChecked(s.value("light", False, type=bool))
        self.act_follow.setChecked(s.value("autoScroll", True, type=bool))
        self.act_names.setChecked(s.value("nameColumn", False, type=bool))
        self.act_proc.setChecked(s.value("procColumn", False, type=bool))
        self.act_stats.setChecked(s.value("statsDock", True, type=bool))
        self.model.set_max_packets(s.value("maxPackets", 0, type=int))
        cr = s.value("colorRules", "", type=str)
        s.endGroup()
        if cr:
            try:
                self.ruleset = RuleSet.from_list(json.loads(cr))
                self.model.set_color_rules(self.ruleset)
                self.table.viewport().update()
            except (ValueError, TypeError):
                pass
        self.lbl_state.setText(tr("Profil {name} geladen.").format(name=name))

    def _profile_delete(self) -> None:
        names = self._profile_names()
        if not names:
            QMessageBox.information(self, "NetFett", tr("Keine Profile vorhanden."))
            return
        name, ok = QInputDialog.getItem(self, tr("Profil löschen"), tr("Profil:"),
                                        names, 0, False)
        if ok:
            self._settings.remove(f"profiles/{name}")
            self.lbl_state.setText(tr("Profil {name} gelöscht.").format(name=name))

    # --- Analyse -----------------------------------------------------------
    def _analysis_packets(self) -> list:
        """Pakete für Analysen: gefiltert oder alle (je nach Umschalter)."""
        if self.act_filtered_stats.isChecked():
            return self.model.view_packets
        return self.model.all_packets

    def _edit_decode_as(self) -> None:
        from .pro_dialogs import DecodeAsDialog
        from ..core.dissect import get_decode_as, set_decode_as
        dlg = DecodeAsDialog(get_decode_as(), self)
        if not dlg.exec():
            return
        set_decode_as(dlg.result_map())
        self._redissect()

    def _redissect(self) -> None:
        """Zerlegt alle vorhandenen Pakete neu (z. B. nach Decode-As-Änderung)."""
        old = self.model.all_packets
        if not old:
            return
        local = set()
        for p in old:
            if p.direction == DIR_OUT and p.src:
                local.add(p.src)
            elif p.direction == DIR_IN and p.dst:
                local.add(p.dst)
        rebuilt = [dissect(p.raw, p.ts, p.number, local) for p in old]
        for new, p in zip(rebuilt, old):
            new.process = p.process          # Prozesszuordnung erhalten
        self.model.clear()
        self.stats.reset()
        self._on_batch(rebuilt)
        self.lbl_state.setText(tr("Neu zerlegt (Decode-As angewendet)."))

    def _show_conversations(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        dlg = ConversationsDialog(pkts, self, resolver=self.resolver,
                                  keylog=self.keylog)
        dlg.followRequested.connect(self._follow_stream)
        dlg.filterRequested.connect(self._set_filter)
        dlg.exec()

    def _show_expert_info(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        dlg = ExpertInfoDialog(pkts, self)
        dlg.jumpToPacket.connect(self._jump_to_packet)
        dlg.exec()

    def _show_tcp_health(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        TcpHealthDialog(pkts, self).exec()

    def _show_hierarchy(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        ProtocolHierarchyDialog(pkts, self).exec()

    def _show_domains(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        dlg = DomainsDialog(pkts, self)
        dlg.filterRequested.connect(self._set_filter)
        dlg.exec()

    def _show_dns(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        dlg = DnsAnalysisDialog(pkts, self)
        dlg.filterRequested.connect(self._set_filter)
        dlg.exec()

    def _show_endpoints(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        dlg = EndpointsDialog(pkts, self)
        dlg.filterRequested.connect(self._set_filter)
        dlg.exec()

    def _show_conn_states(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        dlg = ConnectionStatesDialog(pkts, self)
        dlg.filterRequested.connect(self._set_filter)
        dlg.exec()

    def _show_rtp(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        dlg = RtpStreamsDialog(pkts, self)
        dlg.filterRequested.connect(self._set_filter)
        dlg.exec()

    def _show_processes(self) -> None:
        # Live-Dialog: liest fortlaufend aus dem Modell (kein Snapshot nötig).
        dlg = ProcessTrafficDialog(self.model, self)
        dlg.filterRequested.connect(self._set_filter)
        dlg.exec()

    def _show_devices(self) -> None:
        local = self.iface_combo.currentText().strip() or primary_ipv4()
        # Nicht-modal: bleibt als Dashboard offen, während man die gefilterte
        # Hauptansicht betrachtet.
        dlg = DevicesDialog(self.host_monitor, self.resolver, local, self)
        dlg.filterRequested.connect(self._set_filter)
        self._devices_dlg = dlg              # Referenz halten (gegen GC)
        dlg.show()

    def _show_topology(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        local = set()
        for p in pkts:
            if p.direction == DIR_OUT and p.src:
                local.add(p.src)
            elif p.direction == DIR_IN and p.dst:
                local.add(p.dst)
        nodes, edges = build_topology(pkts, local, 24)
        TopologyDialog(nodes, edges, self).exec()

    def _show_io_graph(self) -> None:
        IoGraphDialog(self.model, self).exec()

    def _show_ioc(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        dlg = IocDialog(pkts, self)
        dlg.jumpToPacket.connect(self._jump_to_packet)
        dlg.markRequested.connect(self._mark_numbers)
        dlg.exec()

    def _mark_numbers(self, numbers: set) -> None:
        self.model.add_marks(numbers)
        self.lbl_state.setText(tr("{n} IOC-Treffer markiert.").format(n=len(numbers)))

    def _show_srt(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        SrtDialog(pkts, self).exec()

    def _show_flowgraph(self) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Analysieren."))
            return
        FlowGraphDialog(pkts, parent=self).exec()

    def _toggle_tcp_flags(self, on: bool) -> None:
        if on:
            flags = tcp_expert_flags(self.model.all_packets)
            self.model.set_expert_flags(flags)
            self.lbl_state.setText(
                tr("{n} TCP-Auffälligkeiten markiert "
                   "(Retransmission/Dup-ACK/Out-of-Order).").format(n=len(flags)))
        else:
            self.model.set_expert_flags({})

    def _goto_packet(self) -> None:
        n, ok = QInputDialog.getInt(self, tr("Gehe zu Paket"), tr("Paketnummer:"),
                                    1, 1, 1_000_000_000)
        if ok:
            self._jump_to_packet(n)

    def _edit_color_rules(self) -> None:
        dlg = ColoringRulesDialog(self.ruleset.rules, self)
        if dlg.exec():
            self.ruleset = RuleSet(dlg.result_rules())
            self.model.set_color_rules(self.ruleset)
            self.table.viewport().update()

    def _follow_stream(self, conv: Conversation) -> None:
        FollowStreamDialog(self.model.all_packets, conv, self,
                           keylog=self.keylog).exec()

    def _autoload_keylog(self) -> None:
        path = os.environ.get("SSLKEYLOGFILE")
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    self.keylog = parse_keylog(f.read())
            except OSError:
                pass

    def _load_keylog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("TLS-Schlüssel (SSLKEYLOGFILE) laden"), "",
            tr("Keylog-Dateien (*.log *.keys *.txt);;Alle Dateien (*)"))
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                self.keylog = parse_keylog(f.read())
        except OSError as exc:
            QMessageBox.critical(self, tr("NetFett – Fehler"), str(exc))
            return
        self.lbl_state.setText(
            tr("{n} TLS-Schlüssel geladen (Follow-Stream: Entschlüsseln)")
            .format(n=len(self.keylog)))

    def _load_geoip(self) -> None:
        if not geoip.lib_available():
            QMessageBox.information(
                self, "GeoIP",
                tr("Für GeoIP wird das Paket 'maxminddb' benötigt:\n\n"
                   "    pip install maxminddb\n\n"
                   "Anschließend eine GeoLite2-Datei (Country/City/ASN) von "
                   "MaxMind laden."))
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self, tr("GeoLite2-Datenbank(en) laden"), "",
            tr("MaxMind-DB (*.mmdb);;Alle Dateien (*)"))
        if not paths:
            return
        msgs = [geoip.add_database(p) for p in paths]
        self._save_settings()
        QMessageBox.information(self, "GeoIP", "\n".join(msgs))
        self.lbl_state.setText(geoip.status())

    def _export(self, kind: str) -> None:
        pkts = self._analysis_packets()
        if not pkts:
            QMessageBox.information(self, "NetFett", tr("Keine Pakete zum Export."))
            return
        path, selected = QFileDialog.getSaveFileName(
            self, tr("Exportieren"), f"netfett-{kind}.csv",
            tr("CSV-Dateien (*.csv);;JSON-Dateien (*.json)"))
        if not path:
            return
        fmt = "json" if path.lower().endswith(".json") \
            or "json" in selected.lower() else "csv"
        builder = {"packets": export_packets,
                   "conversations": export_conversations,
                   "domains": export_domains}[kind]
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(builder(pkts, fmt))
        except OSError as exc:
            QMessageBox.critical(self, tr("NetFett – Fehler"), str(exc))
            return
        self.lbl_state.setText(tr("Export ({fmt}) → {path}").format(
            fmt=fmt.upper(), path=path))

    # --- Suche -------------------------------------------------------------
    def _find(self) -> None:
        term, ok = QInputDialog.getText(
            self, tr("Suchen"), tr("Begriff (Quelle/Ziel/Protokoll/Info):"),
            text=self._find_term)
        if ok and term:
            self._find_term = term
            self._find_from(self.table.currentIndex().row() + 1)

    def _find_next(self) -> None:
        if self._find_term:
            self._find_from(self.table.currentIndex().row() + 1)
        else:
            self._find()

    # --- Markierungen ------------------------------------------------------
    def _toggle_mark(self) -> None:
        row = self.table.currentIndex().row()
        if row < 0:
            return
        self.model.toggle_mark(row)
        self.lbl_state.setText(
            tr("{n} Paket(e) markiert").format(n=self.model.marked_count))

    def _next_mark(self) -> None:
        row = self.model.next_marked_row(self.table.currentIndex().row() + 1)
        if row < 0:
            self.lbl_state.setText(tr("Keine Markierungen."))
            return
        idx = self.model.index(row, 0)
        self.table.setCurrentIndex(idx)
        self.table.scrollTo(idx, QTableView.PositionAtCenter)

    def _clear_marks(self) -> None:
        self.model.clear_marks()
        self.lbl_state.setText(tr("Markierungen gelöscht."))

    # --- Reverse-DNS-Spalte ------------------------------------------------
    def _toggle_proc_column(self, on: bool) -> None:
        self.table.setColumnHidden(PROC_COL, not on)

    def _toggle_name_column(self, on: bool) -> None:
        self.table.setColumnHidden(NAME_COL, not on)
        if on:
            ips = self.model.remote_ips()
            self.resolver.resolve_async(ips)
            self._name_timer.start()
            self.model.refresh_names()
            self.lbl_state.setText(
                tr("Löse {n} Hosts auf (Reverse-DNS) …").format(n=len(ips)))
        else:
            self._name_timer.stop()

    def _poll_names(self) -> None:
        self.model.refresh_names()
        if self.resolver.pending == 0:
            self._name_timer.stop()
            self.lbl_state.setText(tr("Namensauflösung abgeschlossen."))

    def _toggle_light(self, light: bool) -> None:
        """Schaltet zwischen hellem und dunklem Design um."""
        from PySide6.QtWidgets import QApplication
        apply_theme(QApplication.instance(), dark=not light)
        for wdg in (self.graph_bps, self.graph_pps,
                    self.proto_donut, self.talker_bars):
            wdg.update()
        self.table.viewport().update()      # Zeilenfarben neu zeichnen

    # --- Langzeit-Erfassung (Mitschnitt / Ringpuffer / Aufnahme-Filter) ----
    def _toggle_recording(self, on: bool) -> None:
        if on:
            path, _ = QFileDialog.getSaveFileName(
                self, tr("Live-Mitschnitt"), "netfett-live.pcap",
                tr("PCAP-Dateien (*.pcap)"))
            if not path:
                self.act_record.setChecked(False)   # Auswahl abgebrochen
                return
            self.controller.start_recording(path)
            self._record_path = path
            self.lbl_state.setText(tr("Mitschnitt läuft → {path}").format(path=path))
        else:
            count = self.controller.stop_recording()
            self.lbl_state.setText(
                tr("Mitschnitt beendet ({n} Pakete)").format(n=count))

    def _set_language(self, code: str) -> None:
        """Sprache speichern; wirksam nach Neustart (auf Wunsch sofort)."""
        if code == language():
            return
        self._settings.setValue(SETTINGS_KEY, code)
        # Rückfrage in der Zielsprache, damit sie auch verstanden wird.
        if code == "en":
            title, text = ("Language", "The language will change after a "
                           "restart. Restart NetFett now?")
        else:
            title, text = ("Sprache", "Die Sprache wird nach einem Neustart "
                           "übernommen. NetFett jetzt neu starten?")
        if QMessageBox.question(self, title, text) != QMessageBox.Yes:
            return
        if self.controller.running:
            self.controller.stop()
        if getattr(sys, "frozen", False):        # PyInstaller-Build (.exe)
            program, args = sys.executable, sys.argv[1:]
        else:
            program, args = sys.executable, ["-m", "netfett", *sys.argv[1:]]
        if QProcess.startDetached(program, args):
            self.close()

    def _relaunch_admin(self) -> None:
        if self.controller.running:
            self.controller.stop()
        if relaunch_as_admin():
            self.close()                 # elevierte Instanz übernimmt
        else:
            QMessageBox.information(
                self, "NetFett",
                tr("Neustart als Administrator wurde abgebrochen oder ist "
                   "fehlgeschlagen."))

    def _start_rotating(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, tr("Rotierender Mitschnitt (Basisname)"), "netfett.pcap",
            tr("PCAP-Dateien (*.pcap)"))
        if not path:
            return
        mb, ok = QInputDialog.getInt(self, tr("Rotation"),
                                     tr("Max. Dateigröße (MB):"), 50, 1, 10000)
        if not ok:
            return
        keep, ok = QInputDialog.getInt(self, tr("Rotation"),
                                       tr("Anzahl Dateien behalten:"), 5, 1, 1000)
        if not ok:
            return
        self.controller.start_recording_rotating(path, mb * 1024 * 1024, keep)
        self.act_record.blockSignals(True)
        self.act_record.setChecked(True)
        self.act_record.blockSignals(False)
        self.lbl_state.setText(
            tr("Rotierender Mitschnitt → {path} ({mb} MB × {keep})").format(
                path=path, mb=mb, keep=keep))

    def _set_packet_limit(self) -> None:
        n, ok = QInputDialog.getInt(
            self, tr("Paketlimit"),
            tr("Max. Pakete im Speicher (0 = unbegrenzt):"),
            self.model.max_packets, 0, 100_000_000, 1000)
        if not ok:
            return
        self.model.set_max_packets(n)
        self.lbl_state.setText(
            tr("Ringpuffer: {n} Pakete").format(n=n) if n
            else tr("Ringpuffer: unbegrenzt"))
        self._update_counts()

    def _set_capture_filter(self) -> None:
        text, ok = QInputDialog.getText(
            self, tr("Aufnahme-Filter"),
            tr("Nur passende Pakete aufnehmen (gleiche Syntax wie Anzeigefilter):"),
            text=getattr(self, "_capture_filter_text", ""))
        if not ok:
            return
        try:
            func = compile_filter(text)
        except FilterError as exc:
            QMessageBox.warning(self, "NetFett",
                                tr("Filterfehler: {exc}").format(exc=exc))
            return
        self._capture_filter_text = text
        self.controller.set_capture_filter(func)
        self.lbl_state.setText(
            tr("Aufnahme-Filter aktiv") if func
            else tr("Aufnahme-Filter gelöscht"))

    def _find_from(self, start: int) -> None:
        n = self.model.shown
        if n == 0:
            return
        term = self._find_term.lower()
        start = max(0, start)
        order = list(range(start, n)) + list(range(0, start))  # mit Umlauf
        for row in order:
            pkt = self.model.packet_at(row)
            if pkt is not None and _pkt_matches(pkt, term):
                idx = self.model.index(row, 0)
                self.table.setCurrentIndex(idx)
                self.table.scrollTo(idx, QTableView.PositionAtCenter)
                self.lbl_state.setText(
                    tr("Treffer: Zeile {row} (F3 = weiter)").format(row=row + 1))
                return
        self.lbl_state.setText(
            tr("Kein Treffer für „{term}“.").format(term=self._find_term))

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
            tr("Paket {n} nicht sichtbar (evtl. vom Filter ausgeblendet).")
            .format(n=number))

    def _table_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        pkt = self.model.packet_at(index.row()) if index.isValid() else None
        if pkt is None:
            return
        menu = QMenu(self)
        if (pkt.l4 == "TCP" or pkt.protocol == "TCP") and pkt.src_port and pkt.dst_port:
            act = menu.addAction(tr("TCP-Stream folgen…"))
            act.triggered.connect(lambda: self._follow_stream(
                Conversation(proto="TCP", a=pkt.src, a_port=pkt.src_port,
                             b=pkt.dst, b_port=pkt.dst_port)))
            menu.addSeparator()
        menu.addAction(tr("Als Filter: diese Verbindung")).triggered.connect(
            lambda: self._set_filter(f"host {pkt.src} host {pkt.dst}"))
        menu.addAction(tr("Als Filter: {flt}").format(flt=f"host {pkt.src}")).triggered.connect(
            lambda: self._set_filter(f"host {pkt.src}"))
        menu.addAction(tr("Als Filter: {flt}").format(flt=f"host {pkt.dst}")).triggered.connect(
            lambda: self._set_filter(f"host {pkt.dst}"))
        if pkt.dst_port:
            menu.addAction(
                tr("Als Filter: {flt}").format(flt=f"port {pkt.dst_port}")).triggered.connect(
                lambda: self._set_filter(f"port {pkt.dst_port}"))
        menu.addSeparator()
        menu.addAction(tr("Kommentar…")).triggered.connect(
            lambda: self._edit_comment(pkt.number))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _edit_comment(self, number: int) -> None:
        text, ok = QInputDialog.getText(
            self, tr("Paket-Kommentar"),
            tr("Kommentar zu Paket {n}:").format(n=number),
            text=self.model.comment(number))
        if ok:
            self.model.set_comment(number, text.strip())

    def _header_menu(self, pos) -> None:
        menu = QMenu(self)
        menu.addAction(tr("Spalten anzeigen:")).setEnabled(False)
        menu.addSeparator()
        for col in range(self.model.columnCount()):
            act = menu.addAction(tr(COLUMNS[col]))
            act.setCheckable(True)
            act.setChecked(not self.table.isColumnHidden(col))
            act.toggled.connect(
                lambda on, c=col: self.table.setColumnHidden(c, not on))
        menu.exec(self.table.horizontalHeader().mapToGlobal(pos))

    def _detail_menu(self, pos) -> None:
        item = self.detail.itemAt(pos)
        if item is None:
            return
        label = item.text(0)                      # angezeigt (ggf. übersetzt)
        orig = item.data(0, _LABEL_ROLE) or label   # deutsches Original
        value = item.text(1)
        menu = QMenu(self)
        if value:
            menu.addAction(tr("Wert kopieren")).triggered.connect(
                lambda: QGuiApplication.clipboard().setText(value))
        menu.addAction(tr("Feld kopieren")).triggered.connect(
            lambda: QGuiApplication.clipboard().setText(
                f"{label}: {value}".strip(": ")))
        flt = _field_filter(orig, value)
        if flt:
            menu.addSeparator()
            menu.addAction(tr("Als Filter: {flt}").format(flt=flt)).triggered.connect(
                lambda: self._set_filter(flt))
        menu.exec(self.detail.viewport().mapToGlobal(pos))

    # --- Einstellungen (persistent über QSettings) -------------------------
    def _load_settings(self) -> None:
        s = self._settings
        geo = s.value("ui/geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        if s.value("ui/light", False, type=bool):
            self.act_light.setChecked(True)
        if not s.value("ui/autoScroll", True, type=bool):
            self.act_follow.setChecked(False)
        if not s.value("ui/statsDock", True, type=bool):
            self.act_stats.setChecked(False)
        if s.value("ui/nameColumn", False, type=bool):
            self.act_names.setChecked(True)
        if s.value("ui/procColumn", False, type=bool):
            self.act_proc.setChecked(True)
        limit = s.value("capture/maxPackets", 0, type=int)
        if limit:
            self.model.set_max_packets(limit)
        flt = s.value("capture/filter", "", type=str)
        if flt:
            try:
                self.controller.set_capture_filter(compile_filter(flt))
                self._capture_filter_text = flt
            except FilterError:
                pass
        rules_json = s.value("ui/colorRules", "", type=str)
        if rules_json:
            try:
                self.ruleset = RuleSet.from_list(json.loads(rules_json))
                self.model.set_color_rules(self.ruleset)
            except (ValueError, TypeError):
                pass
        geo_paths = s.value("geoip/databases", "", type=str)
        if geo_paths and geoip.lib_available():
            for p in geo_paths.split("\n"):
                if p.strip() and os.path.exists(p):
                    geoip.add_database(p)

    def _save_settings(self) -> None:
        s = self._settings
        s.setValue("ui/geometry", self.saveGeometry())
        s.setValue("ui/light", self.act_light.isChecked())
        s.setValue("ui/autoScroll", self.act_follow.isChecked())
        s.setValue("ui/statsDock", self.act_stats.isChecked())
        s.setValue("ui/nameColumn", self.act_names.isChecked())
        s.setValue("ui/procColumn", self.act_proc.isChecked())
        s.setValue("capture/maxPackets", self.model.max_packets)
        s.setValue("capture/filter", getattr(self, "_capture_filter_text", ""))
        s.setValue("ui/colorRules", json.dumps(self.ruleset.to_list()))
        s.setValue("geoip/databases", "\n".join(geoip.databases()))

    # --- Lebenszyklus ------------------------------------------------------
    def closeEvent(self, event) -> None:
        self._save_settings()
        if self.controller.running:
            self.controller.stop()
        super().closeEvent(event)


def _field_filter(label: str, value: str) -> str:
    """Baut aus einem Detail-Feld einen Anzeigefilter (oder leer)."""
    value = value.strip()
    if not value:
        return ""
    if label in ("Quelle", "Ziel"):
        return f"host {value}"
    if label == "Quell-Port":
        return f"src port {value}"
    if label == "Ziel-Port":
        return f"dst port {value}"
    return ""


def _pkt_matches(pkt: Packet, needle: str) -> bool:
    """Teilstring-Treffer in Quelle/Ziel/Protokoll/Info/Ports (für die Suche)."""
    hay = (f"{pkt.src} {pkt.dst} {pkt.protocol} {pkt.info} "
           f"{pkt.src_port or ''} {pkt.dst_port or ''}").lower()
    return needle in hay


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
