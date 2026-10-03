"""Dialoge der Analyse-Features: Verbindungen, Experten-Infos, Follow-Stream.

Die Dialoge sind dünne Sichten auf die reine :mod:`netfett.core.analyze`-Schicht
und melden Benutzeraktionen (Filter setzen, zu Paket springen, Stream folgen) per
Qt-Signal an das Hauptfenster zurück.
"""
from __future__ import annotations

from collections import deque

from PySide6.QtCore import QPointF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QMessageBox,
    QPlainTextEdit, QPushButton, QScrollArea, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from ..core.analyze import (
    Conversation, HierNode, SeqEvent, StreamResult, connection_states,
    conversations, dns_analysis, domains, endpoints, expert_info, follow_stream,
    io_buckets, port_stats, protocol_hierarchy, rtp_streams, sequence,
    service_response_times, size_histogram, tcp_health,
)
from ..core import geoip
from ..core.extract import http_objects
from ..core.hpack import decode_http2_headers
from ..core.models import Packet
from ..core.procmap import aggregate_processes
from ..core.resolve import NameResolver
from ..core.tlssession import decrypt_conversation
from ..i18n import tr
from .charts import BarChart, DonutChart, MultiLineChart
from .pro_dialogs import ObjectExtractDialog, StreamGraphDialog
from .graph_widget import GraphWidget, human
from .theme import THEME

_MONO = QFont("Consolas", 9)
_CLIENT_COLOR = "#5aa9ff"
_SERVER_COLOR = "#ffb454"
_SEV_COLOR = {"info": "#8b949e", "note": "#58a6ff",
              "warn": "#d29922", "error": "#f85149"}


def _ep(ip: str, port) -> str:
    return f"{ip}:{port}" if port is not None else ip


def _ep_named(ip: str, port, name: str | None) -> str:
    """Endpunkt mit angehängtem PTR-Namen, sofern aufgelöst."""
    base = _ep(ip, port)
    return f"{base}  ({name})" if name else base


# --------------------------------------------------------------------------- #
class ConversationsDialog(QDialog):
    """Tabelle aller Verbindungen; Doppelklick folgt dem TCP-Stream."""
    followRequested = Signal(object)   # Conversation
    filterRequested = Signal(str)

    COLS = [tr("Protokoll"), tr("Endpunkt A"), tr("Endpunkt B"), tr("Pakete"),
            "A→B", "B→A", tr("Bytes"), tr("Dauer"), tr("Durchsatz")]

    def __init__(self, packets: list[Packet], parent=None,
                 resolver: NameResolver | None = None,
                 keylog: dict | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Verbindungen"))
        self.resize(860, 540)
        self._resolver = resolver
        self._keylog = keylog or {}
        self._packets = packets
        lay = QVBoxLayout(self)

        convs = conversations(packets)
        self._convs = convs
        self._items: list[QTreeWidgetItem] = []
        lay.addWidget(QLabel(tr("{convs} Verbindung(en) aus {packets} Paketen")
                             .format(convs=len(convs), packets=len(packets))))

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        self.tree.setSortingEnabled(False)
        for i, c in enumerate(convs):
            it = QTreeWidgetItem([
                c.proto, _ep(c.a, c.a_port), _ep(c.b, c.b_port),
                str(c.packets),
                f"{c.a2b_pkts}/{human(c.a2b_bytes)}",
                f"{c.b2a_pkts}/{human(c.b2a_bytes)}",
                human(c.bytes),
                f"{c.duration:.3f}s",
                human(c.bps / 8, "B/s") if c.bps else "—",
            ])
            it.setData(0, Qt.UserRole, i)
            for col in (3, 4, 5, 6, 7, 8):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            self.tree.addTopLevelItem(it)
            self._items.append(it)
        for col in range(len(self.COLS)):
            self.tree.resizeColumnToContents(col)
        self.tree.itemDoubleClicked.connect(self._double)
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        lay.addWidget(self.tree, 1)

        # IO-Zeitdiagramm der gewählten Verbindung (Bytes/s je Richtung).
        self.io_graph = GraphWidget(tr("Verlauf – Verbindung wählen"), "B/s", self)
        self.io_graph.setMinimumHeight(120)
        self.io_graph.setMaximumHeight(160)
        lay.addWidget(self.io_graph)

        row = QHBoxLayout()
        self.btn_follow = QPushButton(tr("Stream folgen"), self)
        self.btn_follow.setEnabled(False)
        self.btn_follow.clicked.connect(self._follow)
        self.btn_filter = QPushButton(tr("Als Filter setzen"), self)
        self.btn_filter.setEnabled(False)
        self.btn_filter.clicked.connect(self._filter)
        self.btn_seq = QPushButton(tr("Sequenz…"), self)
        self.btn_seq.setEnabled(False)
        self.btn_seq.setToolTip(tr("Paketfluss als Sequenzdiagramm"))
        self.btn_seq.clicked.connect(self._show_sequence)
        self.btn_graph = QPushButton(tr("Stream-Graph…"), self)
        self.btn_graph.setEnabled(False)
        self.btn_graph.clicked.connect(self._show_graph)
        self.btn_objects = QPushButton(tr("Objekte…"), self)
        self.btn_objects.setEnabled(False)
        self.btn_objects.setToolTip(tr("Dateien/Objekte aus HTTP (auch entschlüsselt)"))
        self.btn_objects.clicked.connect(self._show_objects)
        self.btn_resolve = QPushButton(tr("Namen auflösen"), self)
        self.btn_resolve.setToolTip(tr("Reverse-DNS (PTR) der Endpunkt-IPs"))
        self.btn_resolve.clicked.connect(self._resolve_names)
        row.addWidget(self.btn_follow)
        row.addWidget(self.btn_seq)
        row.addWidget(self.btn_graph)
        row.addWidget(self.btn_objects)
        row.addWidget(self.btn_filter)
        row.addWidget(self.btn_resolve)
        row.addStretch(1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        row.addWidget(close)
        lay.addLayout(row)

        # Poll-Timer aktualisiert die Zellen, während die Auflösung läuft.
        self._poll = QTimer(self)
        self._poll.setInterval(350)
        self._poll.timeout.connect(self._apply_names)

    def _resolve_names(self) -> None:
        if self._resolver is None:
            return
        ips = {c.a for c in self._convs} | {c.b for c in self._convs}
        self.btn_resolve.setEnabled(False)
        self.btn_resolve.setText(tr("Löse auf …"))
        self._resolver.resolve_async(ips)
        self._poll.start()
        self._apply_names()

    def _apply_names(self) -> None:
        """Hängt aufgelöste Namen an die Endpunkt-Spalten (aus dem Cache)."""
        r = self._resolver
        if r is None:
            return
        for it, c in zip(self._items, self._convs):
            it.setText(1, _ep_named(c.a, c.a_port, r.cached(c.a)))
            it.setText(2, _ep_named(c.b, c.b_port, r.cached(c.b)))
        self.tree.resizeColumnToContents(1)
        self.tree.resizeColumnToContents(2)
        if r.pending == 0:
            self._poll.stop()
            self.btn_resolve.setText(tr("Namen auflösen"))
            self.btn_resolve.setEnabled(True)

    def _selected(self) -> Conversation | None:
        items = self.tree.selectedItems()
        if not items:
            return None
        return self._convs[items[0].data(0, Qt.UserRole)]

    def _update_buttons(self) -> None:
        conv = self._selected()
        self.btn_filter.setEnabled(conv is not None)
        self.btn_follow.setEnabled(conv is not None and conv.proto == "TCP")
        self.btn_seq.setEnabled(conv is not None)
        self.btn_graph.setEnabled(conv is not None and conv.proto == "TCP")
        self.btn_objects.setEnabled(conv is not None and conv.proto == "TCP")
        self._update_io_graph(conv)

    def _show_sequence(self) -> None:
        conv = self._selected()
        if conv is not None:
            SequenceDialog(self._packets, conv, self).exec()

    def _show_graph(self) -> None:
        conv = self._selected()
        if conv is not None:
            StreamGraphDialog(self._packets, conv, self).exec()

    def _show_objects(self) -> None:
        conv = self._selected()
        if conv is None:
            return
        # Bei TLS und geladenen Schlüsseln zuerst entschlüsseln.
        cb = sb = b""
        if self._keylog:
            dec = decrypt_conversation(self._packets, conv.a, conv.a_port,
                                       conv.b, conv.b_port, self._keylog)
            if dec.ok:
                cb, sb = dec.client_text, dec.server_text
        if not cb and not sb:
            res = follow_stream(self._packets, conv.a, conv.a_port,
                                conv.b, conv.b_port)
            cb, sb = res.client_bytes, res.server_bytes
        objs = http_objects(cb, sb)
        if not objs:
            QMessageBox.information(self, tr("Objekte"),
                                   tr("Keine HTTP-Objekte gefunden (evtl. "
                                      "verschlüsselt – Schlüssel laden?)."))
            return
        ObjectExtractDialog(objs, self).exec()

    def _update_io_graph(self, conv: Conversation | None) -> None:
        if conv is None:
            self.io_graph.set_title(tr("Verlauf – Verbindung wählen"))
            self.io_graph.set_series([], [])
            return
        a2b, b2a = io_buckets(self._packets, conv.a, conv.a_port,
                              conv.b, conv.b_port, bucket=1.0)
        # GraphWidget zeigt „ein" (blau) / „aus" (orange): B→A bzw. A→B.
        self.io_graph.set_title(
            tr("Verlauf  {a} ⇄ {b}").format(a=_ep(conv.a, conv.a_port),
                                            b=_ep(conv.b, conv.b_port)))
        self.io_graph.set_series(b2a, a2b)

    def _double(self, item, _col) -> None:
        conv = self._convs[item.data(0, Qt.UserRole)]
        if conv.proto == "TCP":
            self.followRequested.emit(conv)
        else:
            self._filter()

    def _follow(self) -> None:
        conv = self._selected()
        if conv is not None and conv.proto == "TCP":
            self.followRequested.emit(conv)

    def _filter(self) -> None:
        conv = self._selected()
        if conv is None:
            return
        # Verbindungsfilter: beide Hosts (der Display-Filter kennt „host").
        self.filterRequested.emit(f"host {conv.a} host {conv.b}")


# --------------------------------------------------------------------------- #
class ExpertInfoDialog(QDialog):
    """Liste heuristischer Auffälligkeiten; Doppelklick springt zum Paket."""
    jumpToPacket = Signal(int)

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Experten-Infos"))
        self.resize(720, 440)
        lay = QVBoxLayout(self)

        findings = expert_info(packets)
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = "  ".join(f"{k}: {v}" for k, v in counts.items()) or tr("keine")
        lay.addWidget(QLabel(tr("{n} Befund(e)   ({summary})")
                             .format(n=len(findings), summary=summary)))

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels([tr("Schwere"), tr("Kategorie"), tr("Beschreibung"),
                                   tr("Paket")])
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        for f in findings:
            it = QTreeWidgetItem([f.severity.upper(), tr(f.category), f.summary,
                                  str(f.packet) if f.packet else "—"])
            it.setForeground(0, QColor(_SEV_COLOR.get(f.severity, "#c9d1d9")))
            it.setData(0, Qt.UserRole, f.packet)
            self.tree.addTopLevelItem(it)
        for col in range(4):
            self.tree.resizeColumnToContents(col)
        self.tree.itemDoubleClicked.connect(self._double)
        lay.addWidget(self.tree)

        if not findings:
            lay.addWidget(QLabel(tr("Kein auffälliger Verkehr erkannt. 🎉")))

        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

    def _double(self, item, _col) -> None:
        pkt = item.data(0, Qt.UserRole)
        if pkt:
            self.jumpToPacket.emit(int(pkt))


# --------------------------------------------------------------------------- #
class ProtocolHierarchyDialog(QDialog):
    """Baum der Protokollverteilung (Pakete/Bytes/Anteil), wie Wireshark."""

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Protokoll-Hierarchie"))
        self.resize(640, 460)
        lay = QVBoxLayout(self)
        total = len(packets) or 1
        lay.addWidget(QLabel(tr("{n} Paket(e) gesamt").format(n=len(packets))))

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels([tr("Protokoll"), tr("Pakete"), tr("% Pakete"),
                                   tr("Bytes")])
        self.tree.setFont(_MONO)
        for node in protocol_hierarchy(packets):
            self.tree.addTopLevelItem(self._item(node, total))
        self.tree.expandAll()
        for col in range(4):
            self.tree.resizeColumnToContents(col)
        lay.addWidget(self.tree)

        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

    def _item(self, node: HierNode, total: int) -> QTreeWidgetItem:
        pct = f"{100 * node.packets / total:.1f}"
        it = QTreeWidgetItem([node.name, str(node.packets), pct, human(node.bytes)])
        for col in (1, 2, 3):
            it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
        for child in node.child_list():
            it.addChild(self._item(child, total))
        return it


# --------------------------------------------------------------------------- #
class FollowStreamDialog(QDialog):
    """Zeigt den rekonstruierten TCP-Strom; Client/Server farblich getrennt."""

    def __init__(self, packets: list[Packet], conv: Conversation,
                 parent=None, keylog: dict | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(
            tr("TCP-Stream  {a} ⇄ {b}").format(a=_ep(conv.a, conv.a_port),
                                               b=_ep(conv.b, conv.b_port)))
        self.resize(820, 560)
        self._packets = packets
        self._conv = conv
        self._keylog = keylog or {}
        self._decrypted = None          # DecryptResult nach erfolgreicher Entschl.
        self._res: StreamResult = follow_stream(
            packets, conv.a, conv.a_port, conv.b, conv.b_port)

        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        c = self._res.client
        s = self._res.server
        self.head = QLabel(
            f"<span style='color:{_CLIENT_COLOR}'>■ Client {_ep(*c)}</span>"
            f"   →   "
            f"<span style='color:{_SERVER_COLOR}'>■ Server {_ep(*s)}</span>"
            f"   ·   {human(len(self._res.client_bytes))} ↑ / "
            f"{human(len(self._res.server_bytes))} ↓")
        top.addWidget(self.head)
        top.addStretch(1)
        self.btn_decrypt = QPushButton(tr("Entschlüsseln (TLS)"), self)
        self.btn_decrypt.setEnabled(bool(self._keylog))
        self.btn_decrypt.setToolTip(tr("TLS mit geladener SSLKEYLOGFILE entschlüsseln"))
        self.btn_decrypt.clicked.connect(self._decrypt)
        top.addWidget(self.btn_decrypt)
        top.addWidget(QLabel(tr("Ansicht:")))
        self.mode = QComboBox(self)
        for key in ("ASCII", "Hex", "HTTP/2-Header"):   # Daten = Schlüssel
            self.mode.addItem(tr(key), key)
        self.mode.currentTextChanged.connect(self._render)
        top.addWidget(self.mode)
        self.dir = QComboBox(self)
        for key in ("Beide", "Nur Client", "Nur Server"):
            self.dir.addItem(tr(key), key)
        self.dir.currentTextChanged.connect(self._render)
        top.addWidget(self.dir)
        lay.addLayout(top)

        self.view = QPlainTextEdit(self)
        self.view.setReadOnly(True)
        self.view.setFont(_MONO)
        self.view.setLineWrapMode(QPlainTextEdit.NoWrap)
        lay.addWidget(self.view)

        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)
        self._render()

    def _decrypt(self) -> None:
        from ..core.tlssession import decrypt_conversation
        res = decrypt_conversation(self._packets, self._conv.a, self._conv.a_port,
                                   self._conv.b, self._conv.b_port, self._keylog)
        if not res.ok:
            QMessageBox.information(self, tr("TLS-Entschlüsselung"), tr(res.info))
            return
        self._decrypted = res
        self.head.setText(f"<span style='color:#56d364'>🔓 {tr(res.info)}</span>")
        self.btn_decrypt.setEnabled(False)
        self._render()

    def _chunks(self):
        if self._decrypted is not None:
            return [(True, self._decrypted.client_text),
                    (False, self._decrypted.server_text)]
        return [(ch.from_client, ch.data) for ch in self._res.chunks]

    def _dir_bytes(self):
        """Rohbytes je Richtung (entschlüsselt falls vorhanden)."""
        if self._decrypted is not None:
            return self._decrypted.client_text, self._decrypted.server_text
        return self._res.client_bytes, self._res.server_bytes

    def _render_http2(self, which: str) -> None:
        c_bytes, s_bytes = self._dir_bytes()
        parts: list[str] = []
        for from_client, data, color in (
                (True, c_bytes, _CLIENT_COLOR), (False, s_bytes, _SERVER_COLOR)):
            if which == "Nur Client" and not from_client:
                continue
            if which == "Nur Server" and from_client:
                continue
            try:
                frames = decode_http2_headers(data)
            except Exception:
                frames = []
            if not frames:
                continue
            who = "Client → Server" if from_client else "Server → Client"
            block = [f"<b>{who}</b>"]
            for sid, headers in frames:
                block.append(f"  <i>Stream {sid}</i>")
                for name, value in headers:
                    block.append(f"    {_escape(name)}: {_escape(value)}")
            parts.append(f"<span style='color:{color};white-space:pre'>"
                         f"{'<br>'.join(block)}</span>")
        self.view.clear()
        self.view.appendHtml("<br><br>".join(parts) if parts else
                             "<i>" + tr("Keine HTTP/2-HEADERS-Frames gefunden. "
                                        "(Nur bei HTTP/2-Verkehr; TLS ggf. erst "
                                        "entschlüsseln.)") + "</i>")
        self.view.verticalScrollBar().setValue(0)

    def _render(self, *_a) -> None:
        which = self.dir.currentData()
        mode = self.mode.currentData()
        if mode == "HTTP/2-Header":
            self._render_http2(which)
            return
        as_hex = mode == "Hex"
        parts: list[str] = []
        for from_client, data in self._chunks():
            if which == "Nur Client" and not from_client:
                continue
            if which == "Nur Server" and from_client:
                continue
            if not data:
                continue
            color = _CLIENT_COLOR if from_client else _SERVER_COLOR
            body = _hexblock(data) if as_hex else _ascii(data)
            parts.append(f"<span style='color:{color};white-space:pre'>"
                         f"{_escape(body)}</span>")
        self.view.clear()
        self.view.appendHtml("<br>".join(parts) if parts
                             else "<i>" + tr("Keine Nutzdaten in dieser Richtung.")
                             + "</i>")
        self.view.verticalScrollBar().setValue(0)


# --------------------------------------------------------------------------- #
class TcpHealthDialog(QDialog):
    """Gesundheits-Kennzahlen je TCP-Verbindung (RTT, Retrans, Dup-ACK, Zero-Win)."""

    COLS = [tr("Endpunkt A"), tr("Endpunkt B"), tr("Pakete"), "RTT",
            tr("Retrans."), "Dup-ACK", "Zero-Win"]

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("TCP-Gesundheit"))
        self.resize(780, 460)
        lay = QVBoxLayout(self)

        flows = tcp_health(packets)
        issues = sum(1 for f in flows if f.has_issue)
        lay.addWidget(QLabel(tr("{n} TCP-Verbindung(en), {issues} mit Auffälligkeiten")
                             .format(n=len(flows), issues=issues)))

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        for f in flows:
            it = QTreeWidgetItem([
                _ep(f.a, f.a_port), _ep(f.b, f.b_port), str(f.packets),
                f"{f.rtt_ms:.1f} ms" if f.rtt_ms is not None else "—",
                str(f.retransmissions), str(f.dup_acks), str(f.zero_window),
            ])
            for col in (2, 3, 4, 5, 6):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            if f.has_issue:                       # auffällige Werte hervorheben
                for col in (4, 5, 6):
                    it.setForeground(col, QColor("#d29922"))
            self.tree.addTopLevelItem(it)
        for col in range(len(self.COLS)):
            self.tree.resizeColumnToContents(col)
        lay.addWidget(self.tree)

        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)


# --------------------------------------------------------------------------- #
class DomainsDialog(QDialog):
    """Kontaktierte Domains (DNS-Query / TLS-SNI / HTTP-Host)."""
    filterRequested = Signal(str)

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Besuchte Domains"))
        self.resize(640, 460)
        lay = QVBoxLayout(self)

        self._stats = domains(packets)
        lay.addWidget(QLabel(
            tr("{n} eindeutige Domain(s) aus {packets} Paketen "
               "(DNS / TLS-SNI / HTTP-Host)").format(n=len(self._stats),
                                                     packets=len(packets))))

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels([tr("Domain"), tr("Pakete"), tr("Quelle")])
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        for d in self._stats:
            it = QTreeWidgetItem([d.name, str(d.packets), ", ".join(d.protocols)])
            it.setTextAlignment(1, int(Qt.AlignRight | Qt.AlignVCenter))
            self.tree.addTopLevelItem(it)
        for col in range(3):
            self.tree.resizeColumnToContents(col)
        self.tree.itemDoubleClicked.connect(self._double)
        lay.addWidget(self.tree)

        row = QHBoxLayout()
        btn = QPushButton(tr("Als Filter setzen"), self)
        btn.clicked.connect(self._filter_selected)
        row.addWidget(btn)
        row.addStretch(1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        row.addWidget(close)
        lay.addLayout(row)

    def _double(self, item, _col) -> None:
        self.filterRequested.emit(item.text(0))

    def _filter_selected(self) -> None:
        items = self.tree.selectedItems()
        if items:
            self.filterRequested.emit(items[0].text(0))


# --------------------------------------------------------------------------- #
class _SequenceView(QWidget):
    """Zeichnet den Paketfluss als Sequenzdiagramm (zwei Lebenslinien)."""

    ROW_H = 24
    TOP = 46
    MARGIN = 70

    def __init__(self, client: str, server: str,
                 events: list[SeqEvent], parent=None) -> None:
        super().__init__(parent)
        self._client = client
        self._server = server
        self._events = events
        self.setMinimumWidth(560)
        self.setMinimumHeight(self.TOP + len(events) * self.ROW_H + 20)
        self.setAttribute(Qt.WA_StyledBackground, True)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(self.rect(), QColor(THEME.bg))

        lx, rx = self.MARGIN + 40, w - self.MARGIN
        # Lebenslinien.
        p.setPen(QPen(QColor(THEME.grid), 1, Qt.DashLine))
        p.drawLine(lx, self.TOP - 8, lx, h - 8)
        p.drawLine(rx, self.TOP - 8, rx, h - 8)
        # Kopf-Beschriftung.
        p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        p.setPen(QColor(_CLIENT_COLOR))
        p.drawText(lx - 38, 24, f"Client\n{self._client}".split("\n")[0])
        p.drawText(lx - 38, 38, self._client)
        p.setPen(QColor(_SERVER_COLOR))
        p.drawText(rx - 30, 24, "Server")
        p.drawText(rx - 100, 38, self._server)

        p.setFont(QFont("Consolas", 8))
        t0 = self._events[0].ts if self._events else 0.0
        for i, ev in enumerate(self._events):
            y = self.TOP + i * self.ROW_H + 12
            color = QColor(_CLIENT_COLOR if ev.from_client else _SERVER_COLOR)
            # Zeit (relativ) ganz links.
            p.setPen(QColor(THEME.muted))
            p.drawText(6, y + 4, f"{ev.ts - t0:8.4f}")
            # Pfeil zwischen den Linien.
            x_from, x_to = (lx, rx) if ev.from_client else (rx, lx)
            p.setPen(QPen(color, 1.4))
            p.drawLine(x_from, y, x_to, y)
            self._arrow_head(p, x_to, y, ev.from_client, color)
            # Beschriftung mittig über dem Pfeil.
            p.setPen(QColor(THEME.text))
            tw = p.fontMetrics().horizontalAdvance(ev.label)
            p.drawText(int((lx + rx) / 2 - tw / 2), y - 4, ev.label)
        p.end()

    @staticmethod
    def _arrow_head(p, x, y, pointing_right, color) -> None:
        d = 6 if pointing_right else -6
        head = QPolygonF([QPointF(x, y), QPointF(x - d, y - 3),
                          QPointF(x - d, y + 3)])
        p.setBrush(color)
        p.setPen(Qt.NoPen)
        p.drawPolygon(head)


class SequenceDialog(QDialog):
    """Sequenzdiagramm einer Verbindung (Client ↔ Server über die Zeit)."""

    def __init__(self, packets: list[Packet], conv: Conversation,
                 parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Sequenzdiagramm"))
        self.resize(720, 560)
        client, server, events = sequence(
            packets, conv.a, conv.a_port, conv.b, conv.b_port)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(tr("{n} Paket(e)  ·  {client}  →  {server}").format(
            n=len(events), client=_ep(*client), server=_ep(*server))))
        area = QScrollArea(self)
        area.setWidgetResizable(True)
        area.setWidget(_SequenceView(_ep(*client), _ep(*server), events, self))
        lay.addWidget(area, 1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)


# --------------------------------------------------------------------------- #
class DnsAnalysisDialog(QDialog):
    """DNS-Tiefenanalyse: je Name Anfragen/Antworten, NXDOMAIN, Ø-Zeit, IPs."""
    filterRequested = Signal(str)

    COLS = [tr("Name"), tr("Typ"), tr("Anfragen"), tr("Antworten"), "NXDOMAIN",
            tr("Ø-Zeit"), tr("Adressen")]

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("DNS-Analyse"))
        self.resize(820, 480)
        lay = QVBoxLayout(self)
        stats = dns_analysis(packets)
        total_q = sum(s.queries for s in stats)
        total_nx = sum(s.nxdomain for s in stats)
        lay.addWidget(QLabel(tr("{n} Namen · {q} Anfragen · {nx} NXDOMAIN")
                             .format(n=len(stats), q=total_q, nx=total_nx)))
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        for s in stats:
            it = QTreeWidgetItem([
                s.name, s.qtype, str(s.queries), str(s.responses),
                str(s.nxdomain),
                f"{s.avg_ms:.1f} ms" if s.avg_ms is not None else "—",
                ", ".join(s.addresses)])
            for col in (2, 3, 4, 5):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            if s.nxdomain:
                it.setForeground(4, QColor("#d29922"))
            self.tree.addTopLevelItem(it)
        for col in range(len(self.COLS)):
            self.tree.resizeColumnToContents(col)
        self.tree.itemDoubleClicked.connect(
            lambda it, _c: self.filterRequested.emit(it.text(0)))
        lay.addWidget(self.tree)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)


# --------------------------------------------------------------------------- #
class EndpointsDialog(QDialog):
    """Endpunkt-/Port-Statistik und Paketgrößen-Verteilung."""
    filterRequested = Signal(str)

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Endpunkte & Ports"))
        self.resize(880, 620)
        lay = QVBoxLayout(self)

        lay.addWidget(self._caption(tr("Hosts (nach Volumen)")))
        self.ep_tree = QTreeWidget(self)
        geo_on = geoip.available()
        cols = [tr("Host"), tr("Pakete"), tr("Bytes"), tr("↑ gesendet"),
                tr("↓ empfangen")]
        if geo_on:
            cols.append(tr("Land / ASN"))
        self.ep_tree.setHeaderLabels(cols)
        self.ep_tree.setRootIsDecorated(False)
        self.ep_tree.setFont(_MONO)
        for e in endpoints(packets):
            row = [e.ip, str(e.packets), human(e.bytes),
                   f"{e.tx_pkts}/{human(e.tx_bytes)}",
                   f"{e.rx_pkts}/{human(e.rx_bytes)}"]
            if geo_on:
                row.append(geoip.describe(e.ip))
            it = QTreeWidgetItem(row)
            for col in (1, 2, 3, 4):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            self.ep_tree.addTopLevelItem(it)
        for col in range(len(cols)):
            self.ep_tree.resizeColumnToContents(col)
        self.ep_tree.itemDoubleClicked.connect(
            lambda it, _c: self.filterRequested.emit(f"host {it.text(0)}"))
        lay.addWidget(self.ep_tree, 2)

        lay.addWidget(self._caption(tr("Dienst-Ports (nach Volumen)")))
        self.port_tree = QTreeWidget(self)
        self.port_tree.setHeaderLabels([tr("Port"), tr("Dienst"), "L4", tr("Pakete"),
                                        tr("Bytes")])
        self.port_tree.setRootIsDecorated(False)
        self.port_tree.setFont(_MONO)
        for p in port_stats(packets):
            it = QTreeWidgetItem([str(p.port), p.service, p.proto,
                                  str(p.packets), human(p.bytes)])
            for col in (0, 3, 4):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            self.port_tree.addTopLevelItem(it)
        for col in range(5):
            self.port_tree.resizeColumnToContents(col)
        self.port_tree.itemDoubleClicked.connect(
            lambda it, _c: self.filterRequested.emit(f"port {it.text(0)}"))
        lay.addWidget(self.port_tree, 1)

        lay.addWidget(self._caption(tr("Paketgrößen-Verteilung")))
        self.hist = BarChart("", tr("Pakete"), self)
        self.hist.setMinimumHeight(140)
        self.hist.set_data([(label, n) for label, n in size_histogram(packets)])
        lay.addWidget(self.hist)

        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

    @staticmethod
    def _caption(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color:#8b949e; font-weight:bold; padding:2px 0;")
        return lbl


# --------------------------------------------------------------------------- #
class ConnectionStatesDialog(QDialog):
    """TCP-Verbindungen mit Lebenszyklus-Zustand."""
    filterRequested = Signal(str)

    COLS = [tr("Endpunkt A"), tr("Endpunkt B"), tr("Zustand"), tr("Aufbau"),
            tr("Dauer"), tr("Pakete")]
    _COLORS = {"Zurückgesetzt (RST)": "#f85149",
               "Fehlgeschlagen (keine Antwort)": "#f85149",
               "Aufbau (SYN/ACK)": "#d29922", "Unvollständig": "#d29922"}

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Verbindungs-Status"))
        self.resize(820, 480)
        lay = QVBoxLayout(self)
        conns = connection_states(packets)
        bad = sum(1 for c in conns if c.state in self._COLORS)
        lay.addWidget(QLabel(tr("{n} TCP-Verbindung(en), {bad} auffällig")
                             .format(n=len(conns), bad=bad)))
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        for c in conns:
            it = QTreeWidgetItem([
                _ep(c.a, c.a_port), _ep(c.b, c.b_port), tr(c.state),
                f"{c.setup_ms:.1f} ms" if c.setup_ms is not None else "—",
                f"{c.duration:.3f}s", str(c.packets)])
            for col in (3, 4, 5):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            color = self._COLORS.get(c.state)
            if color:
                it.setForeground(2, QColor(color))
            self.tree.addTopLevelItem(it)
        for col in range(len(self.COLS)):
            self.tree.resizeColumnToContents(col)
        self.tree.itemDoubleClicked.connect(self._double)
        lay.addWidget(self.tree)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

    def _double(self, item, _col) -> None:
        a = item.text(0).rsplit(":", 1)[0]
        b = item.text(1).rsplit(":", 1)[0]
        self.filterRequested.emit(f"host {a} host {b}")


# --------------------------------------------------------------------------- #
class ProcessTrafficDialog(QDialog):
    """Live-Darstellung des Verkehrs nach Programmen (Donut + Tabelle)."""
    filterRequested = Signal(str)

    COLS = [tr("Programm"), tr("Pakete"), tr("Bytes"), tr("↑ gesendet"),
            tr("↓ empfangen")]

    def __init__(self, model, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Programmverkehr"))
        self.resize(720, 560)
        self._model = model
        lay = QVBoxLayout(self)

        self.hint = QLabel("")
        self.hint.setStyleSheet("color:#8b949e;")
        lay.addWidget(self.hint)

        self.donut = DonutChart(tr("Verkehr nach Programm"), "B", self)
        self.donut.setMinimumHeight(170)
        self.donut.sliceClicked.connect(self._slice)
        lay.addWidget(self.donut)

        self.timeline = MultiLineChart(tr("Verlauf nach Programm"), "B/s", self)
        self.timeline.setMinimumHeight(120)
        self.timeline.setMaximumHeight(150)
        lay.addWidget(self.timeline)
        self._hist: dict[str, deque] = {}     # Programm → Bytes/s-Historie
        self._last: dict[str, int] | None = None

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        self.tree.itemDoubleClicked.connect(
            lambda it, _c: self._slice(it.data(0, Qt.UserRole)))
        lay.addWidget(self.tree, 1)

        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()
        self._refresh()

    def _slice(self, name: str) -> None:
        if name and name not in ("unbekannt", tr("unbekannt")):
            self.filterRequested.emit(name)

    _WIN = 60

    def _refresh(self) -> None:
        stats = aggregate_processes(self._model.all_packets)
        self.donut.set_data([(_proc_label(s.name), s.bytes) for s in stats])
        self._update_timeline(stats)
        self.tree.clear()
        for s in stats:
            it = QTreeWidgetItem([
                _proc_label(s.name), str(s.packets), human(s.bytes),
                human(s.tx_bytes), human(s.rx_bytes)])
            it.setData(0, Qt.UserRole, s.name)
            for col in (1, 2, 3, 4):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            self.tree.addTopLevelItem(it)
        for col in range(len(self.COLS)):
            self.tree.resizeColumnToContents(col)
        total = sum(s.bytes for s in stats) or 1
        unknown = next((s.bytes for s in stats if s.name == "unbekannt"), 0)
        if unknown / total > 0.5:
            self.hint.setText(
                tr("Viel Verkehr ohne Programmzuordnung – Prozesszuordnung gibt es "
                   "nur bei Live-Erfassung und am besten als Administrator."))
        else:
            self.hint.setText("")

    def _update_timeline(self, stats) -> None:
        """Bildet aus den kumulativen Summen den Durchsatz (Bytes/s) je Programm."""
        cur = {s.name: s.bytes for s in stats}
        if self._last is None:
            self._last = cur                 # Basiswert, kein Anfangs-Ausschlag
            return
        for name in set(self._hist) | set(cur):
            delta = max(0, cur.get(name, 0) - self._last.get(name, 0))
            dq = self._hist.get(name)
            if dq is None:
                dq = deque([0] * self._WIN, maxlen=self._WIN)
                self._hist[name] = dq
            dq.append(delta)
        self._last = cur
        top = [s.name for s in stats[:6]]
        self.timeline.set_series({_proc_label(n): list(self._hist[n])
                                  for n in top if n in self._hist})

    def closeEvent(self, event) -> None:
        self._timer.stop()
        super().closeEvent(event)


# --------------------------------------------------------------------------- #
class SrtDialog(QDialog):
    """Service-Response-Time je Protokoll (Anzahl, Ø/Min/Max in ms)."""

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Service-Response-Time"))
        self.resize(520, 320)
        lay = QVBoxLayout(self)
        rows = service_response_times(packets)
        lay.addWidget(QLabel(tr("{n} Protokoll(e) mit Antwortzeiten").format(n=len(rows))))
        tree = QTreeWidget(self)
        tree.setHeaderLabels([tr("Protokoll"), tr("Anfragen"), "Ø", "Min", "Max"])
        tree.setRootIsDecorated(False)
        tree.setFont(_MONO)
        for s in rows:
            it = QTreeWidgetItem([s.protocol, str(s.count), f"{s.avg_ms:.1f} ms",
                                  f"{s.min_ms:.1f} ms", f"{s.max_ms:.1f} ms"])
            for col in (1, 2, 3, 4):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            tree.addTopLevelItem(it)
        for col in range(5):
            tree.resizeColumnToContents(col)
        lay.addWidget(tree)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)


# --------------------------------------------------------------------------- #
class RtpStreamsDialog(QDialog):
    """RTP-Streams je SSRC mit Paketzahl, Verlust und Jitter."""
    filterRequested = Signal(str)

    COLS = ["SSRC", tr("Quelle"), tr("Ziel"), "PT", tr("Pakete"), tr("Verlust"),
            "Jitter", tr("Dauer")]

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("RTP-Streams"))
        self.resize(820, 440)
        lay = QVBoxLayout(self)
        streams = rtp_streams(packets)
        lay.addWidget(QLabel(tr("{n} RTP-Stream(s)").format(n=len(streams))))
        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        for s in streams:
            it = QTreeWidgetItem([
                f"0x{s.ssrc:08x}", _ep(s.src, s.src_port),
                _ep(s.dst, s.dst_port), str(s.payload_type), str(s.packets),
                f"{s.lost} ({s.loss_pct:.1f}%)", f"{s.jitter_ms:.1f} ms",
                f"{s.duration:.2f}s"])
            for col in (3, 4, 5, 6, 7):
                it.setTextAlignment(col, int(Qt.AlignRight | Qt.AlignVCenter))
            if s.lost:
                it.setForeground(5, QColor("#d29922"))
            it.setData(0, Qt.UserRole, s.src)
            self.tree.addTopLevelItem(it)
        for col in range(len(self.COLS)):
            self.tree.resizeColumnToContents(col)
        self.tree.itemDoubleClicked.connect(
            lambda it, _c: self.filterRequested.emit(f"host {it.data(0, Qt.UserRole)}"))
        lay.addWidget(self.tree)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)


# --- Formatierung ---------------------------------------------------------- #
def _proc_label(name: str) -> str:
    """Anzeigename eines Programms (nur der Platzhalter „unbekannt" wird übersetzt)."""
    return tr(name) if name == "unbekannt" else name


def _ascii(data: bytes) -> str:
    return data.decode("latin-1", "replace").replace("\r\n", "\n")


def _hexblock(data: bytes) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexp = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hexp:<47}  {asc}")
    return "\n".join(lines)


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\n", "<br>"))
