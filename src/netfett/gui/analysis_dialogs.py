"""Dialoge der Analyse-Features: Verbindungen, Experten-Infos, Follow-Stream.

Die Dialoge sind dünne Sichten auf die reine :mod:`netfett.core.analyze`-Schicht
und melden Benutzeraktionen (Filter setzen, zu Paket springen, Stream folgen) per
Qt-Signal an das Hauptfenster zurück.
"""
from __future__ import annotations

from PySide6.QtCore import QPointF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPlainTextEdit,
    QPushButton, QScrollArea, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..core.analyze import (
    Conversation, FlowHealth, HierNode, SeqEvent, StreamResult, conversations,
    domains, expert_info, follow_stream, io_buckets, protocol_hierarchy,
    sequence, tcp_health,
)
from ..core.models import Packet
from ..core.resolve import NameResolver
from .graph_widget import GraphWidget
from .theme import THEME
from .graph_widget import human

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

    COLS = ["Protokoll", "Endpunkt A", "Endpunkt B", "Pakete",
            "A→B", "B→A", "Bytes", "Dauer", "Durchsatz"]

    def __init__(self, packets: list[Packet], parent=None,
                 resolver: NameResolver | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Verbindungen")
        self.resize(860, 540)
        self._resolver = resolver
        self._packets = packets
        lay = QVBoxLayout(self)

        convs = conversations(packets)
        self._convs = convs
        self._items: list[QTreeWidgetItem] = []
        lay.addWidget(QLabel(f"{len(convs)} Verbindung(en) aus "
                             f"{len(packets)} Paketen"))

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
        self.io_graph = GraphWidget("Verlauf – Verbindung wählen", "B/s", self)
        self.io_graph.setMinimumHeight(120)
        self.io_graph.setMaximumHeight(160)
        lay.addWidget(self.io_graph)

        row = QHBoxLayout()
        self.btn_follow = QPushButton("Stream folgen", self)
        self.btn_follow.setEnabled(False)
        self.btn_follow.clicked.connect(self._follow)
        self.btn_filter = QPushButton("Als Filter setzen", self)
        self.btn_filter.setEnabled(False)
        self.btn_filter.clicked.connect(self._filter)
        self.btn_seq = QPushButton("Sequenz…", self)
        self.btn_seq.setEnabled(False)
        self.btn_seq.setToolTip("Paketfluss als Sequenzdiagramm")
        self.btn_seq.clicked.connect(self._show_sequence)
        self.btn_resolve = QPushButton("Namen auflösen", self)
        self.btn_resolve.setToolTip("Reverse-DNS (PTR) der Endpunkt-IPs")
        self.btn_resolve.clicked.connect(self._resolve_names)
        row.addWidget(self.btn_follow)
        row.addWidget(self.btn_seq)
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
        self.btn_resolve.setText("Löse auf …")
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
            self.btn_resolve.setText("Namen auflösen")
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
        self._update_io_graph(conv)

    def _show_sequence(self) -> None:
        conv = self._selected()
        if conv is not None:
            SequenceDialog(self._packets, conv, self).exec()

    def _update_io_graph(self, conv: Conversation | None) -> None:
        if conv is None:
            self.io_graph.set_title("Verlauf – Verbindung wählen")
            self.io_graph.set_series([], [])
            return
        a2b, b2a = io_buckets(self._packets, conv.a, conv.a_port,
                              conv.b, conv.b_port, bucket=1.0)
        # GraphWidget zeigt „ein" (blau) / „aus" (orange): B→A bzw. A→B.
        self.io_graph.set_title(
            f"Verlauf  {_ep(conv.a, conv.a_port)} ⇄ {_ep(conv.b, conv.b_port)}")
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
        self.setWindowTitle("Experten-Infos")
        self.resize(720, 440)
        lay = QVBoxLayout(self)

        findings = expert_info(packets)
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = "  ".join(f"{k}: {v}" for k, v in counts.items()) or "keine"
        lay.addWidget(QLabel(f"{len(findings)} Befund(e)   ({summary})"))

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Schwere", "Kategorie", "Beschreibung", "Paket"])
        self.tree.setRootIsDecorated(False)
        self.tree.setFont(_MONO)
        for f in findings:
            it = QTreeWidgetItem([f.severity.upper(), f.category, f.summary,
                                  str(f.packet) if f.packet else "—"])
            it.setForeground(0, QColor(_SEV_COLOR.get(f.severity, "#c9d1d9")))
            it.setData(0, Qt.UserRole, f.packet)
            self.tree.addTopLevelItem(it)
        for col in range(4):
            self.tree.resizeColumnToContents(col)
        self.tree.itemDoubleClicked.connect(self._double)
        lay.addWidget(self.tree)

        if not findings:
            lay.addWidget(QLabel("Kein auffälliger Verkehr erkannt. 🎉"))

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
        self.setWindowTitle("Protokoll-Hierarchie")
        self.resize(640, 460)
        lay = QVBoxLayout(self)
        total = len(packets) or 1
        lay.addWidget(QLabel(f"{len(packets)} Paket(e) gesamt"))

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Protokoll", "Pakete", "% Pakete", "Bytes"])
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
                 parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(
            f"TCP-Stream  {_ep(conv.a, conv.a_port)} ⇄ {_ep(conv.b, conv.b_port)}")
        self.resize(820, 560)
        self._res: StreamResult = follow_stream(
            packets, conv.a, conv.a_port, conv.b, conv.b_port)

        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        c = self._res.client
        s = self._res.server
        head = QLabel(
            f"<span style='color:{_CLIENT_COLOR}'>■ Client {_ep(*c)}</span>"
            f"   →   "
            f"<span style='color:{_SERVER_COLOR}'>■ Server {_ep(*s)}</span>"
            f"   ·   {human(len(self._res.client_bytes))} ↑ / "
            f"{human(len(self._res.server_bytes))} ↓")
        top.addWidget(head)
        top.addStretch(1)
        top.addWidget(QLabel("Ansicht:"))
        self.mode = QComboBox(self)
        self.mode.addItems(["ASCII", "Hex"])
        self.mode.currentTextChanged.connect(self._render)
        top.addWidget(self.mode)
        self.dir = QComboBox(self)
        self.dir.addItems(["Beide", "Nur Client", "Nur Server"])
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

    def _render(self, *_a) -> None:
        which = self.dir.currentText()
        as_hex = self.mode.currentText() == "Hex"
        parts: list[str] = []
        for ch in self._res.chunks:
            if which == "Nur Client" and not ch.from_client:
                continue
            if which == "Nur Server" and ch.from_client:
                continue
            color = _CLIENT_COLOR if ch.from_client else _SERVER_COLOR
            body = _hexblock(ch.data) if as_hex else _ascii(ch.data)
            parts.append(f"<span style='color:{color};white-space:pre'>"
                         f"{_escape(body)}</span>")
        self.view.clear()
        # Farbiger Text über das zugrunde liegende Dokument als HTML einfügen.
        self.view.appendHtml("<br>".join(parts) if parts
                             else "<i>Keine Nutzdaten in dieser Richtung.</i>")
        self.view.verticalScrollBar().setValue(0)


# --------------------------------------------------------------------------- #
class TcpHealthDialog(QDialog):
    """Gesundheits-Kennzahlen je TCP-Verbindung (RTT, Retrans, Dup-ACK, Zero-Win)."""

    COLS = ["Endpunkt A", "Endpunkt B", "Pakete", "RTT", "Retrans.",
            "Dup-ACK", "Zero-Win"]

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("TCP-Gesundheit")
        self.resize(780, 460)
        lay = QVBoxLayout(self)

        flows = tcp_health(packets)
        issues = sum(1 for f in flows if f.has_issue)
        lay.addWidget(QLabel(f"{len(flows)} TCP-Verbindung(en), "
                             f"{issues} mit Auffälligkeiten"))

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
        self.setWindowTitle("Besuchte Domains")
        self.resize(640, 460)
        lay = QVBoxLayout(self)

        self._stats = domains(packets)
        lay.addWidget(QLabel(f"{len(self._stats)} eindeutige Domain(s) aus "
                             f"{len(packets)} Paketen (DNS / TLS-SNI / HTTP-Host)"))

        self.tree = QTreeWidget(self)
        self.tree.setHeaderLabels(["Domain", "Pakete", "Quelle"])
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
        btn = QPushButton("Als Filter setzen", self)
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
        self.setWindowTitle("Sequenzdiagramm")
        self.resize(720, 560)
        client, server, events = sequence(
            packets, conv.a, conv.a_port, conv.b, conv.b_port)

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"{len(events)} Paket(e)  ·  "
                             f"{_ep(*client)}  →  {_ep(*server)}"))
        area = QScrollArea(self)
        area.setWidgetResizable(True)
        area.setWidget(_SequenceView(_ep(*client), _ep(*server), events, self))
        lay.addWidget(area, 1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)


# --- Formatierung ---------------------------------------------------------- #
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
