"""Dialoge der Analyse-Features: Verbindungen, Experten-Infos, Follow-Stream.

Die Dialoge sind dünne Sichten auf die reine :mod:`netfett.core.analyze`-Schicht
und melden Benutzeraktionen (Filter setzen, zu Paket springen, Stream folgen) per
Qt-Signal an das Hauptfenster zurück.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPlainTextEdit,
    QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..core.analyze import (
    Conversation, StreamResult, conversations, expert_info, follow_stream,
)
from ..core.models import Packet
from .graph_widget import human

_MONO = QFont("Consolas", 9)
_CLIENT_COLOR = "#5aa9ff"
_SERVER_COLOR = "#ffb454"
_SEV_COLOR = {"info": "#8b949e", "note": "#58a6ff",
              "warn": "#d29922", "error": "#f85149"}


def _ep(ip: str, port) -> str:
    return f"{ip}:{port}" if port is not None else ip


# --------------------------------------------------------------------------- #
class ConversationsDialog(QDialog):
    """Tabelle aller Verbindungen; Doppelklick folgt dem TCP-Stream."""
    followRequested = Signal(object)   # Conversation
    filterRequested = Signal(str)

    COLS = ["Protokoll", "Endpunkt A", "Endpunkt B", "Pakete",
            "A→B", "B→A", "Bytes", "Dauer", "Durchsatz"]

    def __init__(self, packets: list[Packet], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Verbindungen")
        self.resize(820, 460)
        lay = QVBoxLayout(self)

        convs = conversations(packets)
        self._convs = convs
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
        for col in range(len(self.COLS)):
            self.tree.resizeColumnToContents(col)
        self.tree.itemDoubleClicked.connect(self._double)
        self.tree.itemSelectionChanged.connect(self._update_buttons)
        lay.addWidget(self.tree)

        row = QHBoxLayout()
        self.btn_follow = QPushButton("Stream folgen", self)
        self.btn_follow.setEnabled(False)
        self.btn_follow.clicked.connect(self._follow)
        self.btn_filter = QPushButton("Als Filter setzen", self)
        self.btn_filter.setEnabled(False)
        self.btn_filter.clicked.connect(self._filter)
        row.addWidget(self.btn_follow)
        row.addWidget(self.btn_filter)
        row.addStretch(1)
        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        row.addWidget(close)
        lay.addLayout(row)

    def _selected(self) -> Conversation | None:
        items = self.tree.selectedItems()
        if not items:
            return None
        return self._convs[items[0].data(0, Qt.UserRole)]

    def _update_buttons(self) -> None:
        conv = self._selected()
        self.btn_filter.setEnabled(conv is not None)
        self.btn_follow.setEnabled(conv is not None and conv.proto == "TCP")

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
