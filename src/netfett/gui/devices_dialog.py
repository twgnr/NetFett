"""Geräte-Übersicht: aktiver IP-Scan + Live-Durchsatz je Gerät (Mini-Graph)."""
from __future__ import annotations

import html
import threading

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from ..core.arp import arp_table
from ..core.scan import enrich_host, ping_sweep, subnet_hosts
from .graph_widget import GraphWidget, human
from ..i18n import tr

_MONO = QFont("Consolas", 9)


class _HostCard(QWidget):
    """Eine Gerätekarte: Kopfzeile (IP/Name/Total) + kleiner Durchsatz-Graph.

    Doppelklick filtert die Hauptansicht; die Web-Adresse ist ein Browser-Link.
    """
    doubleClicked = Signal(str)

    def __init__(self, ip: str, parent=None) -> None:
        super().__init__(parent)
        self.ip = ip
        self.setToolTip(tr("Doppelklick: Hauptansicht auf dieses Gerät filtern"))
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 4, 6, 4)
        lay.setSpacing(2)
        self.header = QLabel(ip, self)
        self.header.setFont(_MONO)
        lay.addWidget(self.header)
        self.details = QLabel("", self)
        self.details.setStyleSheet("color:#8b949e;")
        self.details.setWordWrap(True)
        self.details.setTextFormat(Qt.RichText)
        self.details.setOpenExternalLinks(True)       # Web-Link öffnet Browser
        self.details.setTextInteractionFlags(Qt.TextBrowserInteraction)
        lay.addWidget(self.details)
        self.graph = GraphWidget("", "B/s", self)
        self.graph.setMinimumHeight(70)
        self.graph.setMaximumHeight(90)
        lay.addWidget(self.graph)

    def update_data(self, name: str, series, info) -> None:
        # Name: NetBIOS bevorzugt, sonst Reverse-DNS.
        display_name = (info.name if info and info.name else name)
        title = self.ip + (f"  ({display_name})" if display_name else "")
        title += f"   ▲ {human(series.total_out)} / ▼ {human(series.total_in)}"
        if info and info.rtt_ms is not None:
            title += f"   {info.rtt_ms:.0f} ms"
        self.header.setText(title)
        if info:
            bits = []
            if info.mac:
                bits.append(html.escape(f"MAC {info.mac}"))
            if info.vendor:
                bits.append(html.escape(info.vendor))
            if info.web:
                url = info.web.split(" ", 1)[0]
                bits.append(f'<a href="{html.escape(url)}" '
                            f'style="color:#5aa9ff">{html.escape(info.web)}</a>')
            self.details.setText("   ·   ".join(bits))
            self.details.setVisible(bool(bits))
        self.graph.set_series(series.in_bps, series.out_bps)

    def mouseDoubleClickEvent(self, event) -> None:
        self.doubleClicked.emit(self.ip)
        super().mouseDoubleClickEvent(event)


class DevicesDialog(QDialog):
    """Listet Geräte (gescannt + aus dem Verkehr) mit Live-Mini-Graph je IP."""
    hostFound = Signal(str, float)
    hostInfo = Signal(object)
    scanDone = Signal(int)
    filterRequested = Signal(str)

    def __init__(self, monitor, resolver, local_ip: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Geräte-Übersicht"))
        self.resize(560, 680)
        self._monitor = monitor
        self._resolver = resolver
        self._local_ip = local_ip
        self._cards: dict[str, _HostCard] = {}
        self._discovered: dict[str, float] = {}
        self._info: dict[str, object] = {}        # ip → ScannedHost (angereichert)

        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        self.btn_scan = QPushButton(tr("Netzwerk scannen"), self)
        self.btn_scan.setToolTip(tr("ICMP-Ping-Sweep des lokalen /24 (Adminrechte)"))
        self.btn_scan.clicked.connect(self._scan)
        top.addWidget(self.btn_scan)
        self.status = QLabel(tr("Geräte aus dem Verkehr werden live angezeigt."))
        top.addWidget(self.status, 1)
        lay.addLayout(top)

        area = QScrollArea(self)
        area.setWidgetResizable(True)
        self._body = QWidget()
        self._vbox = QVBoxLayout(self._body)
        self._vbox.setSpacing(4)
        self._vbox.addStretch(1)
        area.setWidget(self._body)
        lay.addWidget(area, 1)

        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

        self.hostFound.connect(self._on_found)
        self.hostInfo.connect(self._on_info)
        self.scanDone.connect(self._on_scan_done)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()
        self._refresh()

    # --- Scan -------------------------------------------------------------- #
    def _scan(self) -> None:
        hosts = subnet_hosts(self._local_ip, 24)
        if not hosts:
            self.status.setText(tr("Kein lokales Subnetz erkannt."))
            return
        self.btn_scan.setEnabled(False)
        self.status.setText(tr("Scanne {n} Adressen …").format(n=len(hosts)))

        def work() -> None:
            try:
                result = ping_sweep(
                    hosts, timeout=2.0,
                    on_result=lambda ip, rtt: self.hostFound.emit(ip, rtt))
            except PermissionError:
                self.scanDone.emit(-1)
                return
            except OSError:
                self.scanDone.emit(-2)
                return
            arp = arp_table()                         # MACs nach dem Sweep
            for h in result:
                if h.alive:
                    enrich_host(h, arp, timeout=0.8)
                    self.hostInfo.emit(h)
            self.scanDone.emit(0)

        threading.Thread(target=work, daemon=True).start()

    def _on_found(self, ip: str, rtt: float) -> None:
        self._discovered[ip] = rtt
        self._monitor.ensure(ip)
        if self._resolver is not None:
            self._resolver.resolve_async([ip])

    def _on_info(self, host) -> None:
        self._info[host.ip] = host
        self._monitor.ensure(host.ip)

    def _on_scan_done(self, code: int) -> None:
        self.btn_scan.setEnabled(True)
        if code == -1:
            self.status.setText(tr("Scan benötigt Administratorrechte."))
        elif code == -2:
            self.status.setText(tr("Scan fehlgeschlagen (Netzwerkfehler)."))
        else:
            self.status.setText(tr("{n} Gerät(e) gefunden.").format(
                n=len(self._discovered)))

    # --- Live-Aktualisierung ---------------------------------------------- #
    def _refresh(self) -> None:
        hosts = self._monitor.hosts()[:40]            # Top-40 nach Volumen
        seen = set()
        for series in hosts:
            seen.add(series.ip)
            card = self._cards.get(series.ip)
            if card is None:
                card = _HostCard(series.ip, self._body)
                card.doubleClicked.connect(
                    lambda ip: self.filterRequested.emit(f"host {ip}"))
                self._cards[series.ip] = card
                self._vbox.insertWidget(self._vbox.count() - 1, card)
            name = self._resolver.cached(series.ip) if self._resolver else ""
            card.update_data(name or "", series, self._info.get(series.ip))

    def closeEvent(self, event) -> None:
        self._timer.stop()
        super().closeEvent(event)
