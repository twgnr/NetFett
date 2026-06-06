"""Dialoge der aktiven Werkzeuge: Ping, Traceroute und DNS-Lookup.

Die Netzwerkarbeit läuft je in einem Hintergrund-Thread; Ergebnisse werden über
Qt-Signale (thread-sicher, queued) an die Oberfläche gemeldet. Ping/Traceroute
brauchen Administratorrechte (Raw-Socket); Fehler werden im Dialog angezeigt.
"""
from __future__ import annotations

import threading

from PySide6.QtCore import Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
    QPushButton, QVBoxLayout,
)

from ..core import tools

_MONO = QFont("Consolas", 9)


class _ToolDialog(QDialog):
    """Basis: Host-Eingabe, Start-Knopf, Monospace-Ausgabe, Worker-Thread."""
    line = Signal(str)
    done = Signal(str)

    def __init__(self, title: str, default_host: str = "8.8.8.8",
                 parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(620, 420)
        self._alive = True
        lay = QVBoxLayout(self)

        top = QHBoxLayout()
        top.addWidget(QLabel("Ziel:"))
        self.host = QLineEdit(default_host, self)
        self.host.returnPressed.connect(self._start)
        top.addWidget(self.host, 1)
        self.btn = QPushButton("Start", self)
        self.btn.clicked.connect(self._start)
        top.addWidget(self.btn)
        lay.addLayout(top)

        self.out = QPlainTextEdit(self)
        self.out.setReadOnly(True)
        self.out.setFont(_MONO)
        lay.addWidget(self.out)

        close = QDialogButtonBox(QDialogButtonBox.Close, self)
        close.rejected.connect(self.reject)
        lay.addWidget(close)

        self.line.connect(self._append)
        self.done.connect(self._finish)

    def _append(self, text: str) -> None:
        if self._alive:
            self.out.appendPlainText(text)

    def _finish(self, text: str) -> None:
        if not self._alive:
            return
        if text:
            self.out.appendPlainText(text)
        self.btn.setEnabled(True)
        self.host.setEnabled(True)

    def _start(self) -> None:
        host = self.host.text().strip()
        if not host:
            return
        self.out.clear()
        self.btn.setEnabled(False)
        self.host.setEnabled(False)
        t = threading.Thread(target=self._run, args=(host,), daemon=True)
        t.start()

    def _run(self, host: str) -> None:  # im Worker-Thread
        raise NotImplementedError

    def closeEvent(self, event) -> None:
        self._alive = False
        super().closeEvent(event)


class PingDialog(_ToolDialog):
    def __init__(self, parent=None) -> None:
        super().__init__("Ping", parent=parent)

    def _run(self, host: str) -> None:
        self.line.emit(f"Ping {host} …\n")
        try:
            summary = tools.ping(
                host, count=4,
                on_result=lambda seq, rtt, addr: self.line.emit(
                    f"  Antwort von {addr}: seq={seq}  "
                    + (f"{rtt:.1f} ms" if rtt is not None else "Zeitüberschreitung")))
        except PermissionError:
            self.done.emit("\nFehler: Ping benötigt Administratorrechte.")
            return
        except OSError as exc:
            self.done.emit(f"\nFehler: {exc}")
            return
        self.done.emit(
            f"\n{summary.received}/{summary.sent} Antworten, "
            f"{summary.loss_pct:.0f}% Verlust"
            + _rtt_stats(summary.rtts))


class TracerouteDialog(_ToolDialog):
    def __init__(self, parent=None) -> None:
        super().__init__("Traceroute", parent=parent)

    def _run(self, host: str) -> None:
        self.line.emit(f"Traceroute zu {host} (max. 30 Hops) …\n")
        try:
            tools.traceroute(
                host, max_hops=30,
                on_hop=lambda hop: self.line.emit(
                    f"  {hop.ttl:2d}  "
                    + (f"{hop.address:<16} {hop.rtt_ms:.1f} ms"
                       if hop.address else "*  (keine Antwort)")))
        except PermissionError:
            self.done.emit("\nFehler: Traceroute benötigt Administratorrechte.")
            return
        except OSError as exc:
            self.done.emit(f"\nFehler: {exc}")
            return
        self.done.emit("\nFertig.")


class DnsLookupDialog(_ToolDialog):
    def __init__(self, parent=None) -> None:
        super().__init__("DNS-Lookup", default_host="example.com", parent=parent)

    def _run(self, host: str) -> None:
        self.line.emit(f"Auflösung von {host} …\n")
        res = tools.dns_lookup(host)
        if res.error:
            self.done.emit(f"Fehler: {res.error}")
            return
        for addr in res.addresses:
            ptr = res.reverse.get(addr) or "—"
            self.line.emit(f"  {addr:<20}  {ptr}")
        self.done.emit(f"\n{len(res.addresses)} Adresse(n).")


class WhoisDialog(_ToolDialog):
    def __init__(self, parent=None) -> None:
        super().__init__("WHOIS", default_host="example.com", parent=parent)

    def _run(self, host: str) -> None:
        from ..core import whois
        self.line.emit(f"WHOIS {host} …\n")
        try:
            self.done.emit(whois.whois(host))
        except OSError as exc:
            self.done.emit(f"Fehler: {exc}")


def _rtt_stats(rtts) -> str:
    vals = [r for r in rtts if r is not None]
    if not vals:
        return ""
    return (f"\nRTT  min {min(vals):.1f} / "
            f"avg {sum(vals) / len(vals):.1f} / max {max(vals):.1f} ms")
