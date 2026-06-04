"""Brücke zwischen dem Capture-Thread und der Qt-GUI.

Der Capture-Thread liefert Rohbytes, die hier (außerhalb des GUI-Threads)
zerlegt und gepuffert werden. Ein Timer im GUI-Thread leert den Puffer
gebündelt – das hält die Oberfläche flüssig, auch bei hoher Paketrate.
"""
from __future__ import annotations

import threading

from PySide6.QtCore import QObject, QTimer, Signal

from ..core.capture import CaptureError, RawSocketCapture
from ..core.dissect import dissect
from ..core.interfaces import local_ipv4_addresses


class CaptureController(QObject):
    batchReady = Signal(list)   # list[Packet]
    error = Signal(str)
    started = Signal()
    stopped = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._cap: RawSocketCapture | None = None
        self._buf: list = []
        self._lock = threading.Lock()
        self._counter = 0
        self._local_ips: set[str] = set()
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._flush)

    @property
    def running(self) -> bool:
        return self._cap is not None and self._cap.running

    def start(self, host_ip: str) -> None:
        self._local_ips = set(local_ipv4_addresses()) | {host_ip}
        self._counter = 0
        cap = RawSocketCapture(host_ip, self._on_raw, self.error.emit)
        cap.start()  # wirft CaptureError bei fehlenden Rechten
        self._cap = cap
        self._timer.start()
        self.started.emit()

    def _on_raw(self, ts: float, data: bytes) -> None:
        # läuft im Capture-Thread: Zerlegen ist CPU-Arbeit, hier gut aufgehoben.
        with self._lock:
            self._counter += 1
            n = self._counter
        pkt = dissect(data, ts, n, self._local_ips)
        with self._lock:
            self._buf.append(pkt)

    def _flush(self) -> None:
        with self._lock:
            if not self._buf:
                return
            batch = self._buf
            self._buf = []
        self.batchReady.emit(batch)

    def stop(self) -> None:
        self._timer.stop()
        if self._cap is not None:
            self._cap.stop()
            self._cap = None
        self._flush()
        self.stopped.emit()
