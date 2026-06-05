"""Brücke zwischen dem Capture-Thread und der Qt-GUI.

Der Capture-Thread liefert Rohbytes, die hier (außerhalb des GUI-Threads)
zerlegt und gepuffert werden. Ein Timer im GUI-Thread leert den Puffer
gebündelt – das hält die Oberfläche flüssig, auch bei hoher Paketrate.
"""
from __future__ import annotations

import threading
from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer, Signal

from ..core.capture import CaptureError, RawSocketCapture
from ..core.dissect import dissect
from ..core.interfaces import (
    local_ipv4_addresses, local_ipv6_addresses, primary_ipv6,
)
from ..core.models import Packet
from ..core.pcap import PcapWriter


class CaptureController(QObject):
    batchReady = Signal(list)   # list[Packet]
    error = Signal(str)
    started = Signal()
    stopped = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._cap: RawSocketCapture | None = None
        self._cap6: RawSocketCapture | None = None
        self._buf: list = []
        self._lock = threading.Lock()
        self._counter = 0
        self._dropped = 0
        self._local_ips: set[str] = set()
        self._capture_filter: Callable[[Packet], bool] | None = None
        self._writer: PcapWriter | None = None
        self._wlock = threading.Lock()       # schützt den Datei-Writer
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._flush)

    @property
    def running(self) -> bool:
        return self._cap is not None and self._cap.running

    @property
    def recording(self) -> bool:
        return self._writer is not None

    @property
    def dropped(self) -> int:
        """Anzahl der vom Aufnahme-Filter verworfenen Pakete."""
        return self._dropped

    # --- Aufnahme-Filter & Datei-Mitschnitt --------------------------------
    def set_capture_filter(self, func: Callable[[Packet], bool] | None) -> None:
        self._capture_filter = func

    def start_recording(self, path: str) -> None:
        writer = PcapWriter(path)
        with self._wlock:
            if self._writer is not None:
                self._writer.close()
            self._writer = writer

    def stop_recording(self) -> int:
        with self._wlock:
            writer = self._writer
            self._writer = None
        if writer is None:
            return 0
        count = writer.count
        writer.close()
        return count

    def start(self, host_ip: str) -> None:
        self._local_ips = (set(local_ipv4_addresses())
                           | set(local_ipv6_addresses()) | {host_ip})
        self._counter = 0
        self._dropped = 0
        cap = RawSocketCapture(host_ip, self._on_raw, self.error.emit)
        cap.start()  # wirft CaptureError bei fehlenden Rechten
        self._cap = cap
        # Zusätzlich IPv6 erfassen, falls eine globale v6-Adresse existiert –
        # best-effort: schlägt das fehl, läuft die IPv4-Erfassung normal weiter.
        v6 = primary_ipv6()
        if v6:
            try:
                cap6 = RawSocketCapture(v6, self._on_raw, lambda _m: None)
                cap6.start()
                self._cap6 = cap6
            except CaptureError:
                self._cap6 = None
        self._timer.start()
        self.started.emit()

    def _on_raw(self, ts: float, data: bytes) -> None:
        # läuft im Capture-Thread: Zerlegen ist CPU-Arbeit, hier gut aufgehoben.
        pkt = dissect(data, ts, 0, self._local_ips)
        if self._capture_filter is not None and not self._capture_filter(pkt):
            with self._lock:
                self._dropped += 1
            return
        # Nummerierung erst für behaltene Pakete → keine Lücken.
        with self._lock:
            self._counter += 1
            pkt.number = self._counter
        with self._wlock:                    # Live-Mitschnitt (gefilterte Pakete)
            if self._writer is not None:
                self._writer.write_packet(pkt)
        with self._lock:
            self._buf.append(pkt)

    def _flush(self) -> None:
        with self._wlock:                    # Datei regelmäßig auf Platte bringen
            if self._writer is not None:
                self._writer.flush()
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
        if self._cap6 is not None:
            self._cap6.stop()
            self._cap6 = None
        self._flush()
        self.stop_recording()                # Mitschnitt-Datei sauber schließen
        self.stopped.emit()
