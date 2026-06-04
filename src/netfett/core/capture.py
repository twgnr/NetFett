"""Capture-Backend: Windows-Raw-Socket im Promiskuitiv-Modus (``SIO_RCVALL``).

Erfasst **alle** über die gewählte Schnittstelle laufenden IPv4-Pakete – ein-
und ausgehend – ohne Npcap/WinPcap. Erfordert Administratorrechte. Die Klasse
ist GUI-frei: ein Hintergrund-Thread ruft pro Paket einen Callback auf.
"""
from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable


class CaptureError(RuntimeError):
    pass


class RawSocketCapture:
    """Liest Rohpakete (ab IPv4-Kopf) von einer lokalen Schnittstelle."""

    def __init__(self, host_ip: str,
                 on_packet: Callable[[float, bytes], None],
                 on_error: Callable[[str], None] | None = None) -> None:
        self.host_ip = host_ip
        self._on_packet = on_packet
        self._on_error = on_error or (lambda _m: None)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return
        if not hasattr(socket, "SIO_RCVALL"):
            raise CaptureError(
                "SIO_RCVALL wird nur unter Windows unterstützt.")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_IP)
            sock.bind((self.host_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            sock.settimeout(1.0)
        except PermissionError as exc:
            raise CaptureError(
                "Zugriff verweigert – bitte NetFett als Administrator starten.") from exc
        except OSError as exc:
            raise CaptureError(f"Schnittstelle konnte nicht geöffnet werden: {exc}") from exc
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="netfett-capture",
                                        daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        sock = self._sock
        assert sock is not None
        while self._running:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._running:
                    self._on_error(str(exc))
                break
            if data:
                self._on_packet(time.time(), data)

    def stop(self) -> None:
        self._running = False
        sock = self._sock
        if sock is not None:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
