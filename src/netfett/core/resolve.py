"""Reverse-DNS-Namensauflösung (IP → Hostname) – gecacht und nebenläufig.

Bewusst GUI-frei und ohne Fremd-Dependencies (``socket.gethostbyaddr``). Die
Lookup-Funktion ist injizierbar, damit die Logik ohne echte DNS-Anfragen
testbar bleibt. Ergebnisse (auch leere) werden gecacht, sodass jede Adresse
höchstens einmal aufgelöst wird.
"""
from __future__ import annotations

import socket
import threading
from collections.abc import Callable, Iterable


def _default_lookup(ip: str) -> str:
    """PTR-Name einer IP oder leerer String (bei Fehler/keinem Eintrag)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return ""


class NameResolver:
    """Thread-sicherer Reverse-DNS-Cache mit blockierender und Hintergrund-API."""

    def __init__(self, lookup: Callable[[str], str] | None = None) -> None:
        self._lookup = lookup or _default_lookup
        self._cache: dict[str, str] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()

    def cached(self, ip: str) -> str | None:
        """Bereits aufgelöster Name (ggf. leer) oder ``None``, wenn unbekannt."""
        with self._lock:
            return self._cache.get(ip)

    def resolve(self, ip: str) -> str:
        """Blockierende Auflösung (nutzt/füllt den Cache)."""
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        name = self._lookup(ip) or ""
        with self._lock:
            self._cache[ip] = name
        return name

    def resolve_async(self, ips: Iterable[str],
                      on_progress: Callable[[str, str], None] | None = None
                      ) -> threading.Thread:
        """Löst mehrere IPs in einem Hintergrund-Thread auf.

        ``on_progress(ip, name)`` wird je neu aufgelöster IP aufgerufen (im
        Worker-Thread – in GUIs daher nur Daten ablegen, nicht zeichnen).
        Gibt den gestarteten Thread zurück (für Tests joinbar)."""
        todo = []
        with self._lock:
            for ip in ips:
                if ip not in self._cache and ip not in self._pending:
                    self._pending.add(ip)
                    todo.append(ip)

        def work() -> None:
            for ip in todo:
                name = self._lookup(ip) or ""
                with self._lock:
                    self._cache[ip] = name
                    self._pending.discard(ip)
                if on_progress is not None:
                    on_progress(ip, name)

        t = threading.Thread(target=work, name="netfett-resolve", daemon=True)
        t.start()
        return t

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._pending)
