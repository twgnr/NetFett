"""WHOIS-Abfrage (TCP/43) – reine Standardbibliothek.

Fragt zuerst ``whois.iana.org`` und folgt einer Referral-Zeile (``refer:`` /
``whois:``) zum zuständigen Server. Liefert den kombinierten Rohtext.
"""
from __future__ import annotations

import socket

_REFERRAL_KEYS = ("refer:", "whois:", "registrar whois server:")


def _query_server(server: str, query: str, timeout: float = 6.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def referral(text: str) -> str:
    """Liest den Referral-WHOIS-Server aus einer Antwort (oder „")."""
    for line in text.splitlines():
        low = line.strip().lower()
        for key in _REFERRAL_KEYS:
            if low.startswith(key):
                return line.split(":", 1)[1].strip()
    return ""


def whois(query: str, timeout: float = 6.0) -> str:
    """WHOIS für eine Domain/IP – inkl. einem Referral-Hop."""
    text = _query_server("whois.iana.org", query, timeout)
    ref = referral(text)
    if ref and ref.lower() != "whois.iana.org":
        try:
            text += f"\n\n=== {ref} ===\n" + _query_server(ref, query, timeout)
        except OSError as exc:
            text += f"\n\n(Referral {ref} nicht erreichbar: {exc})"
    return text
