"""Datenmodelle für erfasste Pakete und ihre Protokollschichten."""
from __future__ import annotations

from dataclasses import dataclass, field

# Richtung des Pakets relativ zum überwachten Rechner.
DIR_IN = "in"
DIR_OUT = "out"
DIR_UNKNOWN = "?"


@dataclass(slots=True)
class Layer:
    """Eine Protokollschicht für die Detailansicht (Baum)."""
    name: str                                   # z. B. "Internet Protocol v4"
    summary: str = ""                           # Kurzfassung in der Kopfzeile
    fields: list[tuple[str, str]] = field(default_factory=list)  # (Label, Wert)
    start: int = 0                              # Byte-Offset im Rohpaket
    length: int = 0                             # Länge in Bytes


@dataclass(slots=True)
class Packet:
    """Ein vollständig zerlegtes Paket."""
    number: int
    ts: float                 # Epoch-Sekunden des Empfangs
    raw: bytes                # Rohbytes (ab IPv4-Kopf; Raw-Socket liefert kein Ethernet)
    direction: str            # DIR_IN | DIR_OUT | DIR_UNKNOWN
    layers: list[Layer] = field(default_factory=list)

    # Denormalisiert für Tabelle/Filter (schneller Zugriff ohne Layer-Suche):
    src: str = ""
    dst: str = ""
    protocol: str = ""        # höchste erkannte Schicht, z. B. "TLS", "DNS", "TCP"
    l4: str = ""              # "TCP" | "UDP" | "ICMP" | …
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0           # Gesamtlänge des Pakets in Bytes
    info: str = ""            # Kurzbeschreibung (Wireshark-ähnlich)

    @property
    def ports(self) -> tuple[int | None, int | None]:
        return self.src_port, self.dst_port
