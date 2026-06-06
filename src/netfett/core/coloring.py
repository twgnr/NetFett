"""Benutzerdefinierte Einfärbe-Regeln für die Paketliste.

Jede Regel hat einen Anzeigefilter-Ausdruck und Vorder-/Hintergrundfarben; das
erste passende (aktive) Regelwerk bestimmt die Farbe eines Pakets. Aufbauend auf
:mod:`netfett.core.displayfilter`. Rein und unit-testbar.
"""
from __future__ import annotations

from dataclasses import dataclass

from .displayfilter import FilterError, compile_filter
from .models import Packet


@dataclass(slots=True)
class ColorRule:
    name: str
    filter_text: str
    fg: str = ""            # Vordergrund (Hex) oder leer
    bg: str = ""            # Hintergrund (Hex) oder leer
    enabled: bool = True

    def to_dict(self) -> dict:
        return {"name": self.name, "filter": self.filter_text,
                "fg": self.fg, "bg": self.bg, "enabled": self.enabled}

    @classmethod
    def from_dict(cls, d: dict) -> "ColorRule":
        return cls(d.get("name", ""), d.get("filter", ""), d.get("fg", ""),
                   d.get("bg", ""), bool(d.get("enabled", True)))


class RuleSet:
    """Kompiliert die aktiven Regeln und liefert die Farbe des ersten Treffers."""

    def __init__(self, rules: list[ColorRule] | None = None) -> None:
        self._rules = list(rules or [])
        self._compiled = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                self._compiled.append((rule, compile_filter(rule.filter_text)))
            except FilterError:
                continue            # ungültige Regel wird stillschweigend übersprungen

    @property
    def rules(self) -> list[ColorRule]:
        return self._rules

    def match(self, pkt: Packet) -> tuple[str, str] | None:
        """(fg, bg) der ersten passenden Regel oder ``None``."""
        for rule, func in self._compiled:
            if func is None or func(pkt):
                return rule.fg, rule.bg
        return None

    def to_list(self) -> list[dict]:
        return [r.to_dict() for r in self._rules]

    @classmethod
    def from_list(cls, data) -> "RuleSet":
        return cls([ColorRule.from_dict(d) for d in (data or [])])


def default_rules() -> list[ColorRule]:
    """Ein paar sinnvolle Start-Regeln (Wireshark-ähnlich)."""
    return [
        ColorRule("Fehler/Reset", "icmp or rst", bg="#3a1414", fg="#ff7b72"),
        ColorRule("DNS", "dns or mdns", bg="#241a2e"),
        ColorRule("TLS/HTTPS", "tls or https", bg="#13241c"),
        ColorRule("HTTP", "http", bg="#2a2410"),
    ]
