"""Mehrsprachigkeit (Deutsch/Englisch) für NetFett.

Quellsprache ist Deutsch: Jeder sichtbare Text wird mit ``tr("deutscher Text")``
ausgegeben. Bei Sprache ``"en"`` liefert ``tr`` die Übersetzung aus den
Katalogen in ``netfett.locale.en`` (Modul-Dicts ``MESSAGES``), sonst den
deutschen Text unverändert. Platzhalter werden nach der Übersetzung gefüllt:
``tr("{n} Pakete").format(n=5)``.

Die Sprache wird beim Programmstart gesetzt (vor dem Import der GUI-Module),
ein Wechsel wird nach einem Neustart wirksam.
"""
from __future__ import annotations

import importlib
import pkgutil

LANGUAGES = {"de": "Deutsch", "en": "English"}
DEFAULT = "de"                  # Quellsprache (Texte im Code, ohne Katalog)
FIRST_RUN = "en"                # Sprache beim ersten Start (nichts gespeichert)
SETTINGS_KEY = "ui/language"

_lang = DEFAULT
_catalog: dict[str, str] = {}


def _load_catalog(lang: str) -> dict[str, str]:
    if lang == DEFAULT:
        return {}
    pkg = importlib.import_module(f"netfett.locale.{lang}")
    catalog: dict[str, str] = {}
    for info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda m: m.name):
        mod = importlib.import_module(f"{pkg.__name__}.{info.name}")
        catalog.update(getattr(mod, "MESSAGES", {}))
    return catalog


def set_language(lang: str) -> None:
    """Aktive Sprache setzen (unbekannte Codes fallen auf Deutsch zurück)."""
    global _lang, _catalog
    _lang = lang if lang in LANGUAGES else DEFAULT
    _catalog = _load_catalog(_lang)


def language() -> str:
    return _lang


def tr(text: str) -> str:
    """Text in die aktive Sprache übersetzen (fehlt die Übersetzung: Original)."""
    if not _catalog:
        return text
    return _catalog.get(text, text)


def load_saved_language() -> str:
    """Gespeicherte Sprache aus QSettings lesen und aktivieren (sonst Englisch)."""
    try:
        from PySide6.QtCore import QSettings
        lang = QSettings("NetFett", "NetFett").value(SETTINGS_KEY, FIRST_RUN, type=str)
    except Exception:                    # noqa: BLE001 – ohne Qt: Standard
        lang = FIRST_RUN
    set_language(lang)
    return _lang
