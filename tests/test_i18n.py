"""Tests für die Mehrsprachigkeit (i18n) und die englischen Kataloge."""
import string

import pytest

from netfett import i18n
from netfett.i18n import language, set_language, tr


@pytest.fixture
def english():
    set_language("en")
    yield
    set_language("de")


def _fields(text: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(text) if f is not None}


def test_default_is_german_passthrough():
    assert language() == "de"
    assert tr("Verbindungen…") == "Verbindungen…"


def test_unknown_language_falls_back_to_german():
    set_language("xx")
    assert language() == "de"
    assert tr("Pakete") == "Pakete"


def test_english_lookup_and_fallback(english):
    assert language() == "en"
    assert tr("Zeitformat") == "Time Format"
    assert tr("gibt es nicht 123") == "gibt es nicht 123"


def test_catalog_entries_are_consistent(english):
    catalog = i18n._catalog
    assert len(catalog) > 100
    for de, en in catalog.items():
        assert en.strip(), f"leere Übersetzung für {de!r}"
        assert _fields(de) == _fields(en), f"Platzhalter weichen ab: {de!r}"


class _FakeSettings:
    stored: dict = {}

    def __init__(self, *_args):
        pass

    def value(self, key, default=None, type=None):     # noqa: A002 – Qt-API
        return self.stored.get(key, default)


def test_first_run_defaults_to_english(monkeypatch):
    import PySide6.QtCore
    monkeypatch.setattr(PySide6.QtCore, "QSettings", _FakeSettings)
    monkeypatch.setattr(_FakeSettings, "stored", {})
    try:
        assert i18n.load_saved_language() == "en"
        monkeypatch.setattr(_FakeSettings, "stored", {i18n.SETTINGS_KEY: "de"})
        assert i18n.load_saved_language() == "de"
    finally:
        set_language("de")
