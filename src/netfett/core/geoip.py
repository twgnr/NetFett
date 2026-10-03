"""Optionale GeoIP-Auflösung über MaxMind-GeoLite2-Datenbanken (``.mmdb``).

NetFett bringt **keine** GeoIP-Daten mit (Lizenz/Größe). Wer Land/Stadt/ASN
sehen will, lädt eine oder mehrere GeoLite2-Dateien (Country/City/ASN). Ohne die
optionale Abhängigkeit ``maxminddb`` oder ohne geladene DB bleibt die Funktion
schlicht inaktiv – alles andere arbeitet unverändert weiter.

    pip install maxminddb        # oder:  pip install netfett[geoip]
"""
from __future__ import annotations

try:                                    # optionale Abhängigkeit
    import maxminddb
except ImportError:                     # pragma: no cover - umgebungsabhängig
    maxminddb = None

from ..i18n import language, tr

# Geöffnete Reader + zugehörige Pfade (mehrere DBs lassen sich kombinieren).
_readers: list = []
_paths: list[str] = []


def lib_available() -> bool:
    """True, wenn die Bibliothek ``maxminddb`` importierbar ist."""
    return maxminddb is not None


def available() -> bool:
    """True, wenn mindestens eine Datenbank geladen ist."""
    return bool(_readers)


def databases() -> list[str]:
    return list(_paths)


def clear() -> None:
    for r in _readers:
        try:
            r.close()
        except Exception:
            pass
    _readers.clear()
    _paths.clear()


def add_database(path: str) -> str:
    """Lädt eine ``.mmdb``. Gibt eine Status-/Fehlermeldung zurück."""
    if maxminddb is None:
        return tr("GeoIP nicht verfügbar – Paket 'maxminddb' fehlt "
                  "(pip install maxminddb).")
    try:
        reader = maxminddb.open_database(path)
    except (OSError, ValueError) as exc:
        return tr("Konnte GeoIP-Datenbank nicht laden: {exc}").format(exc=exc)
    _readers.append(reader)
    _paths.append(path)
    return tr("GeoIP-Datenbank geladen: {path}").format(path=path)


def status() -> str:
    if maxminddb is None:
        return tr("GeoIP: Bibliothek 'maxminddb' nicht installiert.")
    if not _readers:
        return tr("GeoIP: keine Datenbank geladen.")
    return tr("GeoIP: {n} Datenbank(en) geladen.").format(n=len(_readers))


def _names(node: dict) -> str:
    names = node.get("names", {}) if isinstance(node, dict) else {}
    # Ortsnamen bevorzugt in der Oberflächensprache (Fallback de → en).
    return names.get(language()) or names.get("de") or names.get("en") or ""


def lookup(ip: str) -> dict | None:
    """Sucht ``ip`` in allen geladenen DBs und führt die Felder zusammen.

    Liefert ein dict mit (sofern vorhanden) ``country_code``, ``country``,
    ``city``, ``asn`` und ``org`` – oder ``None``, wenn nichts gefunden wurde."""
    if not _readers:
        return None
    out: dict = {}
    for reader in _readers:
        try:
            rec = reader.get(ip)
        except (ValueError, KeyError):
            rec = None
        if not isinstance(rec, dict):
            continue
        country = rec.get("country") or rec.get("registered_country")
        if isinstance(country, dict):
            out.setdefault("country_code", country.get("iso_code", ""))
            name = _names(country)
            if name:
                out.setdefault("country", name)
        city = rec.get("city")
        if isinstance(city, dict):
            name = _names(city)
            if name:
                out.setdefault("city", name)
        if "autonomous_system_number" in rec:
            out.setdefault("asn", rec["autonomous_system_number"])
        if rec.get("autonomous_system_organization"):
            out.setdefault("org", rec["autonomous_system_organization"])
    return out or None


def describe(ip: str) -> str:
    """Kompakte Einzeiler-Beschreibung (oder leer)."""
    info = lookup(ip)
    if not info:
        return ""
    parts = []
    loc = " ".join(x for x in (info.get("city"), info.get("country")) if x)
    if loc:
        parts.append(loc)
    if info.get("country_code") and not info.get("country"):
        parts.append(info["country_code"])
    if info.get("asn"):
        parts.append(f"AS{info['asn']}" + (f" {info['org']}"
                                           if info.get("org") else ""))
    elif info.get("org"):
        parts.append(info["org"])
    return " · ".join(parts)
