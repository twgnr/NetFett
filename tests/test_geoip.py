"""Tests für die optionale GeoIP-Auflösung (graceful ohne Lib/DB + Merge-Logik)."""
from __future__ import annotations

import pytest

from netfett.core import geoip


@pytest.fixture(autouse=True)
def _clean():
    geoip.clear()
    yield
    geoip.clear()


def test_graceful_without_database():
    assert geoip.available() is False
    assert geoip.lookup("8.8.8.8") is None
    assert geoip.describe("8.8.8.8") == ""
    assert geoip.databases() == []
    assert "GeoIP" in geoip.status()


def test_add_database_bad_path():
    msg = geoip.add_database("does-not-exist.mmdb")
    # Entweder Lib fehlt oder Datei fehlt – in beiden Fällen bleibt es inaktiv.
    assert geoip.available() is False
    assert "GeoIP" in msg or "maxminddb" in msg or "nicht laden" in msg


class _FakeReader:
    def __init__(self, mapping):
        self._m = mapping

    def get(self, ip):
        return self._m.get(ip)

    def close(self):
        pass


def test_lookup_merges_country_and_asn(monkeypatch):
    # Zwei „DBs" simulieren: Country und ASN, separat geladen.
    country = _FakeReader({"8.8.8.8": {
        "country": {"iso_code": "US", "names": {"de": "USA", "en": "United States"}},
        "city": {"names": {"de": "Mountain View"}}}})
    asn = _FakeReader({"8.8.8.8": {
        "autonomous_system_number": 15169,
        "autonomous_system_organization": "GOOGLE"}})
    geoip._readers.extend([country, asn])
    geoip._paths.extend(["country.mmdb", "asn.mmdb"])

    assert geoip.available() is True
    info = geoip.lookup("8.8.8.8")
    assert info["country_code"] == "US"
    assert info["country"] == "USA"
    assert info["city"] == "Mountain View"
    assert info["asn"] == 15169 and info["org"] == "GOOGLE"

    desc = geoip.describe("8.8.8.8")
    assert "Mountain View" in desc and "USA" in desc and "AS15169" in desc
    assert "GOOGLE" in desc


def test_lookup_unknown_ip_returns_none():
    geoip._readers.append(_FakeReader({"1.1.1.1": {"country": {"iso_code": "AU"}}}))
    geoip._paths.append("x.mmdb")
    assert geoip.lookup("9.9.9.9") is None
    assert geoip.lookup("1.1.1.1")["country_code"] == "AU"
