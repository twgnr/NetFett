"""Tests für die Verkehrs-Kategorisierung."""
from __future__ import annotations

from netfett.core.categories import aggregate_categories, categorize
from netfett.core.models import DIR_IN, DIR_OUT, Packet


def test_categorize_by_process():
    assert categorize("firefox.exe") == "Browser"
    assert categorize("msedge.exe") == "Browser"
    assert categorize("Teams.exe") == "Kommunikation"
    assert categorize("OUTLOOK.EXE") == "E-Mail"
    assert categorize("svchost.exe") == "System"
    assert categorize("spotify.exe") == "Medien"


def test_categorize_partial_match():
    assert categorize("ms-teams.exe") == "Kommunikation"
    assert categorize("chrome_proxy.exe") == "Browser"


def test_categorize_by_service_fallback():
    assert categorize("", dport=443) == "Web"
    assert categorize("", dport=53) == "Netz/System"
    assert categorize("", sport=993) == "E-Mail"
    assert categorize("", dport=22) == "Fernzugriff"


def test_categorize_default():
    assert categorize("unbekannt.exe", dport=12345) == "Sonstige"
    assert categorize("") == "Sonstige"


def _pkt(process, sport, dport, length=100, direction=DIR_OUT):
    return Packet(number=1, ts=1.0, raw=b"", direction=direction, src="a",
                  dst="b", src_port=sport, dst_port=dport, length=length,
                  process=process)


def test_aggregate_categories():
    pkts = [
        _pkt("firefox.exe", 50000, 443, 1000, DIR_OUT),
        _pkt("firefox.exe", 443, 50000, 400, DIR_IN),
        _pkt("", 40000, 53, 80, DIR_OUT),          # → Netz/System
    ]
    cats = {c.name: c for c in aggregate_categories(pkts)}
    assert cats["Browser"].bytes == 1400
    assert cats["Browser"].tx_bytes == 1000 and cats["Browser"].rx_bytes == 400
    assert "Netz/System" in cats
