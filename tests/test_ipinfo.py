"""Tests für die Offline-IP-Klassifizierung."""
from __future__ import annotations

from netfett.core.ipinfo import classify, is_public


def test_private_ranges():
    assert classify("192.168.1.5") == "Privates Netz (LAN)"
    assert classify("10.0.0.1") == "Privates Netz (LAN)"
    assert classify("172.16.5.4") == "Privates Netz (LAN)"


def test_special_ranges():
    assert classify("127.0.0.1") == "Loopback"
    assert classify("169.254.1.1") == "Link-local"
    assert classify("100.64.0.1") == "CGNAT (Carrier-NAT)"
    assert classify("192.0.2.10").startswith("Dokumentation")
    assert classify("224.0.0.1") == "Multicast"


def test_well_known_services():
    assert classify("8.8.8.8") == "Google Public DNS"
    assert classify("1.1.1.1") == "Cloudflare DNS"
    assert classify("2606:4700:4700::1111") == "Cloudflare DNS"


def test_public_and_ipv6():
    assert classify("93.184.216.34") == "Öffentlich (Internet)"
    assert is_public("93.184.216.34")
    assert classify("2001:db8::1") == "Dokumentation"
    assert classify("fe80::1") == "Link-local"
    assert classify("ff02::1") == "Multicast"
    assert classify("::1") == "Loopback"


def test_invalid():
    assert classify("nicht-eine-ip") == ""
    assert not is_public("garbage")
