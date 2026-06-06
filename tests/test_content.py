"""Tests für die Nutzdaten-/Inhaltsklassifizierung."""
from __future__ import annotations

import socket
import struct

from netfett.core.content import as_text, content_view, is_mostly_text, l4_payload


def _ip(proto, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000,
                      64, proto, 0)
    return hdr + socket.inet_aton("192.168.0.10") + socket.inet_aton("1.1.1.1") + payload


def _tcp(payload):
    return struct.pack("!HHIIBBHHH", 50000, 80, 1, 0, 0x50, 0x18, 64240, 0, 0) + payload


def _udp(payload):
    return struct.pack("!HHHH", 50000, 53, 8 + len(payload), 0) + payload


def test_l4_payload_tcp_and_udp():
    assert l4_payload(_ip(6, _tcp(b"hello"))) == ("TCP", b"hello")
    assert l4_payload(_ip(17, _udp(b"\x00\x01"))) == ("UDP", b"\x00\x01")


def test_content_view_cleartext_http():
    raw = _ip(6, _tcp(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    kind, is_text, payload = content_view(raw)
    assert is_text and kind == "Klartext"
    assert as_text(payload).startswith("GET / HTTP/1.1")


def test_content_view_tls_is_bytes():
    raw = _ip(6, _tcp(b"\x16\x03\x01\x00\x05hello"))
    kind, is_text, _payload = content_view(raw)
    assert not is_text and "TLS" in kind


def test_content_view_binary_is_bytes():
    raw = _ip(6, _tcp(bytes(range(0, 32)) * 4))      # viele Steuerbytes
    kind, is_text, _payload = content_view(raw)
    assert not is_text and "Bytes" in kind


def test_content_view_empty():
    raw = _ip(6, _tcp(b""))
    kind, is_text, payload = content_view(raw)
    assert payload == b"" and kind == "Keine Nutzdaten"


def test_is_mostly_text():
    assert is_mostly_text(b"plain ascii text\r\n")
    assert not is_mostly_text(bytes(range(0, 32)))
    assert not is_mostly_text(b"")
