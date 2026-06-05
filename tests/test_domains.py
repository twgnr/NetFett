"""Tests für Domain-Extraktion (TLS-SNI/HTTP-Host/DNS), Aggregation und Resolver."""
from __future__ import annotations

import socket
import struct

from netfett.core.analyze import domains
from netfett.core.dissect import dissect, tls_info
from netfett.core.resolve import NameResolver

LOCAL = {"192.168.0.10"}


def _ip(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000,
                      64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _tcp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18,
                       64240, 0, 0) + payload


def _client_hello(server_name: str) -> bytes:
    """Minimales, gültiges TLS-ClientHello mit SNI-Erweiterung."""
    sni = server_name.encode()
    # server_name extension: list_len | name_type(0) | name_len | name
    sn_entry = b"\x00" + struct.pack("!H", len(sni)) + sni
    sn_list = struct.pack("!H", len(sn_entry)) + sn_entry
    ext = struct.pack("!HH", 0x0000, len(sn_list)) + sn_list
    exts = struct.pack("!H", len(ext)) + ext
    body = (b"\x03\x03" + b"\x00" * 32       # version + random
            + b"\x00"                         # session_id_len = 0
            + struct.pack("!H", 0)            # cipher_suites_len = 0
            + b"\x00"                          # compression_len = 0
            + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body   # 3-Byte-Länge
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# --- TLS-SNI --------------------------------------------------------------- #
def test_sni_extracted_into_domain_and_info():
    raw = _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443,
                                                 _client_hello("example.com")))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    assert pkt.protocol == "TLS"
    assert pkt.domain == "example.com"
    assert "example.com" in pkt.info
    # Auch als Detail-Feld vorhanden
    tls = [l for l in pkt.layers if l.name.startswith("Transport Layer")][0]
    assert any(v == "example.com" for _k, v in tls.fields)


def test_tls_without_sni_has_no_domain():
    raw = _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, b"\x16\x03\x01\x00"))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    assert pkt.protocol == "TLS" and pkt.domain == ""


def _server_hello(cipher: int, version: int = 0x0303) -> bytes:
    """Minimales TLS-ServerHello (optional supported_versions für TLS 1.3)."""
    ext = b""
    if version == 0x0304:
        sv = struct.pack("!H", 0x0304)
        ext = struct.pack("!HH", 0x002B, len(sv)) + sv
    exts = struct.pack("!H", len(ext)) + ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"      # version + random + sid_len
            + struct.pack("!H", cipher) + b"\x00" + exts)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def test_tls_client_hello_info():
    info = tls_info(_client_hello("example.com"))
    assert info["type"] == "Client Hello"
    assert info["sni"] == "example.com"
    assert info["version"] in ("TLS 1.0", "TLS 1.2", "TLS 1.3")  # legacy 0x0301


def test_tls_server_hello_cipher_and_version():
    info = tls_info(_server_hello(0x1301, version=0x0304))
    assert info["type"] == "Server Hello"
    assert info["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert info["version"] == "TLS 1.3"


def test_tls_fields_in_dissected_packet():
    raw = _ip("1.1.1.1", "192.168.0.10", 6, _tcp(443, 50000, _server_hello(0xC02F)))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    tls = [l for l in pkt.layers if l.name.startswith("Transport Layer")][0]
    labels = {k: v for k, v in tls.fields}
    assert labels.get("Cipher Suite") == "ECDHE_RSA_AES128_GCM_SHA256"
    assert "Handshake-Typ" in labels


# --- HTTP-Host ------------------------------------------------------------- #
def test_http_host_extracted():
    req = b"GET /index.html HTTP/1.1\r\nHost: www.test.org\r\n\r\n"
    raw = _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 80, req))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    assert pkt.protocol == "HTTP"
    assert pkt.domain == "www.test.org"


def test_http_request_headers_in_detail():
    req = (b"GET /index.html HTTP/1.1\r\nHost: www.test.org\r\n"
           b"User-Agent: NetFett\r\nAccept: */*\r\n\r\n")
    raw = _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 80, req))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    http = [l for l in pkt.layers if l.name.startswith("Hypertext")][0]
    f = dict(http.fields)
    assert f["Typ"] == "Anfrage" and f["Methode"] == "GET"
    assert f["Pfad"] == "/index.html" and f["Version"] == "HTTP/1.1"
    assert f["User-Agent"] == "NetFett" and f["Accept"] == "*/*"


def test_http_response_status_in_detail():
    resp = b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n"
    raw = _ip("1.1.1.1", "192.168.0.10", 6, _tcp(80, 50000, resp))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    http = [l for l in pkt.layers if l.name.startswith("Hypertext")][0]
    f = dict(http.fields)
    assert f["Typ"] == "Antwort" and f["Status"] == "404 Not Found"
    assert f["Server"] == "nginx"


# --- DNS ------------------------------------------------------------------- #
def test_dns_query_sets_domain():
    q = (struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
         + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))
    raw = _ip("192.168.0.10", "8.8.8.8", 17,
              struct.pack("!HHHH", 50000, 53, 8 + len(q), 0) + q)
    pkt = dissect(raw, 1.0, 1, LOCAL)
    assert pkt.protocol == "DNS"
    assert pkt.domain == "example.com"


# --- domains() ------------------------------------------------------------- #
def test_domains_aggregates_and_sorts():
    p1 = dissect(_ip("192.168.0.10", "1.1.1.1", 6,
                     _tcp(50000, 443, _client_hello("a.com"))), 1.0, 1, LOCAL)
    p2 = dissect(_ip("192.168.0.10", "1.1.1.1", 6,
                     _tcp(50001, 443, _client_hello("a.com"))), 2.0, 2, LOCAL)
    p3 = dissect(_ip("192.168.0.10", "1.1.1.1", 6,
                     _tcp(50002, 80, b"GET / HTTP/1.1\r\nHost: b.com\r\n\r\n")),
                 3.0, 3, LOCAL)
    ds = domains([p1, p2, p3])
    assert [d.name for d in ds] == ["a.com", "b.com"]   # a.com häufiger
    assert ds[0].packets == 2 and ds[0].protocols == ("TLS",)
    assert ds[1].protocols == ("HTTP",)


def test_domains_empty():
    assert domains([]) == []


# --- NameResolver ---------------------------------------------------------- #
def test_resolver_caches_and_uses_injected_lookup():
    calls = []

    def fake(ip: str) -> str:
        calls.append(ip)
        return {"1.1.1.1": "one.example"}.get(ip, "")

    r = NameResolver(lookup=fake)
    assert r.resolve("1.1.1.1") == "one.example"
    assert r.resolve("1.1.1.1") == "one.example"   # zweiter Aufruf aus Cache
    assert calls == ["1.1.1.1"]                     # nur einmal aufgelöst
    assert r.cached("1.1.1.1") == "one.example"
    assert r.cached("9.9.9.9") is None


def test_resolver_async_fills_cache():
    r = NameResolver(lookup=lambda ip: f"host-{ip}")
    seen = {}
    t = r.resolve_async(["1.2.3.4", "5.6.7.8"],
                        on_progress=lambda ip, n: seen.__setitem__(ip, n))
    t.join(timeout=2.0)
    assert r.cached("1.2.3.4") == "host-1.2.3.4"
    assert seen == {"1.2.3.4": "host-1.2.3.4", "5.6.7.8": "host-5.6.7.8"}
    assert r.pending == 0
