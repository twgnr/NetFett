"""Tests: TLS-Hygiene, DNS-Auffälligkeiten, Scan/Verbindung, Volumen/DoS."""
from __future__ import annotations

import datetime
import socket
import struct

from netfett.core.analyze import (
    _host_matches_cert, _shannon_entropy, connection_anomalies, dns_anomalies,
    tls_hygiene, traffic_anomalies,
)
from netfett.core.dissect import dissect
from netfett.core.models import Packet

LOCAL = {"192.168.0.10"}


# ---- Bau-Helfer ----------------------------------------------------------- #
def _ip(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000, 64,
                      proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _tcp(sp, dp, payload=b"", flags=0x18, seq=1, ack=0):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 0x50, flags, 64240, 0, 0) + payload


def _udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def _pkt(src, dst, proto, l4payload, n=1, ts=1.0):
    return dissect(_ip(src, dst, proto, l4payload), ts, n, LOCAL)


def _dns_query(txid, name, extra=b""):
    q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1) + extra


def _dns_resp(txid, name, rcode=0, answers=0, padding=b""):
    flags = 0x8000 | (rcode & 0x0F)
    r = struct.pack("!HHHHHH", txid, flags, 1, answers, 0, 0)
    for part in name.split("."):
        r += bytes([len(part)]) + part.encode()
    r += b"\x00" + struct.pack("!HH", 1, 1)
    for _ in range(answers):
        r += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return r + padding


def _tls_client_hello(version=0x0303, sni="", cipher_dummy=True):
    # Minimaler ClientHello (Handshake-Record) mit optionaler SNI-Extension.
    body = struct.pack("!H", version) + b"\x00" * 32 + b"\x00"   # version,random,sid_len
    body += struct.pack("!H", 2) + b"\x00\x2f"                   # cipher suites
    body += b"\x01\x00"                                          # compression
    exts = b""
    if sni:
        name = sni.encode()
        sni_ext = b"\x00" + struct.pack("!H", len(name)) + name
        sni_list = struct.pack("!H", len(sni_ext)) + sni_ext
        exts += b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body       # HS-Typ 1 + len(3)
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def _tls_server_hello(version=0x0303, cipher=0x002f):
    body = struct.pack("!H", version) + b"\x00" * 32 + b"\x00"
    body += struct.pack("!H", cipher) + b"\x00"                  # cipher + compression
    body += struct.pack("!H", 0)                                # keine Extensions
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


# ==== A: TLS-Hygiene ======================================================== #
def test_tls_weak_version():
    rec = _tls_client_hello(version=0x0301)              # TLS 1.0
    pkt = _pkt("192.168.0.10", "9.9.9.9", 6, _tcp(50000, 443, rec))
    f = tls_hygiene([pkt])
    assert any("Veraltete TLS-Version" in x.summary and "TLS 1.0" in x.summary
               for x in f)


def test_tls_modern_version_quiet():
    rec = _tls_client_hello(version=0x0303)              # TLS 1.2
    pkt = _pkt("192.168.0.10", "9.9.9.9", 6, _tcp(50000, 443, rec))
    assert not any("Veraltete" in x.summary for x in tls_hygiene([pkt]))


def test_tls_weak_cipher():
    rec = _tls_server_hello(cipher=0x0005)               # TLS_RSA_WITH_RC4_128_SHA
    pkt = _pkt("9.9.9.9", "192.168.0.10", 6, _tcp(443, 50000, rec))
    f = tls_hygiene([pkt])
    assert any("Schwache Cipher" in x.summary for x in f)


def test_tls_self_signed_and_expired_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self.example")])
    nb = datetime.datetime(2020, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(nb).not_valid_after(nb + datetime.timedelta(days=10))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(Encoding.DER)
    body = (b"\x0b" + (3 + len(der) + 3).to_bytes(3, "big")
            + (len(der) + 3).to_bytes(3, "big")
            + len(der).to_bytes(3, "big") + der)
    rec = b"\x16\x03\x03" + struct.pack("!H", len(body)) + body
    # Erfassungszeit 2024 → Zertifikat (gültig bis 2020) ist abgelaufen.
    pkt = _pkt("9.9.9.9", "192.168.0.10", 6, _tcp(443, 50000, rec),
               ts=1_700_000_000.0)
    f = tls_hygiene([pkt])
    assert any("Selbst-signiert" in x.summary for x in f)
    assert any("Abgelaufenes Zertifikat" in x.summary for x in f)


def test_host_matches_cert_wildcard():
    assert _host_matches_cert("www.example.com", ["*.example.com"])
    assert _host_matches_cert("example.com", ["example.com"])
    assert not _host_matches_cert("evil.com", ["example.com", "*.example.com"])


# ==== B: DNS-Auffälligkeiten ================================================ #
def test_dns_dga_high_entropy():
    name = "x7z9q2w8p1k5.com"                            # zufällig wirkend
    pkt = _pkt("192.168.0.10", "8.8.8.8", 17, _udp(40000, 53, _dns_query(1, name)))
    f = dns_anomalies([pkt])
    assert any("DGA-Verdacht" in x.summary for x in f)


def test_dns_normal_domain_quiet():
    pkt = _pkt("192.168.0.10", "8.8.8.8", 17,
               _udp(40000, 53, _dns_query(1, "www.google.com")))
    assert not any("DGA" in x.summary for x in dns_anomalies([pkt]))


def test_dns_nxdomain_rate():
    pkts = []
    for i in range(22):
        q = _pkt("192.168.0.10", "8.8.8.8", 17,
                 _udp(40000, 53, _dns_query(i, f"bad{i}.example")), n=2 * i + 1)
        r = _pkt("8.8.8.8", "192.168.0.10", 17,
                 _udp(53, 40000, _dns_resp(i, f"bad{i}.example", rcode=3)),
                 n=2 * i + 2)
        pkts += [q, r]
    f = dns_anomalies(pkts)
    assert any("Hohe NXDOMAIN-Rate" in x.summary for x in f)


def test_dns_amplification():
    q = _pkt("192.168.0.10", "8.8.8.8", 17,
             _udp(40000, 53, _dns_query(5, "a.b")), n=1)
    r = _pkt("8.8.8.8", "192.168.0.10", 17,
             _udp(53, 40000, _dns_resp(5, "a.b", answers=20, padding=b"\x00" * 600)),
             n=2)
    f = dns_anomalies([q, r])
    assert any("Amplification" in x.summary for x in f)


def test_shannon_entropy():
    assert _shannon_entropy("aaaa") == 0.0
    assert _shannon_entropy("abcd") == 2.0


# ==== C: Scan/Verbindung ==================================================== #
def test_risky_port_rdp():
    pkt = _pkt("192.168.0.10", "9.9.9.9", 6, _tcp(50000, 3389, flags=0x02))
    f = connection_anomalies([pkt])
    assert any("RDP" in x.summary and "riskant" in x.summary for x in f)


def test_telnet_cleartext():
    pkt = _pkt("192.168.0.10", "9.9.9.9", 6, _tcp(50000, 23, flags=0x02))
    f = connection_anomalies([pkt])
    assert any("Telnet" in x.summary and "unverschlüsselt" in x.summary for x in f)


def test_syn_flood_half_open():
    pkts = [_pkt("192.168.0.10", "9.9.9.9", 6, _tcp(50000 + i, 80, flags=0x02), n=i)
            for i in range(25)]
    f = connection_anomalies(pkts)
    assert any("Half-Open" in x.summary or "SYN-Flood" in x.summary for x in f)


def test_connection_failure_rate():
    pkts = [_pkt("9.9.9.9", "192.168.0.10", 6, _tcp(80, 50000 + i, flags=0x04), n=i)
            for i in range(22)]                          # 22× RST an unseren Host
    f = connection_anomalies(pkts)
    assert any("Verbindungs-Fehlerrate" in x.summary for x in f)


def test_normal_https_quiet():
    pkt = _pkt("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, flags=0x02))
    assert connection_anomalies([pkt]) == []


# ==== D: Volumen/DoS/Tunneling ============================================== #
def test_icmp_tunneling():
    big = b"\x08\x00\x00\x00\x00\x01\x00\x01" + b"X" * 200    # Echo + große Nutzlast
    pkts = [_pkt("192.168.0.10", "9.9.9.9", 1, big, n=i, ts=1.0 + i * 0.01)
            for i in range(12)]
    f = traffic_anomalies(pkts)
    assert any("ICMP-Tunneling" in x.summary for x in f)


def test_traffic_flood():
    pkts = [_pkt("192.168.0.10", "9.9.9.9", 6, _tcp(50000, 80, flags=0x02),
                 n=i, ts=5.0) for i in range(2100)]       # alle in derselben Sekunde
    f = traffic_anomalies(pkts)
    assert any("Traffic-Spitze" in x.summary or "Flood" in x.summary for x in f)


def test_ntp_monlist():
    # NTP mode 7 (privat): erstes Byte mode-Bits = 7
    pkt = _pkt("192.168.0.10", "9.9.9.9", 17, _udp(40000, 123, b"\x17" + b"\x00" * 8))
    f = traffic_anomalies([pkt])
    assert any("monlist" in x.summary for x in f)
