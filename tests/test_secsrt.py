"""Tests: Sicherheits-Heuristiken, SRT, TLS-Cert, TCP-Flags, pcapng-Kommentare."""
from __future__ import annotations

import datetime
import os
import socket
import struct
import tempfile

from netfett.core.analyze import (
    dns_tunneling, exfiltration, first_contacts, service_response_times,
    tcp_expert_flags,
)
from netfett.core.dissect import dissect
from netfett.core.models import DIR_OUT, Packet
from netfett.core.pcap import read_pcapng, write_pcapng

LOCAL = {"192.168.0.10"}


def _ip(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000,
                      64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def _tcp(sp, dp, seq, flags, payload=b"", ack=0):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 0x50, flags, 64240, 0, 0) + payload


def _dnsq(txid, name):
    q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


def _dnsr(txid, name):
    q = struct.pack("!HHHHHH", txid, 0x8000, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


def _pkt(n, raw, ts=1000.0):
    return dissect(raw, ts, n, LOCAL)


# --- Sicherheits-Heuristiken ----------------------------------------------- #
def test_dns_tunneling_detected():
    pkts = []
    for i in range(25):
        sub = f"datachunk{i:04d}exfiltrationpayload"
        raw = _ip("192.168.0.10", "8.8.8.8", 17, _udp(40000, 53,
                  _dnsq(i, f"{sub}.tunnel.example")))
        pkts.append(_pkt(i + 1, raw, ts=1000.0 + i))
    f = dns_tunneling(pkts)
    assert any("DNS-Tunneling" in x.summary for x in f)


def test_exfiltration_detected():
    big = Packet(number=1, ts=1.0, raw=b"", direction=DIR_OUT, src="192.168.0.10",
                 dst="9.9.9.9", length=12 * 1024 * 1024)
    f = exfiltration([big])
    assert any("9.9.9.9" in x.summary for x in f)


def test_first_contacts_order_and_public_only():
    pkts = [
        _pkt(1, _ip("192.168.0.10", "93.184.216.34", 6, _tcp(50000, 443, 0, 0x02))),
        _pkt(2, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50001, 443, 0, 0x02)), ts=2),
        _pkt(3, _ip("192.168.0.10", "192.168.0.20", 6, _tcp(50002, 80, 0, 0x02)), ts=3),
    ]
    fc = [ip for _ts, ip, _d in first_contacts(pkts)]
    assert fc == ["93.184.216.34", "1.1.1.1"]      # privat (192.168.*) ausgelassen


# --- SRT ------------------------------------------------------------------- #
def test_srt_dns():
    pkts = [
        _pkt(1, _ip("192.168.0.10", "8.8.8.8", 17, _udp(40000, 53, _dnsq(7, "a.b"))),
             ts=1.0),
        _pkt(2, _ip("8.8.8.8", "192.168.0.10", 17, _udp(53, 40000, _dnsr(7, "a.b"))),
             ts=1.05),
    ]
    rows = {r.protocol: r for r in service_response_times(pkts)}
    assert "DNS" in rows and 49 < rows["DNS"].avg_ms < 51


def test_srt_http_pairing():
    pkts = [
        _pkt(1, _ip("192.168.0.10", "1.1.1.1", 6,
                    _tcp(50000, 80, 1, 0x18, b"GET / HTTP/1.1\r\n\r\n")), ts=1.0),
        _pkt(2, _ip("1.1.1.1", "192.168.0.10", 6,
                    _tcp(80, 50000, 1, 0x18, b"HTTP/1.1 200 OK\r\n\r\n")), ts=1.2),
    ]
    rows = {r.protocol: r for r in service_response_times(pkts)}
    assert "HTTP" in rows and rows["HTTP"].count == 1


# --- TCP-Expert-Flags ------------------------------------------------------ #
def test_tcp_expert_retransmission():
    pkts = [
        _pkt(1, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, 100, 0x18, b"ABCDE")),
             ts=1.0),
        _pkt(2, _ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 443, 100, 0x18, b"ABCDE")),
             ts=2.0),
    ]
    flags = tcp_expert_flags(pkts)
    assert flags.get(2, "").startswith("Retransmission")
    assert "Seq=" in flags[2]                         # Grund mitgeliefert


def test_tcp_expert_dup_ack():
    pkts = [
        _pkt(i, _ip("1.1.1.1", "192.168.0.10", 6, _tcp(443, 50000, 0, 0x10, ack=500)),
             ts=float(i))
        for i in range(1, 4)
    ]
    flags = tcp_expert_flags(pkts)
    assert flags.get(2, "").startswith("Dup-ACK") and "ACK=" in flags[2]
    assert flags.get(3, "").startswith("Dup-ACK")


# --- TLS-Zertifikat -------------------------------------------------------- #
def _make_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    now = datetime.datetime(2024, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    from cryptography.hazmat.primitives.serialization import Encoding
    return cert.public_bytes(Encoding.DER)


def test_tls_certificate_in_detail():
    der = _make_cert()
    # TLS-Record: Handshake(0x16) v3.3, HS-Typ 11, Längen + cert
    body = (b"\x0b" + (3 + len(der) + 3).to_bytes(3, "big")     # HS len
            + (len(der) + 3).to_bytes(3, "big")                 # cert_list_len
            + len(der).to_bytes(3, "big") + der)                # cert_len + DER
    record = b"\x16\x03\x03" + struct.pack("!H", len(body)) + body
    raw = _ip("1.1.1.1", "192.168.0.10", 6, _tcp(443, 50000, 1, 0x18, record))
    pkt = dissect(raw, 1.0, 1, LOCAL)
    fields = dict([f for layer in pkt.layers for f in layer.fields])
    assert fields.get("Zertifikat-Subject") == "test.example"
    assert "Gültig bis" in fields


# --- pcapng-Kommentare ----------------------------------------------------- #
def test_pcapng_comments_written():
    p = Packet(number=1, ts=1.0, raw=b"\x45" + b"\x00" * 39, direction="?",
               length=40)
    path = os.path.join(tempfile.mkdtemp(), "c.pcapng")
    write_pcapng(path, [p], comments={1: "wichtig"})
    with open(path, "rb") as f:
        assert b"wichtig" in f.read()
    assert len(read_pcapng(path)) == 1               # weiterhin lesbar
