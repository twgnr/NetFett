"""Tests: SMTP/IMAP/POP3-, FTP- und SSH-Dissectoren + Filter-Keywords."""
from __future__ import annotations

import socket
import struct

from netfett.core.dissect import dissect
from netfett.core.displayfilter import compile_filter

LOCAL = {"192.168.0.10"}


def _ip(src, dst, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000, 64, 6, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _tcp(sp, dp, payload):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 0x50, 0x18, 64240, 0, 0) + payload


def _pkt(src, dst, sp, dp, payload, n=1):
    return dissect(_ip(src, dst, _tcp(sp, dp, payload)), 1.0, n, LOCAL)


def _fields(pkt):
    return dict([f for layer in pkt.layers for f in layer.fields])


# --- SMTP ------------------------------------------------------------------ #
def test_smtp_client_command():
    pkt = _pkt("192.168.0.10", "9.9.9.9", 50000, 25, b"MAIL FROM:<a@x.de>\r\n")
    assert pkt.protocol == "SMTP"
    f = _fields(pkt)
    assert f["Richtung"] == "Client→Server"
    assert f.get("Auffällig", "").lower().startswith("mail from")


def test_smtp_server_response():
    pkt = _pkt("9.9.9.9", "192.168.0.10", 25, 50000, b"220 mail.example ESMTP\r\n")
    assert pkt.protocol == "SMTP"
    assert _fields(pkt)["Richtung"] == "Server→Client"


def test_smtp_submission_port_587():
    pkt = _pkt("192.168.0.10", "9.9.9.9", 50000, 587, b"EHLO client\r\n")
    assert pkt.protocol == "SMTP"


# --- POP3 / IMAP ----------------------------------------------------------- #
def test_pop3_user():
    pkt = _pkt("192.168.0.10", "9.9.9.9", 50000, 110, b"USER alice\r\n")
    assert pkt.protocol == "POP3"
    assert _fields(pkt).get("Auffällig", "").lower().startswith("user")


def test_imap_login():
    pkt = _pkt("192.168.0.10", "9.9.9.9", 50000, 143, b"a1 LOGIN alice secret\r\n")
    assert pkt.protocol == "IMAP"


# --- FTP ------------------------------------------------------------------- #
def test_ftp_command():
    pkt = _pkt("192.168.0.10", "9.9.9.9", 50000, 21, b"USER anonymous\r\n")
    assert pkt.protocol == "FTP"
    assert _fields(pkt)["Richtung"] == "Client→Server"


def test_ftp_server_banner():
    pkt = _pkt("9.9.9.9", "192.168.0.10", 21, 50000, b"220 FTP ready\r\n")
    assert pkt.protocol == "FTP" and _fields(pkt)["Richtung"] == "Server→Client"


# --- SSH ------------------------------------------------------------------- #
def test_ssh_banner():
    pkt = _pkt("192.168.0.10", "9.9.9.9", 50000, 22, b"SSH-2.0-OpenSSH_9.6\r\n")
    assert pkt.protocol == "SSH"
    assert _fields(pkt)["Version"].startswith("SSH-2.0-OpenSSH")


def test_ssh_kexinit():
    body = struct.pack("!IB", 1500, 8) + bytes([20]) + b"\x00" * 16
    pkt = _pkt("192.168.0.10", "9.9.9.9", 50000, 22, body)
    assert pkt.protocol == "SSH"
    assert "KEXINIT" in _fields(pkt)["Nachricht"]


def test_ssh_ignores_random_binary():
    # Unbekannte Nachrichten-Codes dürfen KEINEN detaillierten SSH-Layer erzeugen
    # (Port 22 wird generisch trotzdem als „SSH" gelabelt – das ist ok).
    body = struct.pack("!IB", 1500, 8) + bytes([200]) + b"\x00" * 16
    pkt = _pkt("192.168.0.10", "9.9.9.9", 50000, 22, body)
    assert not any(layer.name == "Secure Shell" for layer in pkt.layers)


# --- Filter-Keywords ------------------------------------------------------- #
def test_filter_keywords():
    smtp = _pkt("192.168.0.10", "9.9.9.9", 50000, 25, b"EHLO x\r\n")
    pop3 = _pkt("192.168.0.10", "9.9.9.9", 50000, 110, b"USER a\r\n")
    ssh = _pkt("192.168.0.10", "9.9.9.9", 50000, 22, b"SSH-2.0-x\r\n")
    assert compile_filter("smtp")(smtp) and not compile_filter("smtp")(ssh)
    assert compile_filter("ssh")(ssh)
    assert compile_filter("mail")(smtp) and compile_filter("mail")(pop3)
    assert not compile_filter("mail")(ssh)
