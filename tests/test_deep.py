"""Tests für tiefe Dissectoren: HTTP/2, SMB/SMB2, SIP, RTP."""
from __future__ import annotations

import socket
import struct

from netfett.core.dissect import dissect

LOCAL = {"192.168.0.10"}


def _ip(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0x4000,
                      64, proto, 0)
    return hdr + socket.inet_aton(src) + socket.inet_aton(dst) + payload


def _tcp(sp, dp, payload):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 0x50, 0x18, 64240, 0, 0) + payload


def _udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def _h2_frame(length, ftype, flags, sid):
    return length.to_bytes(3, "big") + bytes([ftype, flags]) + sid.to_bytes(4, "big")


# --- HTTP/2 ---------------------------------------------------------------- #
def test_http2_preface_and_settings():
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    body = preface + _h2_frame(0, 4, 0, 0)            # leeres SETTINGS
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 80, body)),
                  1.0, 1, LOCAL)
    assert pkt.protocol == "HTTP2" and "SETTINGS" in pkt.info


def test_http2_settings_only():
    body = _h2_frame(6, 4, 0, 0) + b"\x00\x03\x00\x00\x00\x64"   # 1 Setting
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 8080, body)),
                  1.0, 1, LOCAL)
    assert pkt.protocol == "HTTP2"


# --- SMB2 ------------------------------------------------------------------ #
def test_smb2_command():
    # Direct-TCP-Header (4) + SMB2-Header (\xfeSMB ... command@12 = 5 CREATE)
    smb2 = b"\xfeSMB" + b"\x40\x00" + b"\x00" * 6 + struct.pack("<H", 5) + b"\x00" * 50
    direct = b"\x00" + len(smb2).to_bytes(3, "big") + smb2
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 445, direct)),
                  1.0, 1, LOCAL)
    assert pkt.protocol == "SMB2" and "CREATE" in pkt.info


def test_smb1_detected():
    smb1 = b"\xffSMB" + b"\x72" + b"\x00" * 30        # Cmd 0x72 (Negotiate)
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 445, smb1)),
                  1.0, 1, LOCAL)
    assert pkt.protocol == "SMB"


# --- SIP ------------------------------------------------------------------- #
def test_sip_request():
    msg = (b"INVITE sip:bob@example.com SIP/2.0\r\n"
           b"From: alice <sip:alice@example.com>\r\n"
           b"To: bob <sip:bob@example.com>\r\n"
           b"Call-ID: abc123\r\nCSeq: 1 INVITE\r\n\r\n")
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 17, _udp(5060, 5060, msg)),
                  1.0, 1, LOCAL)
    assert pkt.protocol == "SIP" and "INVITE" in pkt.info
    sip = [l for l in pkt.layers if l.name.startswith("Session Initiation")][0]
    assert any(k == "Call-ID" for k, _v in sip.fields)


# --- RTP ------------------------------------------------------------------- #
def test_rtp_heuristic():
    rtp = bytes([0x80, 0x08]) + struct.pack("!HII", 1000, 160, 0x12345678) + b"\x00" * 20
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 17, _udp(40000, 40002, rtp)),
                  1.0, 1, LOCAL)
    assert pkt.protocol == "RTP" and "seq=1000" in pkt.info


def test_rtp_not_misfiring_on_dns_port():
    # Auf Port 53 wird DNS erkannt, nicht RTP.
    q = (struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
         + b"\x03www\x03org\x00" + struct.pack("!HH", 1, 1))
    pkt = dissect(_ip("192.168.0.10", "8.8.8.8", 17, _udp(50000, 53, q)),
                  1.0, 1, LOCAL)
    assert pkt.protocol == "DNS"
