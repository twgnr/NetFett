"""Tests für SMB2-Tiefe (Dateiname/Pfad) und RTP-Stream-Verfolgung."""
from __future__ import annotations

import socket
import struct

from netfett.core.analyze import rtp_streams
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


# --- SMB2-Tiefe ------------------------------------------------------------ #
def _smb2_header(cmd, flags=0):
    h = bytearray(64)
    h[0:4] = b"\xfeSMB"
    h[4:6] = (64).to_bytes(2, "little")
    h[12:14] = cmd.to_bytes(2, "little")
    h[16:20] = flags.to_bytes(4, "little")
    h[24:32] = (42).to_bytes(8, "little")            # MessageId
    return h


def test_smb2_create_filename():
    name = "geheim.docx".encode("utf-16-le")
    body = bytearray(48 + 2)                          # CREATE-Request-Body grob
    # NameOffset/NameLength liegen bei Header-Offset 108/110.
    h = _smb2_header(5)                               # CREATE, Anfrage
    name_off = 64 + len(body)
    h += body
    # NameOffset (108) / NameLength (110) setzen:
    h[108:110] = name_off.to_bytes(2, "little")
    h[110:112] = len(name).to_bytes(2, "little")
    data = bytes(h) + name
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 445, data)),
                  1.0, 1, LOCAL)
    assert pkt.protocol == "SMB2"
    fields = dict([f for layer in pkt.layers for f in layer.fields])
    assert fields.get("Dateiname") == "geheim.docx"
    assert fields.get("Richtung") == "Anfrage"


def test_smb2_tree_connect_path():
    path = "\\\\server\\share".encode("utf-16-le")
    h = bytearray(_smb2_header(3))                    # TREE_CONNECT
    h += bytearray(8)                                 # fester Body-Teil (Offset 64–71)
    path_off = len(h)
    h[68:70] = path_off.to_bytes(2, "little")
    h[70:72] = len(path).to_bytes(2, "little")
    data = bytes(h) + path
    pkt = dissect(_ip("192.168.0.10", "1.1.1.1", 6, _tcp(50000, 445, data)),
                  1.0, 1, LOCAL)
    fields = dict([f for layer in pkt.layers for f in layer.fields])
    assert fields.get("Pfad") == "\\\\server\\share"


def test_smb2_response_status():
    h = bytearray(_smb2_header(5, flags=0x1))         # CREATE-Antwort
    h[8:12] = (0).to_bytes(4, "little")
    pkt = dissect(_ip("1.1.1.1", "192.168.0.10", 6, _tcp(445, 50000, bytes(h))),
                  1.0, 1, LOCAL)
    fields = dict([f for layer in pkt.layers for f in layer.fields])
    assert fields.get("Richtung") == "Antwort" and "Status" in fields


# --- RTP-Streams ----------------------------------------------------------- #
def _rtp(pt, seq, ts, ssrc):
    return bytes([0x80, pt & 0x7F]) + struct.pack("!HII", seq, ts, ssrc) + b"\x00" * 10


def _rtp_pkt(n, seq, ts, ssrc=0xABCD, sp=40000, dp=40002, arr=0.0):
    raw = _ip("192.168.0.10", "1.1.1.1", 17, _udp(sp, dp, _rtp(0, seq, ts, ssrc)))
    return dissect(raw, arr, n, LOCAL)


def test_rtp_stream_loss_and_count():
    # seq 100,101,103,104 → eines (102) fehlt; ts in 160er-Schritten (8 kHz)
    pkts = [_rtp_pkt(i, 100 + s, 160 * k, arr=0.02 * k)
            for k, (i, s) in enumerate(
                [(1, 0), (2, 1), (3, 3), (4, 4)])]
    streams = rtp_streams(pkts)
    assert len(streams) == 1
    st = streams[0]
    assert st.payload_type == 0 and st.packets == 4
    assert st.lost == 1                               # seq 102 fehlt
    assert st.jitter_ms >= 0.0
    assert st.ssrc == 0xABCD


def test_rtp_streams_separate_ssrc():
    pkts = [_rtp_pkt(1, 1, 0, ssrc=0x1111), _rtp_pkt(2, 2, 160, ssrc=0x1111),
            _rtp_pkt(3, 1, 0, ssrc=0x2222)]
    assert len(rtp_streams(pkts)) == 2


def test_rtp_streams_empty():
    assert rtp_streams([]) == []
