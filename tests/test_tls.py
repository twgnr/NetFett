"""Tests für TLS-Schlüsselableitung und Record-Entschlüsselung."""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from netfett.core.tlsdecrypt import decrypt_tls12_record, decrypt_tls13_record
from netfett.core.tlskeys import (
    hkdf_expand, hkdf_expand_label, parse_keylog, tls12_key_block, tls13_key_iv,
)


# --- Keylog ---------------------------------------------------------------- #
def test_parse_keylog():
    text = ("# Kommentar\n"
            "CLIENT_RANDOM aabbcc ddeeff\n"
            "SERVER_TRAFFIC_SECRET_0 aabbcc 001122\n"
            "kaputte zeile\n")
    kl = parse_keylog(text)
    assert kl[("CLIENT_RANDOM", "aabbcc")] == bytes.fromhex("ddeeff")
    assert kl[("SERVER_TRAFFIC_SECRET_0", "aabbcc")] == bytes.fromhex("001122")
    assert len(kl) == 2


# --- HKDF (gegen cryptography geprüft) ------------------------------------- #
def test_hkdf_expand_matches_cryptography():
    prk = bytes(range(32))
    info = b"netfett-info"
    for length in (16, 32, 48, 40):
        mine = hkdf_expand(prk, info, length, "sha256")
        ref = HKDFExpand(algorithm=hashes.SHA256(), length=length,
                         info=info).derive(prk)
        assert mine == ref


def test_hkdf_expand_label_structure():
    # Länge + "tls13 key" als Label korrekt verpackt → über Referenz prüfbar.
    secret = bytes(range(32))
    out = hkdf_expand_label(secret, b"key", b"", 16, "sha256")
    full = b"tls13 key"
    info = struct.pack("!H", 16) + bytes([len(full)]) + full + bytes([0])
    ref = HKDFExpand(algorithm=hashes.SHA256(), length=16, info=info).derive(secret)
    assert out == ref


# --- TLS 1.3 Record-Roundtrip --------------------------------------------- #
def test_tls13_record_roundtrip():
    secret = bytes(range(1, 33))
    key, iv = tls13_key_iv(secret, "sha256", 16, 12)
    plaintext = b"GET / HTTP/2\r\n\r\n"
    inner = plaintext + bytes([23])               # innerer Inhaltstyp 23 (App-Data)
    seq = 3
    header = bytes([0x17, 0x03, 0x03]) + struct.pack("!H", len(inner) + 16)
    nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
    ct = AESGCM(key).encrypt(nonce, inner, header)
    res = decrypt_tls13_record("AES-GCM", key, iv, seq, ct, header)
    assert res == (23, plaintext)


def test_tls13_record_wrong_seq_fails():
    secret = bytes(range(1, 33))
    key, iv = tls13_key_iv(secret, "sha256", 16, 12)
    inner = b"data" + bytes([23])
    header = bytes([0x17, 0x03, 0x03]) + struct.pack("!H", len(inner) + 16)
    nonce = bytes(a ^ b for a, b in zip(iv, (0).to_bytes(12, "big")))
    ct = AESGCM(key).encrypt(nonce, inner, header)
    assert decrypt_tls13_record("AES-GCM", key, iv, 1, ct, header) is None


# --- TLS 1.2 GCM Record-Roundtrip ----------------------------------------- #
def test_tls12_gcm_record_roundtrip():
    key = bytes(range(16))
    fixed_iv = bytes(range(4))
    seq = 5
    ctype, ver = 0x17, 0x0303
    plaintext = b"POST /login"
    explicit = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    nonce = fixed_iv + explicit
    aad = struct.pack("!QBHH", seq, ctype, ver, len(plaintext))
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    payload = explicit + ct
    out = decrypt_tls12_record("AES-GCM", key, fixed_iv, seq, ctype, ver, payload)
    assert out == plaintext


# --- Schlüssel-Block --------------------------------------------------------#
def test_tls12_key_block_lengths_and_deterministic():
    ms = bytes(range(48))
    cr = bytes(range(32))
    sr = bytes(range(32, 64))
    kb1 = tls12_key_block(ms, cr, sr, 16, 12, "sha256")
    kb2 = tls12_key_block(ms, cr, sr, 16, 12, "sha256")
    assert kb1 == kb2
    assert len(kb1["client_key"]) == 16 and len(kb1["client_iv"]) == 4


# --- End-to-End: synthetische TLS-1.3-Verbindung entschlüsseln ------------- #
def test_decrypt_conversation_tls13_end_to_end():
    import socket
    from netfett.core.dissect import dissect
    from netfett.core.tlssession import decrypt_conversation

    cr = bytes(range(0, 32))
    sr = bytes(range(100, 132))
    c_hs = bytes(range(1, 33)); s_hs = bytes(range(2, 34))
    c_ap = bytes(range(3, 35)); s_ap = bytes(range(4, 36))

    def enc(secret, seq, inner):
        key, iv = tls13_key_iv(secret, "sha256", 16, 12)
        hdr = bytes([0x17, 0x03, 0x03]) + struct.pack("!H", len(inner) + 16)
        nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
        return hdr + AESGCM(key).encrypt(nonce, inner, hdr)

    # ClientHello (Klartext) + Client-Finished (hs) + Client-App-Data
    chp = b"\x01\x00\x00\x22\x03\x03" + cr
    ch = b"\x16\x03\x01" + struct.pack("!H", len(chp)) + chp
    cfin = enc(c_hs, 0, b"\x14\x00\x00\x04\xaa\xbb\xcc\xdd" + bytes([22]))
    cdata = enc(c_ap, 0, b"GET / secret" + bytes([23]))
    client_stream = ch + cfin + cdata

    # ServerHello (Klartext, supported_versions=TLS1.3, Cipher 0x1301) + Fin + Data
    ext = struct.pack("!HH", 0x002B, 2) + struct.pack("!H", 0x0304)
    body = (b"\x03\x03" + sr + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
            + struct.pack("!H", len(ext)) + ext)
    shp = b"\x02" + struct.pack("!I", len(body))[1:] + body
    sh = b"\x16\x03\x03" + struct.pack("!H", len(shp)) + shp
    sfin = enc(s_hs, 0, b"\x14\x00\x00\x04\x11\x22\x33\x44" + bytes([22]))
    sdata = enc(s_ap, 0, b"HTTP/1.1 200 OK" + bytes([23]))
    server_stream = sh + sfin + sdata

    keylog = {
        ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", cr.hex()): c_hs,
        ("SERVER_HANDSHAKE_TRAFFIC_SECRET", cr.hex()): s_hs,
        ("CLIENT_TRAFFIC_SECRET_0", cr.hex()): c_ap,
        ("SERVER_TRAFFIC_SECRET_0", cr.hex()): s_ap,
    }

    def mk(n, src, dst, sp, dp, seq, payload, ts):
        ip = (struct.pack("!BBHHHBBH", 0x45, 0, 40 + len(payload), 1, 0x4000,
                          64, 6, 0) + socket.inet_aton(src) + socket.inet_aton(dst))
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, 0, 0x50, 0x18, 64240, 0, 0)
        return dissect(ip + tcp + payload, ts, n, {"192.168.0.10"})

    pkts, n, ts = [], 1, 1.0
    cseq, sseq = 1000, 5000
    for rec in (ch, cfin, cdata):
        pkts.append(mk(n, "192.168.0.10", "1.1.1.1", 50000, 443, cseq, rec, ts))
        cseq += len(rec); n += 1; ts += 0.01
    for rec in (sh, sfin, sdata):
        pkts.append(mk(n, "1.1.1.1", "192.168.0.10", 443, 50000, sseq, rec, ts))
        sseq += len(rec); n += 1; ts += 0.01

    res = decrypt_conversation(pkts, "192.168.0.10", 50000, "1.1.1.1", 443, keylog)
    assert res.ok, res.info
    assert res.client_text == b"GET / secret"
    assert res.server_text == b"HTTP/1.1 200 OK"
