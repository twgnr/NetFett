"""Entschlüsselung einer ganzen TLS-Verbindung mithilfe einer SSLKEYLOGFILE.

Setzt die TCP-Ströme einer Verbindung zusammen, erkennt Client-/Server-Random,
Cipher-Suite und Version aus den Hello-Nachrichten und entschlüsselt die
Application-Data-Records. Unterstützt TLS 1.3 sowie TLS 1.2 (AEAD: GCM/ChaCha20).

End-to-End nur möglich, wenn die passenden Secrets in der Keylog stehen; bei
fehlenden/falschen Schlüsseln bleiben Records verschlüsselt (werden übersprungen).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..i18n import tr
from .analyze import follow_stream
from .models import Packet
from .tlsdecrypt import (
    available, decrypt_tls12_record, decrypt_tls13_record,
)
from .tlskeys import CIPHERS, tls12_key_block, tls13_key_iv


@dataclass(slots=True)
class DecryptResult:
    ok: bool
    info: str
    client_text: bytes = b""        # Client→Server (entschlüsselt)
    server_text: bytes = b""        # Server→Client (entschlüsselt)
    chunks: list = field(default_factory=list)   # [(from_client, bytes)]


def parse_records(data: bytes):
    """Zerlegt einen Byte-Strom in TLS-Records: (Typ, Version, Kopf, Nutzlast)."""
    out = []
    pos = 0
    while pos + 5 <= len(data):
        ctype, ver, length = struct.unpack("!BHH", data[pos:pos + 5])
        if pos + 5 + length > len(data):
            break
        out.append((ctype, ver, data[pos:pos + 5], data[pos + 5:pos + 5 + length]))
        pos += 5 + length
    return out


def _client_random(stream: bytes) -> bytes:
    recs = parse_records(stream)
    for ctype, _ver, _hdr, payload in recs:
        if ctype == 0x16 and len(payload) >= 38 and payload[0] == 0x01:
            return payload[6:38]
    return b""


def _server_hello(stream: bytes):
    """(server_random, cipher_id, is_tls13) aus dem ServerHello oder None."""
    for ctype, _ver, _hdr, payload in parse_records(stream):
        if ctype != 0x16 or len(payload) < 44 or payload[0] != 0x02:
            continue
        server_random = payload[6:38]
        pos = 38
        sid_len = payload[pos]
        pos += 1 + sid_len
        if pos + 2 > len(payload):
            return None
        cipher_id = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + 1                              # Cipher + Compression
        is_tls13 = False
        if pos + 2 <= len(payload):
            ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            end = min(len(payload), pos + ext_total)
            while pos + 4 <= end:
                etype, elen = struct.unpack("!HH", payload[pos:pos + 4])
                pos += 4
                if etype == 0x002B and elen >= 2:    # supported_versions
                    if struct.unpack("!H", payload[pos:pos + 2])[0] == 0x0304:
                        is_tls13 = True
                pos += elen
        return server_random, cipher_id, is_tls13
    return None


def _has_finished(plain: bytes) -> bool:
    return len(plain) >= 1 and plain[0] == 20      # Handshake-Typ 20 = Finished


def _decrypt_dir_tls13(records, alg, hs_key, hs_iv, ap_key, ap_iv) -> bytes:
    out = bytearray()
    hs_seq = ap_seq = 0
    phase = "hs"
    for ctype, _ver, hdr, payload in records:
        if ctype != 0x17:                          # Klartext-Records überspringen
            continue
        if phase == "hs":
            res = decrypt_tls13_record(alg, hs_key, hs_iv, hs_seq, payload, hdr)
            if res is None:                        # evtl. schon App-Phase
                res = decrypt_tls13_record(alg, ap_key, ap_iv, ap_seq, payload, hdr)
                if res is None:
                    continue
                phase = "app"
                inner, pt = res
                ap_seq += 1
                if inner == 23:
                    out += pt
                continue
            inner, pt = res
            hs_seq += 1
            if inner == 23:
                out += pt
            if inner == 22 and _has_finished(pt):
                phase = "app"
        else:
            res = decrypt_tls13_record(alg, ap_key, ap_iv, ap_seq, payload, hdr)
            if res is None:
                continue
            inner, pt = res
            ap_seq += 1
            if inner == 23:
                out += pt
    return bytes(out)


def _decrypt_dir_tls12(records, alg, key, fixed_iv) -> bytes:
    out = bytearray()
    seq = 0
    encrypting = False
    for ctype, ver, _hdr, payload in records:
        if ctype == 0x14:                          # ChangeCipherSpec → ab jetzt verschlüsselt
            encrypting = True
            continue
        if not encrypting:
            continue
        if ctype == 0x17:
            pt = decrypt_tls12_record(alg, key, fixed_iv, seq, ctype, ver, payload)
            if pt:
                out += pt
        seq += 1                                   # jeder verschlüsselte Record zählt
    return bytes(out)


def decrypt_conversation(packets: list[Packet], ip_a: str, port_a,
                         ip_b: str, port_b, keylog: dict) -> DecryptResult:
    """Versucht, die TLS-Verbindung mit den Secrets aus ``keylog`` zu entschlüsseln."""
    if not available():
        return DecryptResult(False, tr("cryptography-Bibliothek nicht verfügbar."))
    if not keylog:
        return DecryptResult(False, tr("Keine TLS-Schlüssel geladen (SSLKEYLOGFILE)."))

    stream = follow_stream(packets, ip_a, port_a, ip_b, port_b)
    c_stream, s_stream = stream.client_bytes, stream.server_bytes
    if not c_stream or not s_stream:
        return DecryptResult(
            False, tr("Kein vollständiger TLS-Strom rekonstruierbar."))

    cr = _client_random(c_stream)
    sh = _server_hello(s_stream)
    if not cr or sh is None:
        return DecryptResult(False, tr("ClientHello/ServerHello nicht gefunden."))
    server_random, cipher_id, is_tls13 = sh
    if cipher_id not in CIPHERS:
        return DecryptResult(False, tr(
            "Cipher-Suite 0x{cipher_id:04x} nicht unterstützt.").format(
                cipher_id=cipher_id))
    alg, hash_name, key_len, iv_len = CIPHERS[cipher_id]
    cr_hex = cr.hex()

    c_recs = parse_records(c_stream)
    s_recs = parse_records(s_stream)

    if is_tls13:
        need = ["CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"]
        secrets = {n: keylog.get((n, cr_hex)) for n in need}
        if any(v is None for v in secrets.values()):
            return DecryptResult(
                False, tr("Passende TLS-1.3-Secrets fehlen in der Keylog."))
        c_hs = tls13_key_iv(secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"],
                            hash_name, key_len, iv_len)
        s_hs = tls13_key_iv(secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"],
                            hash_name, key_len, iv_len)
        c_ap = tls13_key_iv(secrets["CLIENT_TRAFFIC_SECRET_0"],
                            hash_name, key_len, iv_len)
        s_ap = tls13_key_iv(secrets["SERVER_TRAFFIC_SECRET_0"],
                            hash_name, key_len, iv_len)
        c_text = _decrypt_dir_tls13(c_recs, alg, *c_hs, *c_ap)
        s_text = _decrypt_dir_tls13(s_recs, alg, *s_hs, *s_ap)
    else:                                          # TLS 1.2
        ms = keylog.get(("CLIENT_RANDOM", cr_hex))
        if ms is None:
            return DecryptResult(
                False, tr("Master-Secret (CLIENT_RANDOM) fehlt in der Keylog."))
        kb = tls12_key_block(ms, cr, server_random, key_len, iv_len, hash_name)
        c_text = _decrypt_dir_tls12(c_recs, alg, kb["client_key"], kb["client_iv"])
        s_text = _decrypt_dir_tls12(s_recs, alg, kb["server_key"], kb["server_iv"])

    if not c_text and not s_text:
        return DecryptResult(False, tr("Entschlüsselung lieferte keine Daten "
                                       "(falsche/fehlende Schlüssel?)."))
    version = "TLS 1.3" if is_tls13 else "TLS 1.2"
    return DecryptResult(
        True, tr("{version}, Cipher 0x{cipher_id:04x} – entschlüsselt.").format(
            version=version, cipher_id=cipher_id),
        client_text=c_text, server_text=s_text,
        chunks=[(True, c_text), (False, s_text)])
