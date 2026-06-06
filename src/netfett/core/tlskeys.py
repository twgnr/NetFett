"""TLS-Schlüsselmaterial: SSLKEYLOGFILE einlesen und Sitzungsschlüssel ableiten.

Reine Standardbibliothek (``hmac``/``hashlib``). Die eigentliche Record-
Entschlüsselung (AEAD) liegt in :mod:`netfett.core.tlsdecrypt` und nutzt die
``cryptography``-Bibliothek.

Ohne den Server-Privatkey ist Entschlüsselung nur möglich, wenn der Client die
Sitzungs-Secrets in eine ``SSLKEYLOGFILE`` geschrieben hat (Browser via
Umgebungsvariable ``SSLKEYLOGFILE``).
"""
from __future__ import annotations

import hashlib
import hmac
import struct

# Cipher-Suite → (AEAD-Verfahren, Hash, Schlüssel-Länge, IV-Länge).
CIPHERS: dict[int, tuple[str, str, int, int]] = {
    0x1301: ("AES-GCM", "sha256", 16, 12),     # TLS_AES_128_GCM_SHA256
    0x1302: ("AES-GCM", "sha384", 32, 12),     # TLS_AES_256_GCM_SHA384
    0x1303: ("CHACHA20", "sha256", 32, 12),    # TLS_CHACHA20_POLY1305_SHA256
    0xC02B: ("AES-GCM", "sha256", 16, 12),     # ECDHE_ECDSA_AES128_GCM_SHA256
    0xC02F: ("AES-GCM", "sha256", 16, 12),     # ECDHE_RSA_AES128_GCM_SHA256
    0xC02C: ("AES-GCM", "sha384", 32, 12),     # ECDHE_ECDSA_AES256_GCM_SHA384
    0xC030: ("AES-GCM", "sha384", 32, 12),     # ECDHE_RSA_AES256_GCM_SHA384
    0xCCA8: ("CHACHA20", "sha256", 32, 12),    # ECDHE_RSA_CHACHA20_POLY1305
    0xCCA9: ("CHACHA20", "sha256", 32, 12),    # ECDHE_ECDSA_CHACHA20_POLY1305
}


def parse_keylog(text: str) -> dict[tuple[str, str], bytes]:
    """Liest eine SSLKEYLOGFILE → ``{(Label, client_random_hex): Secret-Bytes}``.

    Zeilenformat: ``LABEL <client_random_hex> <secret_hex>`` (``#`` = Kommentar)."""
    table: dict[tuple[str, str], bytes] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        label, client_random, secret = parts
        try:
            table[(label, client_random.lower())] = bytes.fromhex(secret)
        except ValueError:
            continue
    return table


# --- HKDF (RFC 5869) und HKDF-Expand-Label (RFC 8446) ---------------------- #
def hkdf_expand(prk: bytes, info: bytes, length: int,
                hash_name: str = "sha256") -> bytes:
    hash_len = hashlib.new(hash_name).digest_size
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_name).digest()
        okm += t
    return okm[:length]


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes,
                      length: int, hash_name: str = "sha256") -> bytes:
    full_label = b"tls13 " + label
    hkdf_label = (struct.pack("!H", length) + bytes([len(full_label)])
                  + full_label + bytes([len(context)]) + context)
    return hkdf_expand(secret, hkdf_label, length, hash_name)


def tls13_key_iv(secret: bytes, hash_name: str, key_len: int,
                 iv_len: int) -> tuple[bytes, bytes]:
    """Schlüssel und IV aus einem TLS-1.3-Traffic-Secret ableiten."""
    key = hkdf_expand_label(secret, b"key", b"", key_len, hash_name)
    iv = hkdf_expand_label(secret, b"iv", b"", iv_len, hash_name)
    return key, iv


# --- TLS-1.2-PRF (RFC 5246) ------------------------------------------------ #
def _p_hash(secret: bytes, seed: bytes, length: int, hash_name: str) -> bytes:
    out = b""
    a = seed
    while len(out) < length:
        a = hmac.new(secret, a, hash_name).digest()
        out += hmac.new(secret, a + seed, hash_name).digest()
    return out[:length]


def tls12_prf(secret: bytes, label: bytes, seed: bytes, length: int,
              hash_name: str = "sha256") -> bytes:
    return _p_hash(secret, label + seed, length, hash_name)


def tls12_key_block(master_secret: bytes, client_random: bytes,
                    server_random: bytes, key_len: int, iv_len: int,
                    hash_name: str) -> dict[str, bytes]:
    """Leitet die AEAD-Schreibschlüssel/IVs (GCM/ChaCha) für TLS 1.2 ab.

    Für AEAD-Suiten gibt es keine MAC-Schlüssel; der „feste" IV-Teil ist 4 Byte
    (GCM) bzw. 12 Byte (ChaCha20-Poly1305, RFC 7905)."""
    fixed_iv = 4 if iv_len == 12 else iv_len      # GCM: 4-Byte-Salt
    total = 2 * key_len + 2 * fixed_iv
    block = tls12_prf(master_secret, b"key expansion",
                      server_random + client_random, total, hash_name)
    pos = 0
    cwk = block[pos:pos + key_len]; pos += key_len
    swk = block[pos:pos + key_len]; pos += key_len
    civ = block[pos:pos + fixed_iv]; pos += fixed_iv
    siv = block[pos:pos + fixed_iv]
    return {"client_key": cwk, "server_key": swk,
            "client_iv": civ, "server_iv": siv}
