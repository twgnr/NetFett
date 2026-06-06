"""TLS-Record-Entschlüsselung (AEAD) für TLS 1.2 (GCM/ChaCha) und TLS 1.3.

Nutzt die ``cryptography``-Bibliothek; ist sie nicht vorhanden, sind die
Funktionen No-ops (liefern ``None``). Die Schlüssel/IV kommen aus
:mod:`netfett.core.tlskeys`.
"""
from __future__ import annotations

import struct

try:
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESGCM, ChaCha20Poly1305,
    )
    HAVE_CRYPTO = True
except ImportError:                                # pragma: no cover
    HAVE_CRYPTO = False


def available() -> bool:
    return HAVE_CRYPTO


def _aead(alg: str, key: bytes):
    if alg == "AES-GCM":
        return AESGCM(key)
    if alg == "CHACHA20":
        return ChaCha20Poly1305(key)
    raise ValueError(f"Unbekanntes AEAD-Verfahren: {alg}")


def _xor_iv(iv: bytes, seq: int) -> bytes:
    seq_bytes = seq.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, seq_bytes))


def decrypt_tls13_record(alg: str, key: bytes, iv: bytes, seq: int,
                         ciphertext: bytes,
                         record_header: bytes) -> tuple[int, bytes] | None:
    """Entschlüsselt einen TLS-1.3-Record. Liefert (Inhaltstyp, Klartext).

    Nonce = IV XOR Sequenznummer; AAD = 5-Byte-Record-Kopf. Der echte
    Inhaltstyp ist das letzte Nicht-Null-Byte des Klartexts (Padding entfernen).
    """
    if not HAVE_CRYPTO:
        return None
    try:
        plain = _aead(alg, key).decrypt(_xor_iv(iv, seq), ciphertext,
                                        record_header)
    except Exception:
        return None
    i = len(plain) - 1
    while i >= 0 and plain[i] == 0:
        i -= 1
    if i < 0:
        return None
    return plain[i], plain[:i]


def decrypt_tls12_record(alg: str, key: bytes, fixed_iv: bytes, seq: int,
                         content_type: int, version: int,
                         payload: bytes) -> bytes | None:
    """Entschlüsselt einen TLS-1.2-AEAD-Record (GCM: 8-Byte-Explicit-Nonce).

    ``payload`` ist die Record-Nutzlast (ohne 5-Byte-Kopf). Für ChaCha20-
    Poly1305 (RFC 7905) ist die Nonce IV XOR seq und es gibt keinen expliziten
    Nonce-Teil."""
    if not HAVE_CRYPTO:
        return None
    try:
        if alg == "AES-GCM":
            explicit = payload[:8]
            ct = payload[8:]
            nonce = fixed_iv + explicit
        else:                                       # ChaCha20-Poly1305 (RFC 7905)
            ct = payload
            nonce = _xor_iv(fixed_iv, seq)
        plain_len = len(ct) - 16
        if plain_len < 0:
            return None
        aad = struct.pack("!QBHH", seq, content_type, version, plain_len)
        return _aead(alg, key).decrypt(nonce, ct, aad)
    except Exception:
        return None
