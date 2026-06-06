"""JA3-/JA3S-Fingerprinting aus TLS-Client-/Server-Hello.

JA3 bildet einen stabilen Fingerabdruck der TLS-Implementierung des Clients aus
Version, Cipher-Suites, Extensions, Kurven und EC-Punktformaten; JA3S das
Gegenstück aus dem ServerHello. Der Standard nutzt einen MD5-Hash über einen
kommagetrennten String – hier nur als Fingerabdruck, nicht zur Absicherung.

Rein und unit-testbar; ``record`` beginnt jeweils mit dem 5-Byte-TLS-Record-Kopf.
"""
from __future__ import annotations

import hashlib


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A          # reservierte GREASE-Werte


def _u16_list(data: bytes) -> list[int]:
    return [int.from_bytes(data[i:i + 2], "big")
            for i in range(0, len(data) - 1, 2)]


def _md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def parse_client_hello(record: bytes):
    """(version, ciphers, extensions, curves, point_formats) oder ``None``."""
    if len(record) < 11 or record[0] != 0x16 or record[5] != 0x01:
        return None
    version = int.from_bytes(record[9:11], "big")
    try:
        pos = 5 + 4 + 2 + 32
        sid_len = record[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(record[pos:pos + 2], "big")
        pos += 2
        ciphers = [c for c in _u16_list(record[pos:pos + cs_len])
                   if not _is_grease(c)]
        pos += cs_len
        comp_len = record[pos]
        pos += 1 + comp_len
        exts: list[int] = []
        curves: list[int] = []
        formats: list[int] = []
        if pos + 2 <= len(record):
            ext_total = int.from_bytes(record[pos:pos + 2], "big")
            pos += 2
            end = min(len(record), pos + ext_total)
            while pos + 4 <= end:
                etype = int.from_bytes(record[pos:pos + 2], "big")
                elen = int.from_bytes(record[pos + 2:pos + 4], "big")
                pos += 4
                data = record[pos:pos + elen]
                pos += elen
                if not _is_grease(etype):
                    exts.append(etype)
                if etype == 0x000A and len(data) >= 2:      # supported_groups
                    glen = int.from_bytes(data[:2], "big")
                    curves = [c for c in _u16_list(data[2:2 + glen])
                              if not _is_grease(c)]
                elif etype == 0x000B and len(data) >= 1:    # ec_point_formats
                    flen = data[0]
                    formats = list(data[1:1 + flen])
        return version, ciphers, exts, curves, formats
    except (IndexError, ValueError):
        return None


def parse_server_hello(record: bytes):
    """(version, cipher, extensions) oder ``None``."""
    if len(record) < 11 or record[0] != 0x16 or record[5] != 0x02:
        return None
    version = int.from_bytes(record[9:11], "big")
    try:
        pos = 5 + 4 + 2 + 32
        sid_len = record[pos]
        pos += 1 + sid_len
        cipher = int.from_bytes(record[pos:pos + 2], "big")
        pos += 2 + 1                                # Cipher + Compression
        exts: list[int] = []
        if pos + 2 <= len(record):
            ext_total = int.from_bytes(record[pos:pos + 2], "big")
            pos += 2
            end = min(len(record), pos + ext_total)
            while pos + 4 <= end:
                etype = int.from_bytes(record[pos:pos + 2], "big")
                elen = int.from_bytes(record[pos + 2:pos + 4], "big")
                pos += 4 + elen
                if not _is_grease(etype):
                    exts.append(etype)
        return version, cipher, exts
    except (IndexError, ValueError):
        return None


def ja3(record: bytes):
    """(JA3-String, JA3-MD5) aus einem ClientHello oder ``None``."""
    parsed = parse_client_hello(record)
    if parsed is None:
        return None
    version, ciphers, exts, curves, formats = parsed
    text = ",".join((
        str(version),
        "-".join(map(str, ciphers)),
        "-".join(map(str, exts)),
        "-".join(map(str, curves)),
        "-".join(map(str, formats)),
    ))
    return text, _md5(text)


def ja3s(record: bytes):
    """(JA3S-String, JA3S-MD5) aus einem ServerHello oder ``None``."""
    parsed = parse_server_hello(record)
    if parsed is None:
        return None
    version, cipher, exts = parsed
    text = f"{version},{cipher},{'-'.join(map(str, exts))}"
    return text, _md5(text)
