"""Tests für HPACK gegen die RFC-7541-Beispielvektoren."""
from __future__ import annotations

from netfett.core.hpack import (
    HUFFMAN, HpackDecoder, _build_huffman_tree, decode_http2_headers,
    huffman_decode,
)


def _hx(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


# --- Huffman-Tabelle: gültiger Präfixcode? --------------------------------- #
def test_huffman_table_complete_prefix_code():
    assert len(HUFFMAN) == 257                       # 256 Symbole + EOS
    # Baum bauen darf keine Konflikte erzeugen (kein Code ist Präfix eines anderen).
    tree = _build_huffman_tree()
    assert tree is not None
    # Stichprobe: bekannte Buchstaben-Codes dekodieren.
    # 'www.example.com' (RFC C.4.1): f1e3 c2e5 f23a 6ba0 ab90 f4ff
    assert huffman_decode(_hx("f1e3 c2e5 f23a 6ba0 ab90 f4ff")) == "www.example.com"


# --- RFC 7541 C.3.1 (Request ohne Huffman) --------------------------------- #
def test_rfc_c31_request_plain():
    block = _hx("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d")
    h = dict(HpackDecoder().decode(block))
    assert h[":method"] == "GET" and h[":scheme"] == "http"
    assert h[":path"] == "/" and h[":authority"] == "www.example.com"


# --- RFC 7541 C.4.1 (Request mit Huffman) ---------------------------------- #
def test_rfc_c41_request_huffman():
    block = _hx("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff")
    h = dict(HpackDecoder().decode(block))
    assert h[":authority"] == "www.example.com"


# --- RFC 7541 C.6.1 (Response mit Huffman, dynamische Tabelle) ------------- #
def test_rfc_c61_response_huffman():
    block = _hx(
        "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81"
        " 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3")
    h = dict(HpackDecoder().decode(block))
    assert h[":status"] == "302"
    assert h["cache-control"] == "private"
    assert h["location"] == "https://www.example.com"
    assert h["date"] == "Mon, 21 Oct 2013 20:13:21 GMT"


# --- Zustandsbehaftung (dynamische Tabelle über zwei Blöcke) --------------- #
def test_dynamic_table_across_requests():
    dec = HpackDecoder()
    dec.decode(_hx("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"))
    # C.3.2: zweite Anfrage referenziert die dynamische Tabelle (Index 62 → :authority)
    h = dict(dec.decode(_hx("8286 84be 5808 6e6f 2d63 6163 6865")))
    assert h[":authority"] == "www.example.com" and h["cache-control"] == "no-cache"


# --- Frame-Walker ---------------------------------------------------------- #
def test_decode_http2_headers_frame():
    block = _hx("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d")
    # HEADERS-Frame: len(3), type=1, flags=END_HEADERS(0x04), stream_id=1
    frame = len(block).to_bytes(3, "big") + bytes([1, 0x04]) + (1).to_bytes(4, "big") + block
    result = decode_http2_headers(frame)
    assert len(result) == 1
    sid, headers = result[0]
    assert sid == 1 and dict(headers)[":method"] == "GET"
