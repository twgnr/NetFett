"""Datei-/Objekt-Extraktion aus (ggf. entschlüsselten) HTTP-Strömen.

Zerlegt die rekonstruierten Client-/Server-Byteströme einer Verbindung in
HTTP/1.x-Nachrichten und gibt die übertragenen Objekte (Antwort-Körper) zurück –
mit Content-Type, Größe und – falls gzip/deflate – entpackt. Rein und testbar.
"""
from __future__ import annotations

import gzip
import zlib
from dataclasses import dataclass

from ..i18n import tr


@dataclass(slots=True)
class HttpObject:
    source: str            # zugehörige Anfrage/Statuszeile
    url: str               # angefragter Pfad (sofern bekannt)
    content_type: str
    size: int
    data: bytes


def _parse_headers(head: bytes) -> tuple[str, dict[str, str]]:
    lines = head.split(b"\r\n")
    start = lines[0].decode("latin-1", "replace")
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if b":" in ln:
            key, value = ln.split(b":", 1)
            headers[key.decode("latin-1", "replace").strip().lower()] = \
                value.decode("latin-1", "replace").strip()
    return start, headers


def _read_chunked(data: bytes, pos: int) -> tuple[bytes, int]:
    out = bytearray()
    while pos < len(data):
        nl = data.find(b"\r\n", pos)
        if nl < 0:
            break
        try:
            size = int(data[pos:nl].split(b";")[0].strip(), 16)
        except ValueError:
            break
        pos = nl + 2
        if size == 0:
            end = data.find(b"\r\n", pos)
            return bytes(out), (end + 2 if end >= 0 else len(data))
        out += data[pos:pos + size]
        pos += size + 2                              # Chunk + CRLF
    return bytes(out), pos


def _split_http(data: bytes, is_response: bool):
    """Liste von (Startzeile, Header, Body) der HTTP-Nachrichten im Strom."""
    msgs = []
    pos = 0
    while pos < len(data):
        he = data.find(b"\r\n\r\n", pos)
        if he < 0:
            break
        start, headers = _parse_headers(data[pos:he])
        if not (start.startswith("HTTP/") or " HTTP/" in start):
            break
        body_start = he + 4
        te = headers.get("transfer-encoding", "").lower()
        if "chunked" in te:
            body, newpos = _read_chunked(data, body_start)
        elif headers.get("content-length", "").isdigit():
            length = int(headers["content-length"])
            body = data[body_start:body_start + length]
            newpos = body_start + length
        elif is_response:
            body = data[body_start:]                 # keine Längenangabe → Rest
            newpos = len(data)
        else:
            body, newpos = b"", body_start
        msgs.append((start, headers, body))
        if newpos <= pos:
            break
        pos = newpos
    return msgs


def _decompress(headers: dict[str, str], body: bytes) -> bytes:
    enc = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body)
    except (OSError, zlib.error):
        pass
    return body


def http_objects(client_bytes: bytes, server_bytes: bytes) -> list[HttpObject]:
    """Extrahiert übertragene HTTP-Objekte (Antwort-Körper) aus den Strömen."""
    requests = _split_http(client_bytes, False)
    responses = _split_http(server_bytes, True)
    req_lines = [r[0] for r in requests]
    objs: list[HttpObject] = []
    for i, (start, headers, body) in enumerate(responses):
        if not body:
            continue
        data = _decompress(headers, body)
        if not data:
            continue
        ct = headers.get("content-type", "application/octet-stream").split(";")[0]
        req = req_lines[i] if i < len(req_lines) else start
        url = req.split(" ")[1] if len(req.split(" ")) >= 2 else ""
        objs.append(HttpObject(req, url, ct, len(data), data))
    return objs


def suggest_filename(obj: HttpObject) -> str:
    """Schlägt einen Dateinamen aus URL bzw. Content-Type vor."""
    name = obj.url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    if name and "." in name:
        return name
    ext = {"text/html": "html", "application/json": "json", "image/png": "png",
           "image/jpeg": "jpg", "image/gif": "gif", "text/css": "css",
           "application/javascript": "js", "text/plain": "txt"}.get(
        obj.content_type, "bin")
    return f"{name or tr('objekt')}.{ext}"
