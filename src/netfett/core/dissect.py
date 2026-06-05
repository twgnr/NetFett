"""Paketzerlegung (Dissector) für IPv4 und die wichtigsten Folgeprotokolle.

Der Windows-Raw-Socket (``SIO_RCVALL``) liefert Pakete **ab dem IPv4-Kopf** –
es gibt also keine Ethernet-Schicht. Alle Funktionen hier sind rein (keine I/O)
und damit vollständig per Unit-Test prüfbar.
"""
from __future__ import annotations

import socket
import struct

from . import protocols as P
from .ipinfo import classify
from .models import DIR_IN, DIR_OUT, DIR_UNKNOWN, Layer, Packet

# TCP-Flag-Bits (Byte 13 des TCP-Kopfs).
_TCP_FLAGS = [
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
]


def _ip_str(raw4: bytes) -> str:
    return socket.inet_ntoa(raw4)


def _direction(src: str, dst: str, local_ips: set[str]) -> str:
    if src in local_ips:
        return DIR_OUT
    if dst in local_ips:
        return DIR_IN
    return DIR_UNKNOWN


def dissect(raw: bytes, ts: float, number: int,
            local_ips: set[str] | None = None) -> Packet:
    """Zerlegt ein Rohpaket (ab IPv4-Kopf) in ein :class:`Packet`."""
    local_ips = local_ips or set()
    pkt = Packet(number=number, ts=ts, raw=raw, direction=DIR_UNKNOWN,
                 length=len(raw))
    if len(raw) < 20:
        pkt.protocol = "?"
        pkt.info = f"Verkürztes Paket ({len(raw)} Bytes)"
        pkt.layers.append(Layer("Daten", f"{len(raw)} Bytes", length=len(raw)))
        return pkt

    version = raw[0] >> 4
    if version == 6:
        _dissect_ipv6(raw, pkt, local_ips)
        return pkt
    if version != 4:
        pkt.protocol = f"IPv{version}"
        pkt.info = f"Unbekannte IP-Version ({version})"
        pkt.layers.append(Layer(f"IPv{version}", length=len(raw)))
        return pkt

    _dissect_ipv4(raw, pkt, local_ips)
    return pkt


def _dissect_ipv4(raw: bytes, pkt: Packet, local_ips: set[str]) -> None:
    ihl = (raw[0] & 0x0F) * 4
    ihl = max(20, min(ihl, len(raw)))
    (b0, tos, total_len, ident, flags_frag, ttl, proto, checksum) = struct.unpack(
        "!BBHHHBBH", raw[:12])
    src = _ip_str(raw[12:16])
    dst = _ip_str(raw[16:20])
    flags = flags_frag >> 13
    frag_off = flags_frag & 0x1FFF

    pkt.src, pkt.dst = src, dst
    pkt.direction = _direction(src, dst, local_ips)
    pname = P.proto_name(proto)
    pkt.protocol = pname
    pkt.l4 = pname

    flag_names = []
    if flags & 0x1:
        flag_names.append("MF")
    if flags & 0x2:
        flag_names.append("DF")
    layer = Layer(
        name="Internet Protocol Version 4",
        summary=f"{src} → {dst}",
        start=0, length=ihl,
        fields=[
            ("Version", "4"),
            ("Header-Länge", f"{ihl} Bytes"),
            ("DSCP/ECN (TOS)", f"0x{tos:02x}"),
            ("Gesamtlänge", str(total_len)),
            ("Identification", f"0x{ident:04x} ({ident})"),
            ("Flags", f"0x{flags:x} {' '.join(flag_names)}".strip()),
            ("Fragment-Offset", str(frag_off)),
            ("TTL", str(ttl)),
            ("Protokoll", f"{pname} ({proto})"),
            ("Header-Prüfsumme", f"0x{checksum:04x}"),
            ("Quelle", src),
            ("Quelle – Netz", classify(src)),
            ("Ziel", dst),
            ("Ziel – Netz", classify(dst)),
        ],
    )
    pkt.layers.append(layer)

    payload = raw[ihl:]
    if frag_off != 0:
        pkt.protocol = "IPv4-Fragment"
        pkt.info = f"Fragment offset={frag_off}"
        return

    if proto == 6:
        _dissect_tcp(payload, ihl, pkt)
    elif proto == 17:
        _dissect_udp(payload, ihl, pkt)
    elif proto == 1:
        _dissect_icmp(payload, ihl, pkt)
    else:
        pkt.info = f"{pname} {src} → {dst}"
        if payload:
            pkt.layers.append(Layer("Daten", f"{len(payload)} Bytes",
                                    start=ihl, length=len(payload)))


# IPv6-Extension-Header, die wir bis zur Oberschicht überspringen.
_V6_EXT = {0, 43, 60}          # Hop-by-Hop, Routing, Destination Options
_V6_FRAGMENT = 44
_ICMPV6_TYPES = {
    1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
    4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
    133: "Router Solicitation", 134: "Router Advertisement",
    135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
}


def _ip6_str(raw16: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw16)


def _dissect_ipv6(raw: bytes, pkt: Packet, local_ips: set[str]) -> None:
    if len(raw) < 40:
        pkt.protocol = "IPv6"
        pkt.info = f"Verkürztes IPv6-Paket ({len(raw)} Bytes)"
        pkt.layers.append(Layer("IPv6", length=len(raw)))
        return
    vtf, payload_len, nexthdr, hop = struct.unpack("!IHBB", raw[:8])
    traffic_class = (vtf >> 20) & 0xFF
    flow_label = vtf & 0xFFFFF
    src = _ip6_str(raw[8:24])
    dst = _ip6_str(raw[24:40])

    pkt.src, pkt.dst = src, dst
    pkt.direction = _direction(src, dst, local_ips)
    pkt.protocol = P.proto_name(nexthdr)
    pkt.l4 = pkt.protocol

    pkt.layers.append(Layer(
        name="Internet Protocol Version 6",
        summary=f"{src} → {dst}",
        start=0, length=40,
        fields=[
            ("Version", "6"),
            ("Traffic Class", f"0x{traffic_class:02x}"),
            ("Flow Label", f"0x{flow_label:05x}"),
            ("Payload-Länge", str(payload_len)),
            ("Next Header", f"{P.proto_name(nexthdr)} ({nexthdr})"),
            ("Hop Limit", str(hop)),
            ("Quelle", src),
            ("Quelle – Netz", classify(src)),
            ("Ziel", dst),
            ("Ziel – Netz", classify(dst)),
        ],
    ))

    nexthdr, payload, offset = _skip_v6_ext(nexthdr, raw[40:], 40)
    pkt.protocol = P.proto_name(nexthdr)
    pkt.l4 = pkt.protocol

    if nexthdr == 6:
        _dissect_tcp(payload, offset, pkt)
    elif nexthdr == 17:
        _dissect_udp(payload, offset, pkt)
    elif nexthdr == 58:
        _dissect_icmpv6(payload, offset, pkt)
    else:
        pkt.info = f"{P.proto_name(nexthdr)} {src} → {dst}"
        if payload:
            pkt.layers.append(Layer("Daten", f"{len(payload)} Bytes",
                                    start=offset, length=len(payload)))


def _skip_v6_ext(nexthdr: int, payload: bytes,
                 offset: int) -> tuple[int, bytes, int]:
    """Überspringt IPv6-Extension-Header bis zur Oberschicht."""
    while payload:
        if nexthdr in _V6_EXT and len(payload) >= 2:
            ext_len = (payload[1] + 1) * 8
        elif nexthdr == _V6_FRAGMENT and len(payload) >= 8:
            ext_len = 8
        else:
            break
        if ext_len > len(payload):
            break
        nexthdr = payload[0]
        payload = payload[ext_len:]
        offset += ext_len
    return nexthdr, payload, offset


def _dissect_icmpv6(data: bytes, offset: int, pkt: Packet) -> None:
    if len(data) < 4:
        pkt.info = "Verkürztes ICMPv6-Paket"
        return
    itype, code, csum = struct.unpack("!BBH", data[:4])
    pkt.l4 = "ICMPv6"
    pkt.protocol = "ICMPv6"
    tname = _ICMPV6_TYPES.get(itype, f"Typ {itype}")
    fields = [("Typ", f"{itype} ({tname})"), ("Code", str(code)),
              ("Prüfsumme", f"0x{csum:04x}")]
    info = tname
    if itype in (128, 129) and len(data) >= 8:
        ident, seq = struct.unpack("!HH", data[4:8])
        fields += [("Identifier", str(ident)), ("Sequenz", str(seq))]
        info = f"{tname} id={ident} seq={seq}"
    pkt.layers.append(Layer("Internet Control Message Protocol v6",
                            summary=tname, start=offset, length=len(data),
                            fields=fields))
    pkt.info = info


def _dissect_tcp(data: bytes, offset: int, pkt: Packet) -> None:
    if len(data) < 20:
        pkt.info = "Verkürztes TCP-Segment"
        return
    sport, dport, seq, ack = struct.unpack("!HHII", data[:12])
    off_res = data[12]
    flags_byte = data[13]
    win, csum, urg = struct.unpack("!HHH", data[14:20])
    data_off = (off_res >> 4) * 4
    data_off = max(20, min(data_off, len(data)))
    payload = data[data_off:]

    flag_list = [name for bit, name in _TCP_FLAGS if flags_byte & bit]
    pkt.l4 = "TCP"
    pkt.src_port, pkt.dst_port = sport, dport
    pkt.protocol = "TCP"

    pkt.layers.append(Layer(
        name="Transmission Control Protocol",
        summary=f"{sport} → {dport} [{', '.join(flag_list)}]",
        start=offset, length=data_off,
        fields=[
            ("Quell-Port", str(sport)),
            ("Ziel-Port", str(dport)),
            ("Sequenznummer", str(seq)),
            ("Bestätigungsnummer", str(ack)),
            ("Header-Länge", f"{data_off} Bytes"),
            ("Flags", f"0x{flags_byte:03x} ({', '.join(flag_list)})"),
            ("Window", str(win)),
            ("Prüfsumme", f"0x{csum:04x}"),
            ("Urgent-Pointer", str(urg)),
            ("Payload", f"{len(payload)} Bytes"),
        ],
    ))

    app = _app_layer(pkt, payload, offset + data_off)
    flags_str = ", ".join(flag_list) if flag_list else "—"
    base_info = (f"{sport} → {dport} [{flags_str}] "
                 f"Seq={seq} Ack={ack} Win={win} Len={len(payload)}")
    pkt.info = app or base_info


def _dissect_udp(data: bytes, offset: int, pkt: Packet) -> None:
    if len(data) < 8:
        pkt.info = "Verkürztes UDP-Datagramm"
        return
    sport, dport, length, csum = struct.unpack("!HHHH", data[:8])
    payload = data[8:]
    pkt.l4 = "UDP"
    pkt.src_port, pkt.dst_port = sport, dport
    pkt.protocol = "UDP"
    pkt.layers.append(Layer(
        name="User Datagram Protocol",
        summary=f"{sport} → {dport}",
        start=offset, length=8,
        fields=[
            ("Quell-Port", str(sport)),
            ("Ziel-Port", str(dport)),
            ("Länge", str(length)),
            ("Prüfsumme", f"0x{csum:04x}"),
            ("Payload", f"{len(payload)} Bytes"),
        ],
    ))
    app = _app_layer(pkt, payload, offset + 8)
    pkt.info = app or f"{sport} → {dport} Len={len(payload)}"


def _dissect_icmp(data: bytes, offset: int, pkt: Packet) -> None:
    if len(data) < 4:
        pkt.info = "Verkürztes ICMP-Paket"
        return
    itype, code, csum = struct.unpack("!BBH", data[:4])
    rest = data[4:]
    pkt.l4 = "ICMP"
    pkt.protocol = "ICMP"
    tname = P.ICMP_TYPES.get(itype, f"Typ {itype}")
    fields = [
        ("Typ", f"{itype} ({tname})"),
        ("Code", str(code)),
        ("Prüfsumme", f"0x{csum:04x}"),
    ]
    info = tname
    if itype in (0, 8) and len(rest) >= 4:
        ident, seq = struct.unpack("!HH", rest[:4])
        fields += [("Identifier", str(ident)), ("Sequenz", str(seq))]
        info = f"{tname} id={ident} seq={seq}"
    pkt.layers.append(Layer(
        name="Internet Control Message Protocol",
        summary=tname, start=offset, length=len(data), fields=fields))
    pkt.info = info


# --- Anwendungsschicht (leichtgewichtige Erkennung) ------------------------
def _app_layer(pkt: Packet, payload: bytes, offset: int) -> str:
    """Erkennt App-Protokoll grob (Port + Signatur) und ergänzt eine Schicht.

    Gibt eine Info-Zeile zurück (oder leer)."""
    sport = pkt.src_port or 0
    dport = pkt.dst_port or 0
    app = P.app_for_ports(sport, dport)

    # DNS / mDNS
    if dport == 53 or sport == 53 or dport == 5353 or sport == 5353:
        info = _dissect_dns(payload, offset, pkt)
        if info:
            pkt.protocol = "DNS" if dport != 5353 and sport != 5353 else "mDNS"
            return info

    # TLS: Record-Typ 0x16 (Handshake) … 0x17 (App-Data), Version 0x03xx
    if len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
        rectype = {0x14: "Change Cipher Spec", 0x15: "Alert",
                   0x16: "Handshake", 0x17: "Application Data"}[payload[0]]
        pkt.protocol = "TLS"
        fields: list[tuple[str, str]] = []
        summary = rectype
        info_line = f"TLS {rectype} ({sport} → {dport})"
        if payload[0] == 0x16:                       # Handshake genauer auswerten
            hs = tls_info(payload)
            if hs["type"]:
                summary = hs["type"]
                if hs["version"]:
                    fields.append(("Version", hs["version"]))
                fields.append(("Handshake-Typ", hs["type"]))
                if hs["cipher"]:
                    fields.append(("Cipher Suite", hs["cipher"]))
                if hs["sni"]:
                    pkt.domain = hs["sni"]
                    fields.append(("Server-Name (SNI)", hs["sni"]))
                    summary = f"{hs['type']} – {hs['sni']}"
                detail = ", ".join(x for x in (hs["version"], hs["cipher"]) if x)
                info_line = (f"TLS {hs['type']}"
                             + (f" SNI={hs['sni']}" if hs["sni"] else "")
                             + (f" [{detail}]" if detail else ""))
        pkt.layers.append(Layer("Transport Layer Security", summary=summary,
                                start=offset, length=len(payload), fields=fields))
        return info_line

    # HTTP: Anfrage-/Antwortzeile + Header im Klartext
    if app in ("HTTP", "HTTP-ALT", "HTTP-PROXY") and payload[:8].isascii():
        first, fields = _http_fields(payload)
        if first:
            pkt.protocol = "HTTP"
            host = next((v for k, v in fields if k.lower() == "host"), "")
            if host:
                pkt.domain = host
            pkt.layers.append(Layer("Hypertext Transfer Protocol",
                                    summary=first[:120], start=offset,
                                    length=len(payload), fields=fields))
            return f"HTTP {first[:120]}" + (f"  (Host: {host})" if host else "")

    if app and payload:
        pkt.protocol = app
        return f"{app} {sport} → {dport} Len={len(payload)}"
    return ""


def _http_fields(payload: bytes) -> tuple[str, list[tuple[str, str]]]:
    """Zerlegt eine HTTP-Anfrage/-Antwort in Startzeile + Header-Felder."""
    head = payload[:4096].split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    first = lines[0].decode("latin-1", "replace")[:200]
    if not first:
        return "", []
    fields: list[tuple[str, str]] = []
    parts = first.split(" ")
    if first.startswith("HTTP/"):                 # Antwort: HTTP/x.y CODE Grund
        fields.append(("Typ", "Antwort"))
        fields.append(("Version", parts[0]))
        if len(parts) >= 2:
            fields.append(("Status", " ".join(parts[1:])[:80]))
    elif len(parts) >= 3:                          # Anfrage: METHODE PFAD VERSION
        fields.append(("Typ", "Anfrage"))
        fields.append(("Methode", parts[0]))
        fields.append(("Pfad", parts[1][:200]))
        fields.append(("Version", parts[2]))
    for line in lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            fields.append((key.decode("latin-1", "replace").strip()[:60],
                           value.decode("latin-1", "replace").strip()[:200]))
        if len(fields) > 40:                       # gegen pathologisch lange Köpfe
            break
    return first, fields


# Häufige TLS-Cipher-Suites (Auszug) und Versionsnamen.
_TLS_CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE_ECDSA_AES128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_AES128_GCM_SHA256",
    0xC030: "ECDHE_RSA_AES256_GCM_SHA384",
    0xCCA8: "ECDHE_RSA_CHACHA20_POLY1305",
    0xCCA9: "ECDHE_ECDSA_CHACHA20_POLY1305",
}
_TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def _is_grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A          # reservierte GREASE-Werte


def tls_info(record: bytes) -> dict[str, str]:
    """Liest aus einem TLS-Handshake-Record Typ, Version, Cipher und SNI.

    Defensiv: liefert leere Strings bei Inkonsistenzen. ``record`` beginnt mit
    dem 5-Byte-TLS-Record-Kopf. Für Client-/Server-Hello implementiert."""
    out = {"type": "", "version": "", "cipher": "", "sni": ""}
    if len(record) < 6 or record[0] != 0x16:
        return out
    htype = record[5]
    out["type"] = {1: "Client Hello", 2: "Server Hello"}.get(
        htype, f"Handshake {htype}")
    if len(record) < 11:
        return out
    legacy = int.from_bytes(record[9:11], "big")
    try:
        pos = 5 + 4 + 2 + 32                    # Record+HS-Kopf, Version, Random
        sid_len = record[pos]
        pos += 1 + sid_len
        if htype == 1:                          # ClientHello
            cs_len = int.from_bytes(record[pos:pos + 2], "big")
            pos += 2 + cs_len
            comp_len = record[pos]
            pos += 1 + comp_len
        elif htype == 2:                        # ServerHello
            out["cipher"] = _TLS_CIPHERS.get(
                int.from_bytes(record[pos:pos + 2], "big"),
                f"0x{int.from_bytes(record[pos:pos + 2], 'big'):04x}")
            pos += 2 + 1                        # gewählte Cipher + Compression
        best = legacy
        if pos + 2 <= len(record):
            ext_total = int.from_bytes(record[pos:pos + 2], "big")
            pos += 2
            end = min(len(record), pos + ext_total)
            while pos + 4 <= end:
                etype = int.from_bytes(record[pos:pos + 2], "big")
                elen = int.from_bytes(record[pos + 2:pos + 4], "big")
                pos += 4
                data = record[pos:pos + elen]
                if etype == 0x0000:
                    out["sni"] = _parse_sni(data)
                elif etype == 0x002B:           # supported_versions
                    best = _parse_versions(data, htype) or best
                pos += elen
        out["version"] = _TLS_VERSIONS.get(best, f"0x{best:04x}")
    except (IndexError, ValueError):
        out["version"] = _TLS_VERSIONS.get(legacy, "")
    return out


def _tls_sni(record: bytes) -> str:
    """Nur der SNI-Server-Name (Bequemlichkeits-Wrapper um :func:`tls_info`)."""
    return tls_info(record)["sni"]


def _parse_sni(data: bytes) -> str:
    # server_name_list(2) | name_type(1=host_name? 0) | name_len(2) | name
    if len(data) >= 5 and data[2] == 0x00:
        nlen = int.from_bytes(data[3:5], "big")
        return data[5:5 + nlen].decode("latin-1", "replace")[:255]
    return ""


def _parse_versions(data: bytes, htype: int) -> int:
    if htype == 2:                              # ServerHello: gewählte Version
        return int.from_bytes(data[:2], "big") if len(data) >= 2 else 0
    if not data:                                # ClientHello: höchste angebotene
        return 0
    list_len = data[0]
    best = 0
    for i in range(1, min(1 + list_len, len(data) - 1), 2):
        ver = int.from_bytes(data[i:i + 2], "big")
        if not _is_grease(ver):
            best = max(best, ver)
    return best


def _dissect_dns(payload: bytes, offset: int, pkt: Packet) -> str:
    if len(payload) < 12:
        return ""
    try:
        ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    except struct.error:
        return ""
    is_resp = bool(flags & 0x8000)
    name, _ = _dns_name(payload, 12)
    qtype = "?"
    pos = 12
    if qd:
        _n, pos = _dns_name(payload, 12)
        if pos + 4 <= len(payload):
            qt, _qc = struct.unpack("!HH", payload[pos:pos + 4])
            qtype = _DNS_TYPES.get(qt, str(qt))
    kind = "response" if is_resp else "query"
    if name:
        pkt.domain = name
    summary = f"Standard {kind} 0x{ident:04x} {qtype} {name}".strip()
    pkt.layers.append(Layer("Domain Name System",
                            summary=summary, start=offset, length=len(payload),
                            fields=[
                                ("Transaction ID", f"0x{ident:04x}"),
                                ("Typ", kind),
                                ("Fragen", str(qd)), ("Antworten", str(an)),
                                ("Name", name or "—"), ("Query-Typ", qtype),
                            ]))
    return summary


_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


def _dns_name(buf: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """Liest einen (ggf. komprimierten) DNS-Namen. Gibt (Name, neue Pos) zurück."""
    labels: list[str] = []
    jumped = False
    end_pos = pos
    while depth < 10 and 0 <= pos < len(buf):
        length = buf[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end_pos = pos
            break
        if length & 0xC0 == 0xC0:  # Komprimierung (Pointer)
            if pos + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                end_pos = pos + 2
            jumped = True
            pos = ptr
            depth += 1
            continue
        pos += 1
        labels.append(buf[pos:pos + length].decode("latin-1", "replace"))
        pos += length
        if not jumped:
            end_pos = pos
    return ".".join(labels), end_pos
