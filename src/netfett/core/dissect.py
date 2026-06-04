"""Paketzerlegung (Dissector) für IPv4 und die wichtigsten Folgeprotokolle.

Der Windows-Raw-Socket (``SIO_RCVALL``) liefert Pakete **ab dem IPv4-Kopf** –
es gibt also keine Ethernet-Schicht. Alle Funktionen hier sind rein (keine I/O)
und damit vollständig per Unit-Test prüfbar.
"""
from __future__ import annotations

import socket
import struct

from . import protocols as P
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
    if version != 4:
        # Raw-Socket ist IPv4-only; alles andere nur grob anzeigen.
        pkt.protocol = f"IPv{version}"
        pkt.info = f"Nicht-IPv4-Paket (Version {version})"
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
            ("Ziel", dst),
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
        pkt.layers.append(Layer("Transport Layer Security",
                                summary=rectype, start=offset, length=len(payload)))
        return f"TLS {rectype} ({sport} → {dport})"

    # HTTP: Anfrage-/Antwortzeile im Klartext
    if app in ("HTTP", "HTTP-ALT", "HTTP-PROXY") and payload[:8].isascii():
        line = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:120]
        if line:
            pkt.protocol = "HTTP"
            pkt.layers.append(Layer("Hypertext Transfer Protocol",
                                    summary=line, start=offset, length=len(payload)))
            return f"HTTP {line}"

    if app and payload:
        pkt.protocol = app
        return f"{app} {sport} → {dport} Len={len(payload)}"
    return ""


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
