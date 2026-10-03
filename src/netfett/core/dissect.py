"""Paketzerlegung (Dissector) für IPv4 und die wichtigsten Folgeprotokolle.

Der Windows-Raw-Socket (``SIO_RCVALL``) liefert Pakete **ab dem IPv4-Kopf** –
es gibt also keine Ethernet-Schicht. Alle Funktionen hier sind rein (keine I/O)
und damit vollständig per Unit-Test prüfbar.
"""
from __future__ import annotations

import socket
import struct

from . import certinfo
from . import protocols as P
from ..i18n import tr
from .ipinfo import classify
from .ja3 import ja3, ja3s
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
        pkt.info = tr("Verkürztes Paket ({n} Bytes)").format(n=len(raw))
        pkt.layers.append(Layer("Daten", f"{len(raw)} Bytes", length=len(raw)))
        return pkt

    version = raw[0] >> 4
    if version == 6:
        _dissect_ipv6(raw, pkt, local_ips)
        return pkt
    if version != 4:
        pkt.protocol = f"IPv{version}"
        pkt.info = tr("Unbekannte IP-Version ({version})").format(version=version)
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
            ("Quelle – Netz", tr(classify(src))),
            ("Ziel", dst),
            ("Ziel – Netz", tr(classify(dst))),
        ],
    )
    pkt.layers.append(layer)

    payload = raw[ihl:]
    if frag_off != 0:                          # Folge-Fragment (ohne L4-Kopf)
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

    if flags & 0x1:                            # MF gesetzt → erstes Fragment
        pkt.info = f"[Fragment] {pkt.info}"


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
        pkt.info = tr("Verkürztes IPv6-Paket ({n} Bytes)").format(n=len(raw))
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
            ("Quelle – Netz", tr(classify(src))),
            ("Ziel", dst),
            ("Ziel – Netz", tr(classify(dst))),
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
        pkt.info = tr("Verkürztes ICMPv6-Paket")
        return
    itype, code, csum = struct.unpack("!BBH", data[:4])
    pkt.l4 = "ICMPv6"
    pkt.protocol = "ICMPv6"
    tname = _ICMPV6_TYPES.get(itype) or tr("Typ {n}").format(n=itype)
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


def _tcp_options(opt: bytes) -> list[str]:
    """Zerlegt den TCP-Options-Bereich in lesbare Einträge."""
    out: list[str] = []
    i = 0
    while i < len(opt):
        kind = opt[i]
        if kind == 0:                                # End of Options
            break
        if kind == 1:                                # NOP
            i += 1
            continue
        if i + 1 >= len(opt):
            break
        length = opt[i + 1]
        if length < 2 or i + length > len(opt):
            break
        data = opt[i + 2:i + length]
        if kind == 2 and len(data) == 2:
            out.append(f"MSS={int.from_bytes(data, 'big')}")
        elif kind == 3 and len(data) == 1:
            out.append(f"WScale={data[0]}")
        elif kind == 4:
            out.append(tr("SACK-erlaubt"))
        elif kind == 5:
            out.append("SACK")
        elif kind == 8 and len(data) == 8:
            tsval, tsecr = struct.unpack("!II", data)
            out.append(f"TS={tsval}/{tsecr}")
        else:
            out.append(f"Opt{kind}")
        i += length
    return out


def _dissect_tcp(data: bytes, offset: int, pkt: Packet) -> None:
    if len(data) < 20:
        pkt.info = tr("Verkürztes TCP-Segment")
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

    fields = [
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
    ]
    opts = _tcp_options(data[20:data_off])
    if opts:
        fields.append(("Optionen", ", ".join(opts)))
    pkt.layers.append(Layer(
        name="Transmission Control Protocol",
        summary=f"{sport} → {dport} [{', '.join(flag_list)}]",
        start=offset, length=data_off, fields=fields))

    app = _app_layer(pkt, payload, offset + data_off)
    flags_str = ", ".join(flag_list) if flag_list else "—"
    base_info = (f"{sport} → {dport} [{flags_str}] "
                 f"Seq={seq} Ack={ack} Win={win} Len={len(payload)}")
    pkt.info = app or base_info


def _dissect_udp(data: bytes, offset: int, pkt: Packet) -> None:
    if len(data) < 8:
        pkt.info = tr("Verkürztes UDP-Datagramm")
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
        pkt.info = tr("Verkürztes ICMP-Paket")
        return
    itype, code, csum = struct.unpack("!BBH", data[:4])
    rest = data[4:]
    pkt.l4 = "ICMP"
    pkt.protocol = "ICMP"
    tname = P.ICMP_TYPES.get(itype) or tr("Typ {n}").format(n=itype)
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


# „Decode As": Port → erzwungenes Protokoll (überschreibt die Heuristik).
_DECODE_AS: dict[int, str] = {}


def set_decode_as(mapping: dict[int, str]) -> None:
    """Setzt Port→Protokoll-Overrides ("tls"/"http"/"dns") für die Zerlegung."""
    _DECODE_AS.clear()
    _DECODE_AS.update({int(p): v.lower() for p, v in mapping.items()})


def get_decode_as() -> dict[int, str]:
    return dict(_DECODE_AS)


# --- Anwendungsschicht (leichtgewichtige Erkennung) ------------------------
def _app_layer(pkt: Packet, payload: bytes, offset: int) -> str:
    """Erkennt App-Protokoll grob (Port + Signatur) und ergänzt eine Schicht.

    Gibt eine Info-Zeile zurück (oder leer)."""
    sport = pkt.src_port or 0
    dport = pkt.dst_port or 0
    app = P.app_for_ports(sport, dport)
    forced = _DECODE_AS.get(dport) or _DECODE_AS.get(sport)
    if forced == "dns":
        dport = 53 if dport not in (53, 5353) else dport
    elif forced == "http":
        app = "HTTP"
    # „tls" wird unten direkt behandelt.

    # DNS / mDNS
    if forced == "dns" or dport == 53 or sport == 53 or dport == 5353 or sport == 5353:
        info = _dissect_dns(payload, offset, pkt)
        if info:
            pkt.protocol = "DNS" if dport != 5353 and sport != 5353 else "mDNS"
            return info

    # TLS: Record-Typ 0x16 (Handshake) … 0x17 (App-Data), Version 0x03xx
    is_tls = (len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17)
              and payload[1] == 0x03)
    if is_tls or (forced == "tls" and len(payload) >= 3):
        rectype = {0x14: "Change Cipher Spec", 0x15: "Alert",
                   0x16: "Handshake", 0x17: "Application Data"}.get(
            payload[0], "TLS-Record")
        pkt.protocol = "TLS"
        fields: list[tuple[str, str]] = []
        summary = rectype
        info_line = f"TLS {rectype} ({sport} → {dport})"
        if payload[0] == 0x16:                       # Handshake genauer auswerten
            hs = tls_info(payload)
            if hs["type"] in ("Client Hello", "Server Hello"):
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
                fp = ja3(payload) if hs["type"] == "Client Hello" else \
                    (ja3s(payload) if hs["type"] == "Server Hello" else None)
                if fp is not None:
                    tag = "JA3" if hs["type"] == "Client Hello" else "JA3S"
                    fields.append((tag, fp[1]))
                    fields.append((f"{tag}-String", fp[0]))
                detail = ", ".join(x for x in (hs["version"], hs["cipher"]) if x)
                info_line = (f"TLS {hs['type']}"
                             + (f" SNI={hs['sni']}" if hs["sni"] else "")
                             + (f" [{detail}]" if detail else ""))
            elif len(payload) > 5 and payload[5] == 11:   # Certificate (TLS 1.2)
                cert = certinfo.summarize(_tls_first_cert(payload))
                if cert:
                    fields += [("Zertifikat-Subject", cert["subject"]),
                               ("Aussteller", cert["issuer"]),
                               ("Gültig von", cert["not_before"]),
                               ("Gültig bis", cert["not_after"])]
                    summary = f"Certificate: {cert['subject']}"
                    info_line = f"TLS Certificate ({cert['subject']})"
        pkt.layers.append(Layer("Transport Layer Security", summary=summary,
                                start=offset, length=len(payload), fields=fields))
        return info_line

    # HTTP/2 im Klartext (Connection-Preface oder SETTINGS-Frame) – vor HTTP/1.x
    info = _dissect_http2(payload, offset, pkt)
    if info:
        return info

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

    # Klartext-Mail (SMTP/IMAP/POP3), FTP-Steuerkanal, SSH – portbasiert
    if dport in (25, 587) or sport in (25, 587):
        info = _dissect_mail(payload, offset, pkt, "SMTP")
        if info:
            return info
    if dport == 110 or sport == 110:
        info = _dissect_mail(payload, offset, pkt, "POP3")
        if info:
            return info
    if dport == 143 or sport == 143:
        info = _dissect_mail(payload, offset, pkt, "IMAP")
        if info:
            return info
    if dport == 21 or sport == 21:
        info = _dissect_ftp(payload, offset, pkt)
        if info:
            return info
    if dport == 22 or sport == 22:
        info = _dissect_ssh(payload, offset, pkt)
        if info:
            return info

    # SMB/SMB2 (TCP 445/139)
    if dport in (445, 139) or sport in (445, 139):
        info = _dissect_smb(payload, offset, pkt)
        if info:
            return info

    # SIP (UDP/TCP 5060/5061 oder Signatur)
    if dport in (5060, 5061) or sport in (5060, 5061) or payload[:8] == b"SIP/2.0 ":
        info = _dissect_sip(payload, offset, pkt)
        if info:
            return info

    # DHCP (BOOTP) auf 67/68
    if dport in (67, 68) or sport in (67, 68):
        info = _dissect_dhcp(payload, offset, pkt)
        if info:
            return info

    # NTP auf 123
    if (dport == 123 or sport == 123) and len(payload) >= 4:
        li_vn_mode = payload[0]
        mode = li_vn_mode & 0x07
        version = (li_vn_mode >> 3) & 0x07
        stratum = payload[1]
        pkt.protocol = "NTP"
        pkt.layers.append(Layer("Network Time Protocol",
                                summary=f"v{version} mode {mode}", start=offset,
                                length=len(payload),
                                fields=[("Version", str(version)),
                                        ("Mode", str(mode)),
                                        ("Stratum", str(stratum))]))
        return f"NTP v{version} mode={mode} stratum={stratum}"

    # QUIC (UDP/443, Long-Header-Bit gesetzt, Version-Feld vorhanden)
    if (dport == 443 or sport == 443) and len(payload) >= 5 and payload[0] & 0x80:
        ver = int.from_bytes(payload[1:5], "big")
        pkt.protocol = "QUIC"
        pkt.layers.append(Layer("QUIC", summary=f"Version 0x{ver:08x}",
                                start=offset, length=len(payload)))
        return f"QUIC (Version 0x{ver:08x})"

    if app and payload:
        pkt.protocol = app
        return f"{app} {sport} → {dport} Len={len(payload)}"

    # RTP (heuristisch): UDP, Version 2, dynamischer (gerader) Port
    if pkt.l4 == "UDP" and dport > 1024 and dport % 2 == 0:
        info = _dissect_rtp(payload, offset, pkt)
        if info:
            return info
    return ""


# --- HTTP/2 ---------------------------------------------------------------- #
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_H2_FRAME = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
             4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
             8: "WINDOW_UPDATE", 9: "CONTINUATION"}


def _dissect_http2(payload: bytes, offset: int, pkt: Packet) -> str:
    data = payload
    preface = data.startswith(_H2_PREFACE)
    if preface:
        data = data[len(_H2_PREFACE):]
    elif not (len(data) >= 9 and data[3] == 4              # SETTINGS-Frame …
              and int.from_bytes(data[5:9], "big") & 0x7FFFFFFF == 0  # Stream 0
              and int.from_bytes(data[0:3], "big") % 6 == 0):         # Länge ×6
        return ""
    frames = []
    pos = 0
    while pos + 9 <= len(data) and len(frames) < 12:
        length = int.from_bytes(data[pos:pos + 3], "big")
        ftype = data[pos + 3]
        if ftype not in _H2_FRAME:
            break
        frames.append(_H2_FRAME[ftype])
        pos += 9 + length
    if not frames and not preface:
        return ""
    pkt.protocol = "HTTP2"
    summary = ("Connection Preface; " if preface else "") + ", ".join(frames)
    pkt.layers.append(Layer("HTTP/2", summary=summary[:120] or "Preface",
                            start=offset, length=len(payload),
                            fields=[("Frames", ", ".join(frames) or "—")]))
    return f"HTTP/2 {summary[:80] or 'Preface'}"


# --- SMB / SMB2 ------------------------------------------------------------ #
_SMB2_CMD = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
             4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH",
             8: "READ", 9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL",
             13: "ECHO", 14: "QUERY_DIRECTORY", 15: "CHANGE_NOTIFY",
             16: "QUERY_INFO", 17: "SET_INFO", 18: "OPLOCK_BREAK"}


def _smb2_utf16(data: bytes, off_pos: int, len_pos: int) -> str:
    """Liest einen UTF-16LE-String, dessen Offset/Länge im Header stehen."""
    try:
        noff = int.from_bytes(data[off_pos:off_pos + 2], "little")
        nlen = int.from_bytes(data[len_pos:len_pos + 2], "little")
        if noff and nlen and noff + nlen <= len(data):
            return data[noff:noff + nlen].decode("utf-16-le", "replace")
    except (IndexError, ValueError):
        pass
    return ""


def _dissect_smb(payload: bytes, offset: int, pkt: Packet) -> str:
    data = payload
    # Optionaler 4-Byte-Header (NetBIOS-Session / Direct-TCP) vor der Signatur.
    if len(data) >= 8 and data[0] == 0x00 and data[4:8] in (
            b"\xfeSMB", b"\xffSMB", b"\xfdSMB"):
        data = data[4:]
    if data[:4] == b"\xfeSMB" and len(data) >= 64:
        return _dissect_smb2(data, offset, len(payload), pkt)
    if data[:4] == b"\xffSMB":
        cmd = data[4] if len(data) > 4 else 0
        pkt.protocol = "SMB"
        pkt.layers.append(Layer("SMB", summary=f"Cmd 0x{cmd:02x}", start=offset,
                                length=len(payload)))
        return f"SMB Cmd 0x{cmd:02x}"
    return ""


def _dissect_smb2(data: bytes, offset: int, plen: int, pkt: Packet) -> str:
    cmd = int.from_bytes(data[12:14], "little")
    flags = int.from_bytes(data[16:20], "little")
    is_resp = bool(flags & 0x1)                       # SERVER_TO_REDIR
    msg_id = int.from_bytes(data[24:32], "little")
    tree_id = int.from_bytes(data[36:40], "little")
    session_id = int.from_bytes(data[40:48], "little")
    status = int.from_bytes(data[8:12], "little")
    name = _SMB2_CMD.get(cmd, f"Cmd {cmd}")
    direction = tr("Antwort") if is_resp else tr("Anfrage")
    fields = [("Command", f"{cmd} ({name})"), ("Richtung", direction),
              ("Message-ID", str(msg_id)),
              ("Tree-ID", f"0x{tree_id:08x}"),
              ("Session-ID", f"0x{session_id:016x}")]
    detail = ""
    if not is_resp and cmd == 5:                       # CREATE Request → Dateiname
        fn = _smb2_utf16(data, 108, 110)
        if fn:
            fields.append(("Dateiname", fn))
            detail = f" {fn}"
    elif not is_resp and cmd == 3:                     # TREE_CONNECT → Pfad
        path = _smb2_utf16(data, 68, 70)
        if path:
            fields.append(("Pfad", path))
            detail = f" {path}"
    if is_resp:
        fields.append(("Status", f"0x{status:08x}"))
    pkt.protocol = "SMB2"
    pkt.layers.append(Layer("SMB2", summary=f"{name} ({direction}){detail}",
                            start=offset, length=plen, fields=fields))
    return f"SMB2 {name} {direction}{detail}"


# --- SIP ------------------------------------------------------------------- #
_SIP_HEADERS = ("from", "to", "call-id", "cseq", "via", "contact", "user-agent")


def _dissect_sip(payload: bytes, offset: int, pkt: Packet) -> str:
    if not payload[:1].isascii():
        return ""
    head = payload[:2048].split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    first = lines[0].decode("latin-1", "replace")
    if "SIP/2.0" not in first:
        return ""
    fields = []
    for ln in lines[1:]:
        if b":" in ln:
            key, value = ln.split(b":", 1)
            k = key.decode("latin-1", "replace").strip()
            if k.lower() in _SIP_HEADERS:
                fields.append((k, value.decode("latin-1", "replace").strip()[:160]))
    pkt.protocol = "SIP"
    pkt.layers.append(Layer("Session Initiation Protocol", summary=first[:120],
                            start=offset, length=len(payload), fields=fields))
    return f"SIP {first[:90]}"


# --- Klartext-Mail: SMTP / IMAP / POP3 ------------------------------------- #
_MAIL_SERVER_PORTS = {"SMTP": (25, 587), "POP3": (110,), "IMAP": (143,)}
# Befehle/Antworten mit Forensik-/Credential-Bezug:
_MAIL_NOTABLE = ("mail from", "rcpt to", "ehlo", "helo", "auth", "user", "pass",
                 "login", "from:", "to:", "subject:")


def _dissect_mail(payload: bytes, offset: int, pkt: Packet, proto: str) -> str:
    if len(payload) < 3 or not payload[:1].isascii():
        return ""
    text = payload[:2048].decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0].strip()
    if not first or not first.isprintable():
        return ""
    sport = pkt.src_port or 0
    from_server = sport in _MAIL_SERVER_PORTS[proto]
    fields = [("Richtung", "Server→Client" if from_server else "Client→Server")]
    notable = None
    for ln in [x for x in text.split("\r\n") if x][:10]:
        fields.append(("Zeile", ln[:200]))
        low = ln.lower()
        if notable is None and any(low.startswith(k) for k in _MAIL_NOTABLE):
            notable = ln[:120]
    if notable:
        fields.append(("Auffällig", notable))
    pkt.protocol = proto
    names = {"SMTP": "Simple Mail Transfer Protocol",
             "POP3": "Post Office Protocol v3",
             "IMAP": "Internet Message Access Protocol"}
    pkt.layers.append(Layer(names[proto], summary=first[:120], start=offset,
                            length=len(payload), fields=fields))
    return f"{proto} {first[:100]}"


# --- FTP-Steuerkanal ------------------------------------------------------- #
def _dissect_ftp(payload: bytes, offset: int, pkt: Packet) -> str:
    if len(payload) < 3 or not payload[:1].isascii():
        return ""
    text = payload[:1024].decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0].strip()
    if not first or not first.isprintable():
        return ""
    from_server = (pkt.src_port or 0) == 21
    fields = [("Richtung", "Server→Client" if from_server else "Client→Server"),
              ("Zeile", first[:200])]
    low = first.lower()
    if low.startswith(("user ", "pass ", "stor ", "retr ", "cwd ")):
        fields.append(("Auffällig", first[:120]))
    pkt.protocol = "FTP"
    pkt.layers.append(Layer("File Transfer Protocol", summary=first[:120],
                            start=offset, length=len(payload), fields=fields))
    return f"FTP {first[:100]}"


# --- SSH (Banner + Klartext-Handshake-Nachrichten) ------------------------- #
_SSH_MSG = {1: "DISCONNECT", 2: "IGNORE", 5: "SERVICE_REQUEST",
            6: "SERVICE_ACCEPT", 20: "KEXINIT", 21: "NEWKEYS",
            30: "KEXDH_INIT", 31: "KEXDH_REPLY", 50: "USERAUTH_REQUEST",
            51: "USERAUTH_FAILURE", 52: "USERAUTH_SUCCESS"}


def _dissect_ssh(payload: bytes, offset: int, pkt: Packet) -> str:
    if payload[:4] == b"SSH-":                      # Versions-Banner
        banner = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:120]
        pkt.protocol = "SSH"
        pkt.layers.append(Layer("Secure Shell", summary=banner, start=offset,
                                length=len(payload), fields=[("Version", banner)]))
        return f"SSH {banner}"
    if len(payload) >= 6:                            # Binär-Paket vor Verschlüsselung
        plen = int.from_bytes(payload[:4], "big")
        msg = payload[5]
        if 0 < plen < 35000 and msg in _SSH_MSG:
            pkt.protocol = "SSH"
            pkt.layers.append(Layer("Secure Shell", summary=_SSH_MSG[msg],
                                    start=offset, length=len(payload),
                                    fields=[("Nachricht", f"{msg} ({_SSH_MSG[msg]})")]))
            return f"SSH {_SSH_MSG[msg]}"
    return ""


# --- RTP (heuristisch) ----------------------------------------------------- #
def _dissect_rtp(payload: bytes, offset: int, pkt: Packet) -> str:
    if len(payload) < 12 or (payload[0] >> 6) != 2:        # Version 2
        return ""
    pt = payload[1] & 0x7F
    if not (pt < 35 or 96 <= pt <= 127):                   # plausible Payload-Typen
        return ""
    seq = int.from_bytes(payload[2:4], "big")
    ts = int.from_bytes(payload[4:8], "big")
    ssrc = int.from_bytes(payload[8:12], "big")
    pkt.protocol = "RTP"
    pkt.layers.append(Layer("Real-time Transport Protocol",
                            summary=f"PT={pt} seq={seq}", start=offset,
                            length=len(payload),
                            fields=[("Payload-Typ", str(pt)),
                                    ("Sequenz", str(seq)),
                                    ("Timestamp", str(ts)),
                                    ("SSRC", f"0x{ssrc:08x}")]))
    return f"RTP PT={pt} seq={seq} ssrc=0x{ssrc:08x}"


_DHCP_MSG = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
             5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}


def _dissect_dhcp(payload: bytes, offset: int, pkt: Packet) -> str:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return ""                                   # kein DHCP-Magic-Cookie
    op = payload[0]
    msg_type = 0
    pos = 240
    while pos + 2 <= len(payload):
        code = payload[pos]
        if code == 255:
            break
        if code == 0:
            pos += 1
            continue
        length = payload[pos + 1]
        if code == 53 and length >= 1:
            msg_type = payload[pos + 2]
        pos += 2 + length
    name = _DHCP_MSG.get(msg_type, "?")
    pkt.protocol = "DHCP"
    pkt.l4 = pkt.l4 or "UDP"
    pkt.layers.append(Layer("Dynamic Host Configuration Protocol",
                            summary=f"DHCP {name}", start=offset,
                            length=len(payload),
                            fields=[("Op", "Request" if op == 1 else "Reply"),
                                    ("Nachrichtentyp", f"{msg_type} ({name})")]))
    return f"DHCP {name}"


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
        fields.append(("Typ", tr("Antwort")))
        fields.append(("Version", parts[0]))
        if len(parts) >= 2:
            fields.append(("Status", " ".join(parts[1:])[:80]))
    elif len(parts) >= 3:                          # Anfrage: METHODE PFAD VERSION
        fields.append(("Typ", tr("Anfrage")))
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
    out = {"type": "", "version": "", "cipher": "", "sni": "", "cipher_id": ""}
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
            cid = int.from_bytes(record[pos:pos + 2], "big")
            out["cipher_id"] = cid
            out["cipher"] = _TLS_CIPHERS.get(cid, f"0x{cid:04x}")
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


def _tls_first_cert(record: bytes) -> bytes:
    """Erste Zertifikat-DER aus einer TLS-1.2-Certificate-Handshake (oder b"")."""
    # Record(5) | HS-Typ 11(1) | HS-Länge(3) | cert_list_len(3) | cert_len(3) | DER
    if len(record) < 15 or record[0] != 0x16 or record[5] != 11:
        return b""
    clen = int.from_bytes(record[12:15], "big")
    der = record[15:15 + clen]
    return der if clen and len(der) == clen else b""


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
