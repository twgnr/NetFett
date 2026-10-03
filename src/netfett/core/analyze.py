"""Nachträgliche Analyse erfasster Pakete – rein (keine I/O, keine GUI).

Drei Bausteine, alle vollständig per Unit-Test prüfbar:

* :func:`conversations` – Aggregation pro Verbindung (5-Tupel): Pakete/Bytes je
  Richtung, Dauer, Durchsatz.
* :func:`follow_stream` – seq-korrekte Rekonstruktion eines TCP-Byte-Stroms,
  getrennt nach Client- und Server-Richtung (Wireshark „Follow Stream").
* :func:`expert_info` – heuristische Auffälligkeiten (TCP-Reset/-Retransmission,
  ICMP-Unreachable, einfache Port-Scan-Erkennung).

Die Funktionen lesen nur die ``Packet``-Felder bzw. – für seq/Flags/Payload –
die Rohbytes ab IPv4-Kopf; das Paketmodell bleibt unverändert.
"""
from __future__ import annotations

import base64
import math
import socket
import struct
from dataclasses import dataclass, field

from . import certinfo
from ..i18n import tr
from .dissect import _tls_first_cert, tls_info
from .ipinfo import is_public
from .models import DIR_OUT, Packet

# TCP-Flag-Bits.
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

Endpoint = tuple[str, int | None]  # (IP, Port) – Port None bei portlosen L4


# --------------------------------------------------------------------------- #
# Roh-Hilfen: TCP-Details aus den Rohbytes (ab IPv4-Kopf) ziehen.
# --------------------------------------------------------------------------- #
def _ihl(raw: bytes) -> int:
    return (raw[0] & 0x0F) * 4


def _parse_tcp(raw: bytes) -> tuple[int, int, int, int, bytes] | None:
    """(seq, ack, flags, window, payload) oder ``None`` (kein/zu kurzes TCP)."""
    if len(raw) < 20 or (raw[0] >> 4) != 4 or raw[9] != 6:
        return None
    ihl = max(20, min(_ihl(raw), len(raw)))
    tcp = raw[ihl:]
    if len(tcp) < 20:
        return None
    seq, ack = struct.unpack("!II", tcp[4:12])
    data_off = max(20, min((tcp[12] >> 4) * 4, len(tcp)))
    flags = tcp[13]
    window = struct.unpack("!H", tcp[14:16])[0]
    return seq, ack, flags, window, tcp[data_off:]


def tcp_segment(raw: bytes) -> tuple[int, int, int, bytes] | None:
    """(seq, ack, flags, payload) eines TCP-Pakets oder ``None``.

    Erwartet Rohbytes ab dem IPv4-Kopf (so liefert sie der Raw-Socket)."""
    parsed = _parse_tcp(raw)
    if parsed is None:
        return None
    seq, ack, flags, _win, payload = parsed
    return seq, ack, flags, payload


# --------------------------------------------------------------------------- #
# Verbindungen (Conversations)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Conversation:
    """Eine Verbindung zwischen zwei Endpunkten (richtungsneutral aggregiert)."""
    proto: str                      # "TCP" | "UDP" | "ICMP" | …
    a: str
    a_port: int | None
    b: str
    b_port: int | None
    a2b_pkts: int = 0
    a2b_bytes: int = 0
    b2a_pkts: int = 0
    b2a_bytes: int = 0
    start: float = 0.0
    end: float = 0.0

    @property
    def packets(self) -> int:
        return self.a2b_pkts + self.b2a_pkts

    @property
    def bytes(self) -> int:
        return self.a2b_bytes + self.b2a_bytes

    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)

    @property
    def bps(self) -> float:
        """Mittlerer Durchsatz in Bit/s über die Dauer (0 bei Nulldauer)."""
        d = self.duration
        return (self.bytes * 8 / d) if d > 0 else 0.0

    def endpoints(self) -> tuple[Endpoint, Endpoint]:
        return (self.a, self.a_port), (self.b, self.b_port)


def _conv_key(pkt: Packet):
    """Richtungsneutraler, stabiler Schlüssel und kanonische A/B-Zuordnung."""
    l4 = pkt.l4 or pkt.protocol or "?"
    e1: Endpoint = (pkt.src, pkt.src_port)
    e2: Endpoint = (pkt.dst, pkt.dst_port)
    # Kanonische Reihenfolge: kleinerer Endpunkt = A (stabil & reproduzierbar).
    a, b = (e1, e2) if _ep_sort(e1) <= _ep_sort(e2) else (e2, e1)
    return (l4, a, b)


def _ep_sort(e: Endpoint):
    ip, port = e
    return (ip, port if port is not None else -1)


def conversations(packets: list[Packet]) -> list[Conversation]:
    """Aggregiert Pakete zu Verbindungen, sortiert nach Volumen (absteigend)."""
    table: dict[tuple, Conversation] = {}
    for pkt in packets:
        l4, a, b = _conv_key(pkt)
        conv = table.get((l4, a, b))
        if conv is None:
            conv = Conversation(proto=l4, a=a[0], a_port=a[1],
                                b=b[0], b_port=b[1],
                                start=pkt.ts, end=pkt.ts)
            table[(l4, a, b)] = conv
        # Richtung relativ zur kanonischen A/B-Zuordnung bestimmen.
        if (pkt.src, pkt.src_port) == a:
            conv.a2b_pkts += 1
            conv.a2b_bytes += pkt.length
        else:
            conv.b2a_pkts += 1
            conv.b2a_bytes += pkt.length
        conv.start = min(conv.start, pkt.ts)
        conv.end = max(conv.end, pkt.ts)
    return sorted(table.values(), key=lambda c: c.bytes, reverse=True)


# --------------------------------------------------------------------------- #
# Follow TCP Stream
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class StreamChunk:
    from_client: bool      # True: Client→Server, False: Server→Client
    ts: float
    data: bytes


@dataclass(slots=True)
class StreamResult:
    client: Endpoint
    server: Endpoint
    chunks: list[StreamChunk] = field(default_factory=list)  # zeitlich geordnet
    client_bytes: bytes = b""    # seq-rekonstruierter Client→Server-Strom
    server_bytes: bytes = b""    # seq-rekonstruierter Server→Client-Strom

    @property
    def packets(self) -> int:
        return len(self.chunks)


def follow_stream(packets: list[Packet], ip_a: str, port_a: int,
                  ip_b: str, port_b: int) -> StreamResult:
    """Rekonstruiert den TCP-Byte-Strom zwischen zwei Endpunkten.

    Client = Absender des zeitlich ersten Pakets (bzw. des ersten SYN).
    Innerhalb jeder Richtung werden die Nutzdaten nach Sequenznummer sortiert
    und Überlappungen/Retransmissions zusammengeführt.
    """
    ea, eb = (ip_a, port_a), (ip_b, port_b)
    selected = [p for p in packets
                if {(p.src, p.src_port), (p.dst, p.dst_port)} == {ea, eb}
                and (p.l4 == "TCP" or p.protocol == "TCP")]
    selected.sort(key=lambda p: (p.ts, p.number))

    if not selected:
        return StreamResult(client=ea, server=eb)

    # Client = Absender des ersten SYN-ohne-ACK, sonst Absender des 1. Pakets.
    client_ep: Endpoint = (selected[0].src, selected[0].src_port)
    for p in selected:
        seg = tcp_segment(p.raw)
        if seg and (seg[2] & SYN) and not (seg[2] & ACK):
            client_ep = (p.src, p.src_port)
            break
    server_ep: Endpoint = eb if client_ep == ea else ea

    chunks: list[StreamChunk] = []
    c_segs: list[tuple[int, bytes]] = []
    s_segs: list[tuple[int, bytes]] = []
    for p in selected:
        seg = tcp_segment(p.raw)
        if not seg:
            continue
        seq, _ack, _flags, payload = seg
        if not payload:
            continue
        from_client = (p.src, p.src_port) == client_ep
        chunks.append(StreamChunk(from_client, p.ts, payload))
        (c_segs if from_client else s_segs).append((seq, payload))

    return StreamResult(
        client=client_ep, server=server_ep, chunks=chunks,
        client_bytes=_reassemble(c_segs),
        server_bytes=_reassemble(s_segs),
    )


def io_buckets(packets: list[Packet], ip_a: str, port_a, ip_b: str, port_b,
               bucket: float = 1.0) -> tuple[list[int], list[int]]:
    """Bytes je Zeitintervall einer Verbindung, getrennt nach Richtung.

    Liefert ``(a2b, b2a)`` – zwei gleich lange Listen mit Bytes pro ``bucket``
    Sekunden über die Dauer der Verbindung (für ein IO-Zeitdiagramm).
    """
    ea, eb = (ip_a, port_a), (ip_b, port_b)
    sel = [p for p in packets
           if {(p.src, p.src_port), (p.dst, p.dst_port)} == {ea, eb}]
    if not sel:
        return [], []
    sel.sort(key=lambda p: p.ts)
    t0, t1 = sel[0].ts, sel[-1].ts
    n = max(1, int((t1 - t0) / bucket) + 1)
    a2b = [0] * n
    b2a = [0] * n
    for p in sel:
        idx = min(n - 1, int((p.ts - t0) / bucket))
        if (p.src, p.src_port) == ea:
            a2b[idx] += p.length
        else:
            b2a[idx] += p.length
    return a2b, b2a


@dataclass(slots=True)
class SeqEvent:
    ts: float
    from_client: bool          # True: Client→Server, False: Server→Client
    label: str


def sequence(packets: list[Packet], ip_a: str, port_a, ip_b: str, port_b,
             limit: int = 500) -> tuple[Endpoint, Endpoint, list[SeqEvent]]:
    """Bereitet den Paketfluss einer Verbindung als Sequenz auf (für Diagramm).

    Client = Absender des ersten SYN (bzw. des zeitlich ersten Pakets)."""
    ea, eb = (ip_a, port_a), (ip_b, port_b)
    sel = [p for p in packets
           if {(p.src, p.src_port), (p.dst, p.dst_port)} == {ea, eb}]
    sel.sort(key=lambda p: (p.ts, p.number))
    if not sel:
        return ea, eb, []
    client: Endpoint = (sel[0].src, sel[0].src_port)
    for p in sel:
        seg = tcp_segment(p.raw)
        if seg and (seg[2] & SYN) and not (seg[2] & ACK):
            client = (p.src, p.src_port)
            break
    server = eb if client == ea else ea
    events = [SeqEvent(p.ts, (p.src, p.src_port) == client, _seq_label(p))
              for p in sel[:limit]]
    return client, server, events


_SEQ_FLAGS = [(FIN, "FIN"), (SYN, "SYN"), (RST, "RST"), (PSH, "PSH"),
              (ACK, "ACK")]


def _seq_label(pkt: Packet) -> str:
    seg = tcp_segment(pkt.raw)
    if seg is not None:
        flags = seg[2]
        names = [n for bit, n in _SEQ_FLAGS if flags & bit]
        label = f"{pkt.protocol} [{','.join(names) or '—'}]"
        plen = len(seg[3])
        if plen:
            label += f" len={plen}"
        return label
    return (pkt.info or pkt.protocol)[:48]


def _reassemble(segments: list[tuple[int, bytes]]) -> bytes:
    """Fügt (seq, payload)-Stücke einer Richtung lückenfrei zusammen.

    Sortiert nach (gegen Wrap relativiertem) Seq und überspringt Überlappungen
    bzw. Retransmissions. Lücken werden übersprungen (kein Auffüllen)."""
    if not segments:
        return b""
    base = segments[0][0]
    norm = sorted(((seq - base) & 0xFFFFFFFF, data) for seq, data in segments)
    out = bytearray()
    next_off = norm[0][0]
    for off, data in norm:
        end = off + len(data)
        if end <= next_off:
            continue                       # vollständig überlappend (Retrans.)
        if off < next_off:                 # teilweise Überlappung: vorne kürzen
            data = data[next_off - off:]
            off = next_off
        out += data
        next_off = off + len(data)
    return bytes(out)


# --------------------------------------------------------------------------- #
# Experten-Infos (Heuristiken)
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Kontaktierte Domains (DNS-Query / TLS-SNI / HTTP-Host)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class DomainStat:
    name: str
    packets: int
    protocols: tuple[str, ...]   # über welche Protokolle gesehen (sortiert)


def domains(packets: list[Packet]) -> list[DomainStat]:
    """Aggregiert die in ``pkt.domain`` vermerkten Domains, nach Häufigkeit."""
    table: dict[str, list] = {}   # name -> [count, set(protocols)]
    for pkt in packets:
        name = pkt.domain
        if not name:
            continue
        ent = table.setdefault(name, [0, set()])
        ent[0] += 1
        ent[1].add(pkt.protocol or pkt.l4 or "?")
    out = [DomainStat(name, c, tuple(sorted(p))) for name, (c, p) in table.items()]
    out.sort(key=lambda d: (d.packets, d.name), reverse=True)
    return out


# --------------------------------------------------------------------------- #
# Protokoll-Hierarchie
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class HierNode:
    """Ein Knoten der Protokoll-Hierarchie (Schichtname → Kennzahlen)."""
    name: str
    packets: int = 0
    bytes: int = 0
    children: dict[str, "HierNode"] = field(default_factory=dict)

    def child_list(self) -> list["HierNode"]:
        """Kinder nach Volumen absteigend."""
        return sorted(self.children.values(), key=lambda n: n.bytes, reverse=True)


def protocol_hierarchy(packets: list[Packet]) -> list[HierNode]:
    """Baut die Protokollverteilung als Baum entlang der Schichtfolge je Paket.

    Jeder Knoten zählt die Pakete und (vollen) Bytes, die ihn durchlaufen –
    wie die „Protocol Hierarchy" in Wireshark. Rückgabe: Wurzelknoten (Top-Level)."""
    roots: dict[str, HierNode] = {}
    for pkt in packets:
        level = roots
        for layer in pkt.layers:
            node = level.get(layer.name)
            if node is None:
                node = HierNode(layer.name)
                level[layer.name] = node
            node.packets += 1
            node.bytes += pkt.length
            level = node.children
    return sorted(roots.values(), key=lambda n: n.bytes, reverse=True)


# --------------------------------------------------------------------------- #
# Experten-Infos (Heuristiken)
# --------------------------------------------------------------------------- #
SEV_INFO, SEV_NOTE, SEV_WARN, SEV_ERROR = "info", "note", "warn", "error"


@dataclass(slots=True)
class Finding:
    severity: str          # SEV_*
    category: str          # "TCP" | "ICMP" | "Security"
    summary: str
    packet: int | None = None   # Paketnummer (oder None für Aggregat)


def expert_info(packets: list[Packet], scan_port_threshold: int = 15,
                scan_host_threshold: int = 15) -> list[Finding]:
    """Erkennt gängige Auffälligkeiten und liefert eine Befundliste."""
    findings: list[Finding] = []
    seen_seq: dict[tuple, set[tuple[int, int]]] = {}  # conv+dir -> {(seq,len)}
    syn_ports: dict[str, set[int]] = {}   # src -> Menge angefragter dst-Ports
    syn_hosts: dict[str, set[str]] = {}   # src -> Menge angefragter dst-Hosts

    for pkt in packets:
        if pkt.l4 == "ICMP":
            if "Unreachable" in (pkt.info or "") or "Time Exceeded" in (pkt.info or ""):
                findings.append(Finding(
                    SEV_WARN, "ICMP", pkt.info or tr("ICMP-Fehler"), pkt.number))
            continue

        seg = tcp_segment(pkt.raw)
        if seg is None:
            continue
        seq, _ack, flags, payload = seg

        if flags & RST:
            findings.append(Finding(
                SEV_NOTE, "TCP",
                tr("Verbindungs-Reset (RST) {src} → {dst}").format(
                    src=pkt.src, dst=pkt.dst),
                pkt.number))

        # Retransmission: identisches (seq, len) mit Nutzdaten erneut gesehen.
        if payload:
            key = (pkt.src, pkt.src_port, pkt.dst, pkt.dst_port)
            sset = seen_seq.setdefault(key, set())
            sig = (seq, len(payload))
            if sig in sset:
                findings.append(Finding(
                    SEV_WARN, "TCP",
                    tr("Mögliche Retransmission (seq={seq}, len={length})").format(
                        seq=seq, length=len(payload)),
                    pkt.number))
            else:
                sset.add(sig)

        # SYN-ohne-ACK = Verbindungsversuch → für Scan-Heuristik sammeln.
        if (flags & SYN) and not (flags & ACK):
            if pkt.dst_port is not None:
                syn_ports.setdefault(pkt.src, set()).add(pkt.dst_port)
            syn_hosts.setdefault(pkt.src, set()).add(pkt.dst)

    for src, ports in syn_ports.items():
        if len(ports) >= scan_port_threshold:
            findings.append(Finding(
                SEV_ERROR, "Security",
                tr("Möglicher Port-Scan: {src} sendete SYN an {n} Ports").format(
                    src=src, n=len(ports))))
    for src, hosts in syn_hosts.items():
        if len(hosts) >= scan_host_threshold:
            findings.append(Finding(
                SEV_ERROR, "Security",
                tr("Möglicher Host-Scan: {src} sendete SYN an {n} Hosts").format(
                    src=src, n=len(hosts))))

    findings.extend(beaconing(packets))
    findings.extend(credentials(packets))
    findings.extend(dns_tunneling(packets))
    findings.extend(exfiltration(packets))
    findings.extend(tls_hygiene(packets))
    findings.extend(dns_anomalies(packets))
    findings.extend(connection_anomalies(packets))
    findings.extend(traffic_anomalies(packets))
    for ts, ip, domain in first_contacts(packets)[:15]:
        label = f"{ip} ({domain})" if domain else ip
        findings.append(Finding(SEV_INFO, "Erstkontakt",
                                tr("Erster Kontakt: {label}").format(label=label)))
    return findings


# --------------------------------------------------------------------------- #
# TCP-Gesundheit (Metriken pro Verbindung)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class FlowHealth:
    a: str
    a_port: int | None
    b: str
    b_port: int | None
    packets: int = 0
    retransmissions: int = 0
    dup_acks: int = 0
    zero_window: int = 0
    rtt_ms: float | None = None      # Handshake-RTT (SYN → SYN/ACK), falls messbar

    @property
    def has_issue(self) -> bool:
        return (self.retransmissions or self.dup_acks or self.zero_window) > 0


class _HealthAcc:
    __slots__ = ("h", "seen", "last_ack", "syn_ts")

    def __init__(self, a, b):
        self.h = FlowHealth(a[0], a[1], b[0], b[1])
        self.seen: dict[Endpoint, set] = {}        # Richtung → {(seq,len)}
        self.last_ack: dict[Endpoint, list] = {}   # Richtung → [ack, count]
        self.syn_ts: float | None = None


def tcp_health(packets: list[Packet]) -> list[FlowHealth]:
    """Berechnet je TCP-Verbindung Gesundheits-Kennzahlen.

    * Handshake-RTT: Zeit zwischen Client-SYN und Server-SYN/ACK.
    * Retransmissions: identisches (seq, len) mit Nutzdaten je Richtung erneut.
    * Dup-ACKs: gleiche Bestätigungsnummer ohne Nutzdaten mehrfach hintereinander.
    * Zero-Window: angekündigtes Empfangsfenster 0 (Empfänger ausgebremst).
    """
    accs: dict[tuple, _HealthAcc] = {}
    for pkt in packets:
        parsed = _parse_tcp(pkt.raw)
        if parsed is None:
            continue
        seq, ack, flags, window, payload = parsed
        _l4, a, b = _conv_key(pkt)
        acc = accs.get((a, b))
        if acc is None:
            acc = _HealthAcc(a, b)
            accs[(a, b)] = acc
        h = acc.h
        h.packets += 1
        direction: Endpoint = (pkt.src, pkt.src_port)

        if payload:                                # Retransmission je Richtung
            sset = acc.seen.setdefault(direction, set())
            sig = (seq, len(payload))
            if sig in sset:
                h.retransmissions += 1
            else:
                sset.add(sig)
        elif flags & ACK:                          # reiner ACK → Dup-ACK/Zero-Win
            la = acc.last_ack.get(direction)
            if la is not None and la[0] == ack:
                la[1] += 1
                h.dup_acks += 1
            else:
                acc.last_ack[direction] = [ack, 0]
            if window == 0:
                h.zero_window += 1

        # Handshake-RTT.
        if (flags & SYN) and not (flags & ACK):
            acc.syn_ts = pkt.ts
        elif (flags & SYN) and (flags & ACK) and acc.syn_ts is not None \
                and h.rtt_ms is None:
            h.rtt_ms = max(0.0, (pkt.ts - acc.syn_ts) * 1000.0)

    return sorted((a.h for a in accs.values()),
                  key=lambda f: f.packets, reverse=True)


# --------------------------------------------------------------------------- #
# Sicherheit: Beaconing & Klartext-Credentials
# --------------------------------------------------------------------------- #
def beaconing(packets: list[Packet], min_events: int = 4,
              max_cv: float = 0.15) -> list[Finding]:
    """Erkennt periodische Verbindungsversuche (gleichmäßiges Intervall → C2).

    Gruppiert Client-SYNs nach (Quelle, Ziel, Ziel-Port); ist die Streuung der
    Zeitabstände gering (Variationskoeffizient ≤ ``max_cv``), gilt es als Beacon.
    """
    starts: dict[tuple, list[float]] = {}
    for pkt in packets:
        seg = tcp_segment(pkt.raw)
        if seg is None:
            continue
        flags = seg[2]
        if (flags & SYN) and not (flags & ACK):
            starts.setdefault((pkt.src, pkt.dst, pkt.dst_port), []).append(pkt.ts)

    out: list[Finding] = []
    for (src, dst, dport), times in starts.items():
        if len(times) < min_events:
            continue
        times.sort()
        deltas = [t2 - t1 for t1, t2 in zip(times, times[1:])]
        mean = sum(deltas) / len(deltas)
        if mean <= 0:
            continue
        var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
        cv = (var ** 0.5) / mean
        if cv <= max_cv:
            out.append(Finding(
                SEV_WARN, "Security",
                tr("Mögliches Beaconing: {src} → {dst}:{dport} "
                   "alle ~{mean:.1f}s ({n}×, CV={cv:.2f})").format(
                    src=src, dst=dst, dport=dport, mean=mean, n=len(times),
                    cv=cv)))
    return out


def credentials(packets: list[Packet]) -> list[Finding]:
    """Findet im Klartext übertragene Zugangsdaten (HTTP Basic-Auth, FTP)."""
    out: list[Finding] = []
    for pkt in packets:
        seg = tcp_segment(pkt.raw)
        if seg is None:
            continue
        payload = seg[3]
        if not payload:
            continue

        low = payload.lower()
        idx = low.find(b"authorization: basic ")
        if idx != -1:
            token = payload[idx + 21:].split(b"\r\n", 1)[0].strip()
            try:
                decoded = base64.b64decode(token, validate=True).decode("latin-1")
            except (ValueError, UnicodeDecodeError):
                decoded = ""
            if ":" in decoded:
                out.append(Finding(
                    SEV_ERROR, "Security",
                    tr("HTTP Basic-Auth im Klartext: {cred} ({src} → {dst})")
                    .format(cred=decoded, src=pkt.src, dst=pkt.dst),
                    pkt.number))

        if pkt.dst_port == 21 or pkt.src_port == 21:
            line = payload.split(b"\r\n", 1)[0]
            tag = line[:5].upper()
            if tag in (b"USER ", b"PASS "):
                value = line[5:].decode("latin-1", "replace")
                text = (tr("FTP-Benutzer im Klartext: {value} ({src} → {dst})")
                        if tag == b"USER " else
                        tr("FTP-Passwort im Klartext: {value} ({src} → {dst})"))
                sev = SEV_NOTE if tag == b"USER " else SEV_ERROR
                out.append(Finding(
                    sev, "Security",
                    text.format(value=value, src=pkt.src, dst=pkt.dst),
                    pkt.number))
    return out


# --------------------------------------------------------------------------- #
# Transport-Payload-Helfer (für DNS-Analyse; IPv4/IPv6 ohne Ext-Header)
# --------------------------------------------------------------------------- #
def _udp_payload(raw: bytes) -> bytes | None:
    if len(raw) < 1:
        return None
    version = raw[0] >> 4
    if version == 4:
        if len(raw) < 20 or raw[9] != 17:
            return None
        ihl = max(20, min((raw[0] & 0x0F) * 4, len(raw)))
        l4 = raw[ihl:]
    elif version == 6:
        if len(raw) < 40 or raw[6] != 17:        # ohne Ext-Header (für DNS ok)
            return None
        l4 = raw[40:]
    else:
        return None
    return l4[8:] if len(l4) >= 8 else None


# --------------------------------------------------------------------------- #
# DNS-Tiefenanalyse
# --------------------------------------------------------------------------- #
_DNS_TYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


@dataclass(slots=True)
class DnsMessage:
    is_response: bool
    txid: int
    rcode: int
    qname: str
    qtype: str
    answers: list[tuple[str, str]]    # (Typ, Wert)


@dataclass(slots=True)
class DnsStat:
    name: str
    qtype: str
    queries: int
    responses: int
    nxdomain: int
    avg_ms: float | None
    addresses: tuple[str, ...]


def _dns_name(buf: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = pos
    while depth < 12 and 0 <= pos < len(buf):
        length = buf[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            depth += 1
            continue
        pos += 1
        labels.append(buf[pos:pos + length].decode("latin-1", "replace"))
        pos += length
        if not jumped:
            end = pos
    return ".".join(labels), end


def parse_dns(payload: bytes) -> DnsMessage | None:
    if len(payload) < 12:
        return None
    try:
        txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    except struct.error:
        return None
    is_resp = bool(flags & 0x8000)
    rcode = flags & 0x000F
    if qd < 1:
        return None
    qname, pos = _dns_name(payload, 12)
    if pos + 4 > len(payload):
        return None
    qtype_num, _qclass = struct.unpack("!HH", payload[pos:pos + 4])
    pos += 4
    answers: list[tuple[str, str]] = []
    for _ in range(an):
        if pos + 1 > len(payload):
            break
        _name, pos = _dns_name(payload, pos)
        if pos + 10 > len(payload):
            break
        atype, _aclass, _ttl, rdlen = struct.unpack("!HHIH", payload[pos:pos + 10])
        pos += 10
        rdata = payload[pos:pos + rdlen]
        if atype == 1 and len(rdata) == 4:
            answers.append(("A", socket.inet_ntoa(rdata)))
        elif atype == 28 and len(rdata) == 16:
            answers.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rdata)))
        elif atype == 5:
            cname, _ = _dns_name(payload, pos)
            answers.append(("CNAME", cname))
        pos += rdlen
    return DnsMessage(is_resp, txid, rcode, qname,
                      _DNS_TYPE.get(qtype_num, str(qtype_num)), answers)


def dns_analysis(packets: list[Packet]) -> list[DnsStat]:
    """Korreliert DNS-Anfragen/-Antworten und aggregiert je Name.

    Liefert je (Name, Typ): Anzahl Anfragen/Antworten, NXDOMAIN, mittlere
    Antwortzeit (ms) und gefundene A/AAAA/CNAME-Werte."""
    pending: dict[tuple, float] = {}                 # (txid, name) -> Anfrage-ts
    agg: dict[tuple, dict] = {}
    for pkt in packets:
        if pkt.src_port not in (53, 5353) and pkt.dst_port not in (53, 5353):
            continue
        payload = _udp_payload(pkt.raw)
        if payload is None:
            continue
        msg = parse_dns(payload)
        if msg is None:
            continue
        key = (msg.qname.lower(), msg.qtype)
        a = agg.setdefault(key, {"name": msg.qname, "qtype": msg.qtype,
                                 "q": 0, "r": 0, "nx": 0, "rts": [],
                                 "addrs": []})
        if not msg.is_response:
            a["q"] += 1
            pending[(msg.txid, msg.qname.lower())] = pkt.ts
        else:
            a["r"] += 1
            if msg.rcode == 3:
                a["nx"] += 1
            for _atype, value in msg.answers:
                if value not in a["addrs"]:
                    a["addrs"].append(value)
            t0 = pending.pop((msg.txid, msg.qname.lower()), None)
            if t0 is not None:
                a["rts"].append((pkt.ts - t0) * 1000.0)
    out = []
    for a in agg.values():
        avg = sum(a["rts"]) / len(a["rts"]) if a["rts"] else None
        out.append(DnsStat(a["name"], a["qtype"], a["q"], a["r"], a["nx"],
                           avg, tuple(a["addrs"][:8])))
    out.sort(key=lambda d: (d.queries + d.responses), reverse=True)
    return out


# --------------------------------------------------------------------------- #
# Endpunkt- & Port-Statistik
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class EndpointStat:
    ip: str
    tx_pkts: int = 0
    tx_bytes: int = 0
    rx_pkts: int = 0
    rx_bytes: int = 0

    @property
    def packets(self) -> int:
        return self.tx_pkts + self.rx_pkts

    @property
    def bytes(self) -> int:
        return self.tx_bytes + self.rx_bytes


def endpoints(packets: list[Packet]) -> list[EndpointStat]:
    """Aggregiert Volumen je einzelner Host-IP (gesendet/empfangen)."""
    table: dict[str, EndpointStat] = {}
    for pkt in packets:
        if pkt.src:
            e = table.setdefault(pkt.src, EndpointStat(pkt.src))
            e.tx_pkts += 1
            e.tx_bytes += pkt.length
        if pkt.dst:
            e = table.setdefault(pkt.dst, EndpointStat(pkt.dst))
            e.rx_pkts += 1
            e.rx_bytes += pkt.length
    return sorted(table.values(), key=lambda e: e.bytes, reverse=True)


@dataclass(slots=True)
class PortStat:
    port: int
    service: str
    proto: str
    packets: int
    bytes: int


def port_stats(packets: list[Packet]) -> list[PortStat]:
    """Top-Dienst-Ports (der „bekannte" Port je TCP/UDP-Paket), nach Volumen."""
    from . import protocols as _P
    table: dict[tuple, list] = {}
    for pkt in packets:
        if pkt.l4 not in ("TCP", "UDP"):
            continue
        sp, dp = pkt.src_port, pkt.dst_port
        if sp is None or dp is None:
            continue
        if _P.port_app(dp):
            port = dp
        elif _P.port_app(sp):
            port = sp
        else:
            port = min(sp, dp)
        key = (port, pkt.l4)
        row = table.setdefault(key, [0, 0])
        row[0] += 1
        row[1] += pkt.length
    out = [PortStat(port, _P.port_app(port) or "?", proto, c[0], c[1])
           for (port, proto), c in table.items()]
    out.sort(key=lambda p: p.bytes, reverse=True)
    return out


def size_histogram(packets: list[Packet]) -> list[tuple[str, int]]:
    """Verteilung der Paketgrößen in festen Größenklassen."""
    bounds = [64, 128, 256, 512, 1024, 1280, 1518]
    labels = ["≤64", "65–128", "129–256", "257–512", "513–1024",
              "1025–1280", "1281–1518", ">1518"]
    counts = [0] * len(labels)
    for pkt in packets:
        for i, b in enumerate(bounds):
            if pkt.length <= b:
                counts[i] += 1
                break
        else:
            counts[-1] += 1
    return [(labels[i], counts[i]) for i in range(len(labels)) if counts[i]]


# --------------------------------------------------------------------------- #
# Verbindungs-Lebenszyklus (TCP-Zustand je Flow)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ConnState:
    a: str
    a_port: int | None
    b: str
    b_port: int | None
    state: str
    setup_ms: float | None      # Handshake-Zeit (SYN → SYN/ACK)
    duration: float
    packets: int


def connection_states(packets: list[Packet]) -> list[ConnState]:
    """Klassifiziert jede TCP-Verbindung nach ihrem Lebenszyklus-Zustand."""
    acc: dict[tuple, dict] = {}
    for pkt in packets:
        if pkt.l4 != "TCP":
            continue
        seg = tcp_segment(pkt.raw)
        if seg is None:
            continue
        flags = seg[2]
        _l4, a, b = _conv_key(pkt)
        d = acc.get((a, b))
        if d is None:
            d = {"a": a, "b": b, "syn": None, "synack": None, "data": False,
                 "fin": 0, "rst": False, "first": pkt.ts, "last": pkt.ts,
                 "pkts": 0}
            acc[(a, b)] = d
        d["pkts"] += 1
        d["first"] = min(d["first"], pkt.ts)
        d["last"] = max(d["last"], pkt.ts)
        if (flags & SYN) and not (flags & ACK):
            if d["syn"] is None:
                d["syn"] = pkt.ts
        elif (flags & SYN) and (flags & ACK):
            if d["synack"] is None:
                d["synack"] = pkt.ts
        if flags & RST:
            d["rst"] = True
        if flags & FIN:
            d["fin"] += 1
        if len(seg[3]) > 0:
            d["data"] = True
    out = []
    for d in acc.values():
        if d["rst"]:
            state = "Zurückgesetzt (RST)"
        elif d["fin"] >= 1:
            state = "Geschlossen (FIN)"
        elif d["data"] and d["synack"]:
            state = "Aktiv (established)"
        elif d["syn"] and d["synack"]:
            state = "Aufbau (SYN/ACK)"
        elif d["syn"] and not d["synack"]:
            state = "Fehlgeschlagen (keine Antwort)"
        else:
            state = "Unvollständig"
        setup = ((d["synack"] - d["syn"]) * 1000.0
                 if d["syn"] and d["synack"] else None)
        (a_ip, a_port), (b_ip, b_port) = d["a"], d["b"]
        out.append(ConnState(a_ip, a_port, b_ip, b_port, state, setup,
                             max(0.0, d["last"] - d["first"]), d["pkts"]))
    out.sort(key=lambda c: c.packets, reverse=True)
    return out


# --------------------------------------------------------------------------- #
# Globaler IO-Verlauf (mehrere Filter-Linien)
# --------------------------------------------------------------------------- #
def io_timeline(packets: list[Packet], predicates: list,
                bucket: float = 1.0, by_packets: bool = False
                ) -> tuple[int, list[list[int]]]:
    """Bytes (oder Pakete) je Zeitintervall für mehrere Filter-Prädikate.

    ``predicates`` ist eine Liste von ``Packet -> bool`` (oder ``None`` = alles).
    Liefert (Anzahl Buckets, Liste gleich langer Reihen – eine je Prädikat)."""
    series = [[] for _ in predicates]
    if not packets or not predicates:
        return 0, series
    t0 = min(p.ts for p in packets)
    t1 = max(p.ts for p in packets)
    n = max(1, int((t1 - t0) / bucket) + 1)
    series = [[0] * n for _ in predicates]
    for p in packets:
        idx = min(n - 1, int((p.ts - t0) / bucket))
        val = 1 if by_packets else p.length
        for i, pred in enumerate(predicates):
            if pred is None or pred(p):
                series[i][idx] += val
    return n, series


# --------------------------------------------------------------------------- #
# Netzwerk-Topologie (Knoten = Hosts, Kanten = Verbindungen)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class TopoNode:
    ip: str
    bytes: int
    packets: int
    is_local: bool


@dataclass(slots=True)
class TopoEdge:
    a: str
    b: str
    bytes: int
    packets: int


def topology(packets: list[Packet], local_ips: set[str] | None = None,
             max_nodes: int = 20) -> tuple[list[TopoNode], list[TopoEdge]]:
    """Baut Knoten (Top-Hosts nach Volumen) und Kanten (Verbindungen dazwischen)."""
    local_ips = local_ips or set()
    host_b: dict[str, list[int]] = {}        # ip -> [bytes, pkts]
    edge_b: dict[tuple, list[int]] = {}      # (a,b) -> [bytes, pkts]
    for p in packets:
        if not p.src or not p.dst:
            continue
        for ip in (p.src, p.dst):
            h = host_b.setdefault(ip, [0, 0])
            h[0] += p.length
            h[1] += 1
        a, b = (p.src, p.dst) if p.src <= p.dst else (p.dst, p.src)
        e = edge_b.setdefault((a, b), [0, 0])
        e[0] += p.length
        e[1] += 1
    top = sorted(host_b, key=lambda ip: host_b[ip][0], reverse=True)[:max_nodes]
    keep = set(top)
    nodes = [TopoNode(ip, host_b[ip][0], host_b[ip][1], ip in local_ips)
             for ip in top]
    edges = [TopoEdge(a, b, v[0], v[1]) for (a, b), v in edge_b.items()
             if a in keep and b in keep and a != b]
    edges.sort(key=lambda e: e.bytes, reverse=True)
    return nodes, edges


# --------------------------------------------------------------------------- #
# TCP-Stream-Trace (für Sequenz-/Durchsatz-/Window-Graphen)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class TcpSample:
    t: float                 # Zeit relativ zum ersten Paket
    seq: int                 # relative Sequenznummer (ab 0 je Richtung)
    length: int              # Nutzdatenlänge
    window: int
    from_client: bool


def tcp_trace(packets: list[Packet], ip_a: str, port_a, ip_b: str, port_b):
    """Sammelt je TCP-Paket einer Verbindung (t, rel-seq, len, window, Richtung)."""
    ea, eb = (ip_a, port_a), (ip_b, port_b)
    sel = [p for p in packets
           if {(p.src, p.src_port), (p.dst, p.dst_port)} == {ea, eb}
           and p.l4 == "TCP"]
    sel.sort(key=lambda p: (p.ts, p.number))
    if not sel:
        return []
    t0 = sel[0].ts
    client = (sel[0].src, sel[0].src_port)
    for p in sel:
        seg = _parse_tcp(p.raw)
        if seg and (seg[2] & SYN) and not (seg[2] & ACK):
            client = (p.src, p.src_port)
            break
    base = {}                                        # Richtung → initiale seq
    out = []
    for p in sel:
        seg = _parse_tcp(p.raw)
        if seg is None:
            continue
        seq, _ack, _flags, window, payload = seg
        fc = (p.src, p.src_port) == client
        if fc not in base:
            base[fc] = seq
        rel = (seq - base[fc]) & 0xFFFFFFFF
        out.append(TcpSample(p.ts - t0, rel, len(payload), window, fc))
    return out


# --------------------------------------------------------------------------- #
# RTP-Stream-Verfolgung (Verlust & Jitter je SSRC)
# --------------------------------------------------------------------------- #
_RTP_CLOCK = {0: 8000, 3: 8000, 4: 8000, 8: 8000, 9: 8000, 15: 8000,
              18: 8000, 5: 8000, 6: 16000, 7: 8000, 10: 44100, 11: 44100,
              16: 11025, 17: 22050, 25: 90000, 26: 90000, 28: 90000,
              31: 90000, 32: 90000, 33: 90000, 34: 90000}


@dataclass(slots=True)
class RtpStream:
    ssrc: int
    src: str
    src_port: int | None
    dst: str
    dst_port: int | None
    payload_type: int
    packets: int
    lost: int
    jitter_ms: float
    duration: float

    @property
    def loss_pct(self) -> float:
        total = self.packets + self.lost
        return (100.0 * self.lost / total) if total else 0.0


def rtp_streams(packets: list[Packet]) -> list[RtpStream]:
    """Gruppiert RTP-Pakete nach SSRC und berechnet Verlust und Jitter (RFC 3550)."""
    groups: dict[tuple, list] = {}
    for p in packets:
        if p.protocol != "RTP":
            continue
        pl = _udp_payload(p.raw)
        if pl is None or len(pl) < 12 or (pl[0] >> 6) != 2:
            continue
        pt = pl[1] & 0x7F
        seq = int.from_bytes(pl[2:4], "big")
        rtp_ts = int.from_bytes(pl[4:8], "big")
        ssrc = int.from_bytes(pl[8:12], "big")
        key = (p.src, p.src_port, p.dst, p.dst_port, ssrc)
        groups.setdefault(key, []).append((p.ts, seq, rtp_ts, pt))

    out = []
    for (src, sp, dst, dp, ssrc), items in groups.items():
        items.sort(key=lambda x: x[0])               # nach Ankunftszeit
        pt = items[0][3]
        clock = _RTP_CLOCK.get(pt, 8000)
        # Sequenznummern entrollen (16-Bit-Wrap), erwartete Anzahl bestimmen.
        cycles = 0
        prev_seq = None
        ext = []
        for _ts, seq, _rts, _pt in items:
            if prev_seq is not None and seq < prev_seq - 30000:
                cycles += 1
            ext.append(seq + cycles * 65536)
            prev_seq = seq
        expected = max(ext) - min(ext) + 1
        received = len(items)
        lost = max(0, expected - received)
        # Jitter nach RFC 3550 (in Timestamp-Einheiten → ms).
        jitter = 0.0
        prev_arr = prev_rts = None
        for ts, _seq, rts, _pt in items:
            if prev_arr is not None:
                d = (ts - prev_arr) * clock - (rts - prev_rts)
                jitter += (abs(d) - jitter) / 16.0
            prev_arr, prev_rts = ts, rts
        duration = items[-1][0] - items[0][0]
        out.append(RtpStream(ssrc, src, sp, dst, dp, pt, received, lost,
                             jitter / clock * 1000.0, duration))
    out.sort(key=lambda s: s.packets, reverse=True)
    return out


# --------------------------------------------------------------------------- #
# Sicherheits-Heuristiken: DNS-Tunneling, Exfiltration, Erstkontakte
# --------------------------------------------------------------------------- #
def dns_tunneling(packets: list[Packet], min_queries: int = 20,
                  min_avg_sub: int = 20) -> list[Finding]:
    """Erkennt mögliches DNS-Tunneling (viele lange, eindeutige Subdomains)."""
    agg: dict[tuple, list] = {}                   # (src, base) -> [count, sublen, subs]
    for p in packets:
        if p.src_port not in (53, 5353) and p.dst_port not in (53, 5353):
            continue
        pl = _udp_payload(p.raw)
        if pl is None:
            continue
        msg = parse_dns(pl)
        if msg is None or msg.is_response:
            continue
        labels = msg.qname.lower().rstrip(".").split(".")
        if len(labels) < 3:
            continue
        base = ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
        a = agg.setdefault((p.src, base), [0, 0, set()])
        a[0] += 1
        a[1] += len(sub)
        a[2].add(sub)
    out = []
    for (src, base), (cnt, sublen, subs) in agg.items():
        if (cnt >= min_queries and len(subs) >= min_queries * 0.6
                and cnt and sublen / cnt >= min_avg_sub):
            out.append(Finding(
                SEV_WARN, "Security",
                tr("Mögliches DNS-Tunneling: {src} → {base} "
                   "({cnt} Anfragen, {subs} eindeutige Subdomains, "
                   "Ø {avg} Zeichen)").format(
                    src=src, base=base, cnt=cnt, subs=len(subs),
                    avg=sublen // cnt)))
    return out


def exfiltration(packets: list[Packet],
                 min_bytes: int = 10 * 1024 * 1024) -> list[Finding]:
    """Auffällig großes ausgehendes Volumen zu einem einzelnen Host."""
    out_by_dst: dict[str, int] = {}
    for p in packets:
        if p.direction == DIR_OUT and p.dst:
            out_by_dst[p.dst] = out_by_dst.get(p.dst, 0) + p.length
    findings = []
    for dst, total in out_by_dst.items():
        if total >= min_bytes:
            mb = total / (1024 * 1024)
            findings.append(Finding(
                SEV_WARN, "Security",
                tr("Großes ausgehendes Volumen: {mb:.1f} MB → {dst}").format(
                    mb=mb, dst=dst)))
    return findings


def first_contacts(packets: list[Packet]) -> list[tuple[float, str, str]]:
    """Erstmals kontaktierte **öffentliche** Hosts (Zeit, IP, Domain), in Reihenfolge."""
    seen: set[str] = set()
    out = []
    for p in packets:
        for ip in (p.dst, p.src):
            if ip and ip not in seen and is_public(ip):
                seen.add(ip)
                out.append((p.ts, ip, p.domain))
    return out


# --------------------------------------------------------------------------- #
# A — TLS-/Zertifikats-Hygiene
# --------------------------------------------------------------------------- #
_WEAK_TLS_VERSIONS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
# Tokens, die auf schwache/veraltete Cipher-Suites hindeuten (falls Name bekannt).
_WEAK_CIPHER_TOKENS = ("RC4", "NULL", "EXPORT", "DES", "MD5", "ANON", "_40_")
# Kuratierte, bekannt schwache Cipher-Suite-IDs (RC4/NULL/EXPORT/DES/anon).
# Bewusst unterhalb der starken Suiten (AES-GCM ab 0x009C, ECDHE-AES ab 0xC013).
_WEAK_CIPHER_IDS = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0009,
    0x000B, 0x000C, 0x000E, 0x000F, 0x0011, 0x0012, 0x0014, 0x0015, 0x0017,
    0x0018, 0x0019, 0x001A, 0x001B, 0x003B,
    0xC001, 0xC002, 0xC006, 0xC007, 0xC00B, 0xC00C, 0xC010, 0xC011,
}
_VOWELS = set("aeiou")


def _host_matches_cert(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for raw in names:
        n = (raw or "").lower().rstrip(".")
        if not n:
            continue
        if n == host:
            return True
        if n.startswith("*.") and host.endswith(n[1:]) and \
                host.count(".") >= n.count("."):
            return True
    return False


def tls_hygiene(packets: list[Packet]) -> list[Finding]:
    """Erkennt veraltete TLS-Versionen, schwache Cipher und Zertifikatsprobleme."""
    out: list[Finding] = []
    sni_by_conn: dict[frozenset, str] = {}
    weak_seen: set = set()
    cipher_seen: set = set()
    for p in packets:
        seg = tcp_segment(p.raw)
        if seg is None:
            continue
        _seq, _ack, _flags, payload = seg
        if len(payload) < 6 or payload[0] != 0x16:        # nur Handshake-Records
            continue
        conn = frozenset({(p.src, p.src_port), (p.dst, p.dst_port)})
        info = tls_info(payload)
        htype = info["type"]
        if htype == "Client Hello" and info["sni"]:
            sni_by_conn[conn] = info["sni"]
        if htype in ("Client Hello", "Server Hello") and \
                info["version"] in _WEAK_TLS_VERSIONS:
            key = (p.src, p.dst, info["version"])
            if key not in weak_seen:
                weak_seen.add(key)
                out.append(Finding(
                    SEV_WARN, "TLS",
                    tr("Veraltete TLS-Version {version}: {src} ⇄ {dst}").format(
                        version=info["version"], src=p.src, dst=p.dst),
                    p.number))
        if htype == "Server Hello" and info["cipher"]:
            cid = info.get("cipher_id")
            weak = (cid in _WEAK_CIPHER_IDS) or any(
                tok in info["cipher"].upper() for tok in _WEAK_CIPHER_TOKENS)
            if weak:
                key = (p.src, p.dst, info["cipher"])
                if key not in cipher_seen:
                    cipher_seen.add(key)
                    out.append(Finding(
                        SEV_WARN, "TLS",
                        tr("Schwache Cipher-Suite {cipher}: {src} → {dst}")
                        .format(cipher=info["cipher"], src=p.src, dst=p.dst),
                        p.number))
        if len(payload) > 5 and payload[5] == 11:          # Certificate
            der = _tls_first_cert(payload)
            d = certinfo.details(der) if der else None
            if not d:
                continue
            subj = d["subject"] or "?"
            if d["self_signed"]:
                out.append(Finding(
                    SEV_NOTE, "TLS",
                    tr("Selbst-signiertes Zertifikat: {subj} ({src})").format(
                        subj=subj, src=p.src), p.number))
            if d["not_after_ts"] < p.ts:
                out.append(Finding(
                    SEV_WARN, "TLS",
                    tr("Abgelaufenes Zertifikat: {subj} (gültig bis {date})")
                    .format(subj=subj, date=d["not_after"]), p.number))
            elif d["not_before_ts"] > p.ts:
                out.append(Finding(
                    SEV_NOTE, "TLS",
                    tr("Zertifikat noch nicht gültig: {subj} (ab {date})")
                    .format(subj=subj, date=d["not_before"]), p.number))
            sni = sni_by_conn.get(conn)
            if sni and d["names"] and not _host_matches_cert(sni, d["names"]):
                out.append(Finding(
                    SEV_NOTE, "TLS",
                    tr("SNI ≠ Zertifikat: angefragt {sni}, Zertifikat {subj}")
                    .format(sni=sni, subj=subj),
                    p.number))
    return out


# --------------------------------------------------------------------------- #
# B — DNS-Auffälligkeiten (DGA, NXDOMAIN-Rate, Amplification)
# --------------------------------------------------------------------------- #
def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_dga(label: str, min_len: int, min_entropy: float) -> bool:
    """Zufällig wirkende Domain: hohe Entropie UND wenig Vokale bzw. viele Ziffern.

    Die Zusatzbedingung verhindert Falschmeldungen bei echten Wörtern (die
    naturgemäß Vokale enthalten, z. B. „stackoverflow")."""
    if len(label) < min_len or _shannon_entropy(label) < min_entropy:
        return False
    letters = [c for c in label if c.isalpha()]
    vowel_ratio = (sum(c in _VOWELS for c in letters) / len(letters)
                   if letters else 0.0)
    digit_ratio = sum(c.isdigit() for c in label) / len(label)
    return vowel_ratio < 0.26 or digit_ratio > 0.25


def dns_anomalies(packets: list[Packet], nx_min: int = 15,
                  dga_min_len: int = 12, dga_entropy: float = 3.4,
                  amp_factor: int = 5) -> list[Finding]:
    """DGA-Verdacht (Hoch-Entropie-Domains), hohe NXDOMAIN-Rate, Amplification."""
    out: list[Finding] = []
    nx_by_host: dict[str, list[int]] = {}     # querier -> [nxdomain, antworten]
    pending_len: dict[tuple, int] = {}        # (txid, name) -> Anfragegröße
    dga_seen: set[str] = set()
    for p in packets:
        if p.src_port not in (53, 5353) and p.dst_port not in (53, 5353):
            continue
        pl = _udp_payload(p.raw)
        if pl is None:
            continue
        msg = parse_dns(pl)
        if msg is None:
            continue
        if not msg.is_response:
            labels = msg.qname.lower().rstrip(".").split(".")
            sld = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
            if (sld and sld not in dga_seen
                    and _looks_dga(sld, dga_min_len, dga_entropy)):
                dga_seen.add(sld)
                out.append(Finding(
                    SEV_NOTE, "DNS",
                    tr("DGA-Verdacht (zufällig wirkende Domain): {name}").format(
                        name=msg.qname)))
            pending_len[(msg.txid, msg.qname.lower())] = len(pl)
        else:
            acc = nx_by_host.setdefault(p.dst, [0, 0])
            acc[1] += 1
            if msg.rcode == 3:
                acc[0] += 1
            qlen = pending_len.pop((msg.txid, msg.qname.lower()), None)
            if qlen and len(pl) >= max(512, qlen * amp_factor):
                out.append(Finding(
                    SEV_NOTE, "DNS",
                    tr("DNS-Amplification: Antwort {resp} B ≫ Anfrage {req} B "
                       "({name})").format(resp=len(pl), req=qlen, name=msg.qname),
                    p.number))
    for host, (nx, total) in nx_by_host.items():
        if total >= 20 and nx >= nx_min and nx / total >= 0.5:
            out.append(Finding(
                SEV_WARN, "DNS",
                tr("Hohe NXDOMAIN-Rate: {host} erhielt {nx}/{total} NXDOMAIN "
                   "(nicht gefunden) – DGA-/Schadsoftware-Verdacht").format(
                    host=host, nx=nx, total=total)))
    return out


# --------------------------------------------------------------------------- #
# C — Scan- & Verbindungsverhalten
# --------------------------------------------------------------------------- #
_RISKY_PORTS = {
    23: "Telnet", 2323: "Telnet", 512: "rexec", 513: "rlogin", 514: "rsh",
    3389: "RDP", 5900: "VNC", 445: "SMB", 139: "NetBIOS", 1433: "MSSQL",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    9200: "Elasticsearch", 4444: "Metasploit", 31337: "Back-Orifice",
}


def connection_anomalies(packets: list[Packet], half_open_min: int = 20,
                         fail_min: int = 20) -> list[Finding]:
    """SYN-Flood/Half-Open, Verbindungs-Fehlerrate, riskante Ziel-Ports."""
    out: list[Finding] = []
    syn_sent: dict[str, int] = {}
    synack_to: dict[str, int] = {}        # SYN/ACK-Empfänger (= Client)
    rst_to: dict[str, int] = {}
    risky_seen: set = set()
    for p in packets:
        seg = tcp_segment(p.raw)
        if seg is None:
            continue
        _seq, _ack, flags, _payload = seg
        is_syn = bool(flags & SYN) and not (flags & ACK)
        is_synack = bool(flags & SYN) and bool(flags & ACK)
        if is_syn:
            syn_sent[p.src] = syn_sent.get(p.src, 0) + 1
            dp = p.dst_port
            if dp in _RISKY_PORTS:
                key = (p.src, p.dst, dp)
                if key not in risky_seen:
                    risky_seen.add(key)
                    public = is_public(p.dst) or is_public(p.src)
                    if dp in (23, 2323):
                        out.append(Finding(
                            SEV_WARN, "Security",
                            tr("Telnet (Klartext-Login): {src} → {dst} – "
                               "Anmeldedaten werden unverschlüsselt übertragen")
                            .format(src=p.src, dst=p.dst),
                            p.number))
                    else:
                        out.append(Finding(
                            SEV_WARN if public else SEV_NOTE, "Security",
                            tr("Verbindung zu riskantem Dienst "
                               "{service} (Port {port}): {src} → {dst}").format(
                                service=_RISKY_PORTS[dp], port=dp,
                                src=p.src, dst=p.dst),
                            p.number))
        elif is_synack:
            synack_to[p.dst] = synack_to.get(p.dst, 0) + 1
        if flags & RST:
            rst_to[p.dst] = rst_to.get(p.dst, 0) + 1
    for src, sent in syn_sent.items():
        got = synack_to.get(src, 0)
        if sent >= half_open_min and got < sent * 0.5:
            out.append(Finding(
                SEV_WARN, "Security",
                tr("Viele unvollständige Verbindungen (SYN-Flood/Half-Open): "
                   "{src} sendete {sent} SYN, erhielt nur {got} SYN/ACK").format(
                    src=src, sent=sent, got=got)))
    for host, rst in rst_to.items():
        if rst >= fail_min:
            out.append(Finding(
                SEV_NOTE, "TCP",
                tr("Hohe Verbindungs-Fehlerrate: {host} erhielt {rst} RST").format(
                    host=host, rst=rst)))
    return out


# --------------------------------------------------------------------------- #
# D — Volumen / DoS / Tunneling
# --------------------------------------------------------------------------- #
def _icmp_echo_payload(raw: bytes) -> bytes | None:
    if len(raw) < 20 or (raw[0] >> 4) != 4 or raw[9] != 1:
        return None
    ihl = max(20, min(_ihl(raw), len(raw)))
    icmp = raw[ihl:]
    if len(icmp) < 8 or icmp[0] not in (0, 8):           # nur Echo Request/Reply
        return None
    return icmp[8:]


def traffic_anomalies(packets: list[Packet], pps_min: int = 2000,
                      icmp_payload_min: int = 120,
                      icmp_count_min: int = 10) -> list[Finding]:
    """Traffic-Spitzen/Floods, ICMP-Tunneling, NTP-Amplification (monlist)."""
    out: list[Finding] = []
    pps_bucket: dict[tuple, int] = {}        # (src, Sekunde) -> Pakete
    icmp_big: dict[str, int] = {}
    ntp_mode7: set = set()
    for p in packets:
        pps_bucket[(p.src, int(p.ts))] = pps_bucket.get((p.src, int(p.ts)), 0) + 1
        if p.l4 == "ICMP":
            pl = _icmp_echo_payload(p.raw)
            if pl is not None and len(pl) >= icmp_payload_min:
                icmp_big[p.src] = icmp_big.get(p.src, 0) + 1
        if p.src_port == 123 or p.dst_port == 123:
            pl = _udp_payload(p.raw)
            if pl and (pl[0] & 0x07) == 7:               # NTP mode 7 (privat)
                ntp_mode7.add((p.src, p.dst))
    peak: dict[str, int] = {}
    for (src, _sec), cnt in pps_bucket.items():
        if cnt > peak.get(src, 0):
            peak[src] = cnt
    for src, cnt in peak.items():
        if cnt >= pps_min:
            out.append(Finding(
                SEV_WARN, "Security",
                tr("Traffic-Spitze/Flood: {src} mit {cnt} Paketen/s").format(
                    src=src, cnt=cnt)))
    for src, cnt in icmp_big.items():
        if cnt >= icmp_count_min:
            out.append(Finding(
                SEV_WARN, "Security",
                tr("Mögliches ICMP-Tunneling: {src} – {cnt} Echo-Pakete mit "
                   "großer Nutzlast (≥{size} B)").format(
                    src=src, cnt=cnt, size=icmp_payload_min)))
    for src, dst in ntp_mode7:
        out.append(Finding(
            SEV_WARN, "Security",
            tr("NTP mode 7 (monlist) – Amplification-Risiko: {src} ⇄ {dst}")
            .format(src=src, dst=dst)))
    return out


# --------------------------------------------------------------------------- #
# Service-Response-Time (Request↔Response-Latenz je Protokoll)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class SrtStat:
    protocol: str
    count: int
    avg_ms: float
    min_ms: float
    max_ms: float


def _smb2_ids(payload: bytes):
    d = payload
    if len(d) >= 8 and d[0] == 0x00 and d[4:8] == b"\xfeSMB":
        d = d[4:]
    if d[:4] == b"\xfeSMB" and len(d) >= 48:
        flags = int.from_bytes(d[16:20], "little")
        mid = int.from_bytes(d[24:32], "little")
        sid = int.from_bytes(d[40:48], "little")
        return flags, mid, sid
    return None


def service_response_times(packets: list[Packet]) -> list[SrtStat]:
    """Antwortzeiten (ms) je Protokoll: DNS (txid), HTTP (Reihenfolge), SMB2 (MID)."""
    dns_rt, http_rt, smb_rt = [], [], []
    dns_pending: dict = {}
    http_pending: dict = {}
    smb_pending: dict = {}
    for p in sorted(packets, key=lambda x: (x.ts, x.number)):
        if p.src_port == 53 or p.dst_port == 53:
            pl = _udp_payload(p.raw)
            msg = parse_dns(pl) if pl else None
            if msg:
                key = (msg.txid, msg.qname.lower())
                if msg.is_response:
                    t0 = dns_pending.pop(key, None)
                    if t0 is not None:
                        dns_rt.append((p.ts - t0) * 1000.0)
                else:
                    dns_pending[key] = p.ts
        elif p.protocol == "HTTP":
            seg = tcp_segment(p.raw)
            if seg:
                first = seg[3][:64].split(b"\r\n", 1)[0]
                _l4, a, b = _conv_key(p)
                if first.startswith(b"HTTP/"):           # Antwort
                    q = http_pending.get((a, b))
                    if q:
                        http_rt.append((p.ts - q.pop(0)) * 1000.0)
                else:                                    # Anfrage
                    http_pending.setdefault((a, b), []).append(p.ts)
        elif p.protocol == "SMB2":
            seg = tcp_segment(p.raw)
            ids = _smb2_ids(seg[3]) if seg else None
            if ids:
                flags, mid, sid = ids
                if flags & 0x1:                          # Antwort
                    t0 = smb_pending.pop((sid, mid), None)
                    if t0 is not None:
                        smb_rt.append((p.ts - t0) * 1000.0)
                else:
                    smb_pending[(sid, mid)] = p.ts
    out = []
    for proto, rts in (("DNS", dns_rt), ("HTTP", http_rt), ("SMB2", smb_rt)):
        if rts:
            out.append(SrtStat(proto, len(rts), sum(rts) / len(rts),
                               min(rts), max(rts)))
    return out


# --------------------------------------------------------------------------- #
# TCP-Expert-Flags je Paket (Retransmission / Dup-ACK / Out-of-Order)
# --------------------------------------------------------------------------- #
def tcp_expert_flags(packets: list[Packet]) -> dict[int, str]:
    """Markiert je TCP-Paket Auffälligkeiten → ``{Paketnummer: Flag-Text}``."""
    seen: dict[tuple, set] = {}          # Richtung → {(seq,len)}
    last_ack: dict[tuple, list] = {}     # Richtung → [ack, count]
    high: dict[tuple, int] = {}          # Richtung → höchstes seq-Ende
    flags: dict[int, str] = {}
    for p in sorted(packets, key=lambda x: (x.ts, x.number)):
        seg = _parse_tcp(p.raw)
        if seg is None:
            continue
        seq, ack, fl, _win, payload = seg
        d = (p.src, p.src_port, p.dst, p.dst_port)
        if payload:
            sset = seen.setdefault(d, set())
            sig = (seq, len(payload))
            if sig in sset:
                flags[p.number] = tr(
                    "Retransmission – Segment Seq={seq} ({n} Bytes) "
                    "wurde bereits gesendet (vermutlich Paketverlust)").format(
                    seq=seq, n=len(payload))
            else:
                sset.add(sig)
                hi = high.get(d)
                if hi is not None and seq < hi:
                    flags[p.number] = tr(
                        "Out-of-Order – Seq={seq} liegt vor dem bereits "
                        "empfangenen Ende {hi} (Segment kam verspätet/vertauscht)"
                    ).format(seq=seq, hi=hi)
                high[d] = max(hi or 0, seq + len(payload))
        elif fl & ACK:
            la = last_ack.get(d)
            if la is not None and la[0] == ack:
                la[1] += 1
                flags[p.number] = tr(
                    "Dup-ACK #{n} – ACK={ack} wiederholt; der Empfänger "
                    "fordert ein fehlendes Segment erneut an").format(
                    n=la[1], ack=ack)
            else:
                last_ack[d] = [ack, 0]
    return flags
