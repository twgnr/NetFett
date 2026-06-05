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
import struct
from dataclasses import dataclass, field

from .models import Packet

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
                    SEV_WARN, "ICMP", pkt.info or "ICMP-Fehler", pkt.number))
            continue

        seg = tcp_segment(pkt.raw)
        if seg is None:
            continue
        seq, _ack, flags, payload = seg

        if flags & RST:
            findings.append(Finding(
                SEV_NOTE, "TCP", f"Verbindungs-Reset (RST) {pkt.src} → {pkt.dst}",
                pkt.number))

        # Retransmission: identisches (seq, len) mit Nutzdaten erneut gesehen.
        if payload:
            key = (pkt.src, pkt.src_port, pkt.dst, pkt.dst_port)
            sset = seen_seq.setdefault(key, set())
            sig = (seq, len(payload))
            if sig in sset:
                findings.append(Finding(
                    SEV_WARN, "TCP",
                    f"Mögliche Retransmission (seq={seq}, len={len(payload)})",
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
                f"Möglicher Port-Scan: {src} sendete SYN an {len(ports)} Ports"))
    for src, hosts in syn_hosts.items():
        if len(hosts) >= scan_host_threshold:
            findings.append(Finding(
                SEV_ERROR, "Security",
                f"Möglicher Host-Scan: {src} sendete SYN an {len(hosts)} Hosts"))

    findings.extend(beaconing(packets))
    findings.extend(credentials(packets))
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
                f"Mögliches Beaconing: {src} → {dst}:{dport} "
                f"alle ~{mean:.1f}s ({len(times)}×, CV={cv:.2f})"))
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
                    f"HTTP Basic-Auth im Klartext: {decoded} "
                    f"({pkt.src} → {pkt.dst})", pkt.number))

        if pkt.dst_port == 21 or pkt.src_port == 21:
            line = payload.split(b"\r\n", 1)[0]
            tag = line[:5].upper()
            if tag in (b"USER ", b"PASS "):
                value = line[5:].decode("latin-1", "replace")
                kind = "Benutzer" if tag == b"USER " else "Passwort"
                sev = SEV_NOTE if tag == b"USER " else SEV_ERROR
                out.append(Finding(
                    sev, "Security",
                    f"FTP-{kind} im Klartext: {value} ({pkt.src} → {pkt.dst})",
                    pkt.number))
    return out
