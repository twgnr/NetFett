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


def tcp_segment(raw: bytes) -> tuple[int, int, int, bytes] | None:
    """(seq, ack, flags, payload) eines TCP-Pakets oder ``None``.

    Erwartet Rohbytes ab dem IPv4-Kopf (so liefert sie der Raw-Socket)."""
    if len(raw) < 20 or (raw[0] >> 4) != 4 or raw[9] != 6:
        return None
    ihl = max(20, min(_ihl(raw), len(raw)))
    tcp = raw[ihl:]
    if len(tcp) < 20:
        return None
    seq, ack = struct.unpack("!II", tcp[4:12])
    data_off = max(20, min((tcp[12] >> 4) * 4, len(tcp)))
    flags = tcp[13]
    return seq, ack, flags, tcp[data_off:]


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

    return findings
