"""Aktive Netzwerk-Werkzeuge: DNS-Lookup, ICMP-Ping und Traceroute.

Nur Standardbibliothek. Die **reinen** Bausteine (Prüfsumme, ICMP-Bau/-Parser)
sind unit-testbar; die eigentlichen Sende-/Empfangsfunktionen nutzen Sockets.

Hinweis: Ping/Traceroute benötigen unter Windows einen Raw-Socket
(``SOCK_RAW``, ``IPPROTO_ICMP``) und damit **Administratorrechte**. Der
DNS-Lookup kommt ohne erhöhte Rechte aus.
"""
from __future__ import annotations

import os
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_ECHO = 8
ICMP_TIME_EXCEEDED = 11


# --------------------------------------------------------------------------- #
# Reine Bausteine (testbar)
# --------------------------------------------------------------------------- #
def checksum(data: bytes) -> int:
    """Internet-Prüfsumme (RFC 1071) über ``data``."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def build_icmp_echo(ident: int, seq: int, payload: bytes = b"netfett-ping") -> bytes:
    """Erzeugt ein ICMP-Echo-Request-Paket mit korrekter Prüfsumme."""
    head = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    chk = checksum(head + payload)
    head = struct.pack("!BBHHH", ICMP_ECHO, 0, chk, ident & 0xFFFF, seq & 0xFFFF)
    return head + payload


def parse_icmp_reply(data: bytes) -> tuple[int, int, int | None, int | None] | None:
    """Zerlegt eine empfangene ICMP-Antwort (inkl. IPv4-Kopf).

    Liefert ``(typ, code, ident, seq)``. Bei „Time Exceeded"/„Unreachable"
    werden ident/seq aus dem eingebetteten Original-Echo gelesen (für
    Traceroute), sonst ``None``."""
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    icmp = data[ihl:]
    if len(icmp) < 8:
        return None
    itype, icode = icmp[0], icmp[1]
    if itype == ICMP_ECHO_REPLY:
        ident, seq = struct.unpack("!HH", icmp[4:8])
        return itype, icode, ident, seq
    if itype in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH):
        embedded = icmp[8:]                       # Original-IP-Kopf + 8 Byte
        if len(embedded) >= 20:
            eihl = (embedded[0] & 0x0F) * 4
            orig = embedded[eihl:]
            if len(orig) >= 8 and orig[0] == ICMP_ECHO:
                ident, seq = struct.unpack("!HH", orig[4:8])
                return itype, icode, ident, seq
        return itype, icode, None, None
    return itype, icode, None, None


# --------------------------------------------------------------------------- #
# DNS-Lookup (keine erhöhten Rechte nötig)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class DnsResult:
    query: str
    addresses: list[str] = field(default_factory=list)
    reverse: dict[str, str] = field(default_factory=dict)
    error: str = ""


def dns_lookup(name: str) -> DnsResult:
    """Vorwärts-Auflösung (Name → IPs) plus Reverse-DNS je gefundener IP."""
    try:
        infos = socket.getaddrinfo(name, None)
    except socket.gaierror as exc:
        return DnsResult(name, error=str(exc))
    addrs = sorted({info[4][0] for info in infos})
    reverse: dict[str, str] = {}
    for addr in addrs:
        try:
            reverse[addr] = socket.gethostbyaddr(addr)[0]
        except (OSError, socket.herror):
            reverse[addr] = ""
    return DnsResult(name, addrs, reverse)


# --------------------------------------------------------------------------- #
# ICMP-Ping (Raw-Socket → Administratorrechte)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class PingSummary:
    host: str
    address: str
    rtts: list[float | None] = field(default_factory=list)   # ms, None = Timeout

    @property
    def sent(self) -> int:
        return len(self.rtts)

    @property
    def received(self) -> int:
        return sum(1 for r in self.rtts if r is not None)

    @property
    def loss_pct(self) -> float:
        return 100.0 * (self.sent - self.received) / self.sent if self.sent else 0.0


def ping(host: str, count: int = 4, timeout: float = 1.0,
         on_result: Callable[[int, float | None, str], None] | None = None
         ) -> PingSummary:
    """Sendet ``count`` ICMP-Echos und misst die RTT je Antwort (ms)."""
    dest = socket.gethostbyname(host)
    ident = os.getpid() & 0xFFFF
    summary = PingSummary(host, dest)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        for seq in range(1, count + 1):
            sock.sendto(build_icmp_echo(ident, seq), (dest, 0))
            rtt = _await_echo(sock, ident, seq, timeout)
            summary.rtts.append(rtt)
            if on_result is not None:
                on_result(seq, rtt, dest)
            if seq < count:
                time.sleep(0.2)
    finally:
        sock.close()
    return summary


def _await_echo(sock, ident: int, seq: int, timeout: float) -> float | None:
    start = time.time()
    while True:
        remaining = timeout - (time.time() - start)
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data, _addr = sock.recvfrom(2048)
        except socket.timeout:
            return None
        reply = parse_icmp_reply(data)
        if reply and reply[0] == ICMP_ECHO_REPLY and reply[2] == ident \
                and reply[3] == seq:
            return (time.time() - start) * 1000.0


# --------------------------------------------------------------------------- #
# Traceroute (Raw-Socket → Administratorrechte)
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Hop:
    ttl: int
    address: str | None
    rtt_ms: float | None


def traceroute(host: str, max_hops: int = 30, timeout: float = 1.0,
               on_hop: Callable[[Hop], None] | None = None) -> list[Hop]:
    """Verfolgt den Pfad zum Ziel über aufsteigende TTL der Echo-Requests."""
    dest = socket.gethostbyname(host)
    ident = os.getpid() & 0xFFFF
    hops: list[Hop] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        for ttl in range(1, max_hops + 1):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            start = time.time()
            sock.sendto(build_icmp_echo(ident, ttl), (dest, 0))
            hop = _await_hop(sock, ident, ttl, timeout, start)
            hops.append(hop)
            if on_hop is not None:
                on_hop(hop)
            if hop.address == dest:
                break
    finally:
        sock.close()
    return hops


def _await_hop(sock, ident: int, ttl: int, timeout: float, start: float) -> Hop:
    while True:
        remaining = timeout - (time.time() - start)
        if remaining <= 0:
            return Hop(ttl, None, None)
        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            return Hop(ttl, None, None)
        reply = parse_icmp_reply(data)
        if reply and (reply[3] == ttl or reply[2] == ident):
            return Hop(ttl, addr[0], (time.time() - start) * 1000.0)
