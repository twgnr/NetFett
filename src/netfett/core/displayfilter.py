"""Einfacher, robuster Anzeigefilter (Display Filter) für die Paketliste.

Bewusst kompakt statt einer vollständigen Wireshark-Filtersprache – aber genau
die Ausdrücke, die man täglich braucht:

  * Protokoll-Schlüsselwörter:  ``tcp udp icmp dns tls http https mdns``
  * ``host <ip>``   – Quelle ODER Ziel
  * ``src <ip>`` / ``dst <ip>``
  * ``port <n>``    – Quell- ODER Ziel-Port
  * ``src port <n>`` / ``dst port <n>``
  * ``in`` / ``out`` – Richtung
  * Freitext        – Teilstring in Quelle/Ziel/Info/Protokoll

Mehrere Begriffe mit Leerzeichen = UND.  ``or`` trennt Alternativen,
``not`` / ``!`` negiert den folgenden Begriff.  Beispiel::

    tcp dst port 443 not src 192.168.0.10
    dns or mdns
"""
from __future__ import annotations

from .models import DIR_IN, DIR_OUT, Packet

_PROTO_WORDS = {"tcp", "udp", "icmp", "dns", "mdns", "tls", "http", "https",
                "arp", "igmp", "smtp", "imap", "pop3", "ftp", "ssh", "mail"}


class FilterError(ValueError):
    pass


def compile_filter(text: str):
    """Übersetzt den Filtertext in eine Funktion ``Packet -> bool``.

    Leerer Text -> ``None`` (alles anzeigen)."""
    text = (text or "").strip()
    if not text:
        return None
    # ODER-Gruppen auf oberster Ebene.
    or_groups = [g.strip() for g in _split_keyword(text, "or") if g.strip()]
    compiled_groups = [_compile_and_group(g) for g in or_groups]

    def match(pkt: Packet) -> bool:
        return any(g(pkt) for g in compiled_groups)

    return match


def _split_keyword(text: str, kw: str) -> list[str]:
    out, cur = [], []
    for tok in text.split():
        if tok.lower() == kw:
            out.append(" ".join(cur))
            cur = []
        else:
            cur.append(tok)
    out.append(" ".join(cur))
    return out


def _compile_and_group(text: str):
    """Eine UND-Gruppe aus einzelnen (ggf. negierten) Termen."""
    tokens = text.split()
    terms = []
    i = 0
    while i < len(tokens):
        negate = False
        tok = tokens[i].lower()
        if tok in ("not", "!"):
            negate = True
            i += 1
            if i >= len(tokens):
                break
            tok = tokens[i].lower()

        # zwei-/dreiteilige Ausdrücke
        if tok in ("src", "dst") and i + 1 < len(tokens) and tokens[i + 1].lower() == "port":
            value = tokens[i + 2] if i + 2 < len(tokens) else ""
            term = _make_port(value, side=tok)
            i += 3
        elif tok in ("src", "dst") and i + 1 < len(tokens):
            term = _make_addr(tokens[i + 1], side=tok)
            i += 2
        elif tok == "host" and i + 1 < len(tokens):
            term = _make_addr(tokens[i + 1], side="host")
            i += 2
        elif tok == "port" and i + 1 < len(tokens):
            term = _make_port(tokens[i + 1], side="any")
            i += 2
        elif tok in ("in", "out"):
            term = _make_dir(tok)
            i += 1
        elif tok in _PROTO_WORDS:
            term = _make_proto(tok)
            i += 1
        else:
            term = _make_text(tokens[i])  # Originalschreibweise für Freitext
            i += 1

        terms.append((negate, term))

    def match(pkt: Packet) -> bool:
        for negate, term in terms:
            ok = term(pkt)
            if negate:
                ok = not ok
            if not ok:
                return False
        return True

    return match


def _make_proto(word: str):
    word = word.lower()

    def term(pkt: Packet) -> bool:
        p = (pkt.protocol or "").lower()
        l4 = (pkt.l4 or "").lower()
        if word == "https":
            return p == "tls" or pkt.src_port == 443 or pkt.dst_port == 443
        if word == "mail":
            return p in ("smtp", "imap", "pop3")
        return word == p or word == l4
    return term


def _make_addr(value: str, side: str):
    def term(pkt: Packet) -> bool:
        if side == "src":
            return pkt.src == value
        if side == "dst":
            return pkt.dst == value
        return value in (pkt.src, pkt.dst)
    return term


def _make_port(value: str, side: str):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise FilterError(f"Ungültiger Port: {value!r}")

    def term(pkt: Packet) -> bool:
        if side == "src":
            return pkt.src_port == port
        if side == "dst":
            return pkt.dst_port == port
        return port in (pkt.src_port, pkt.dst_port)
    return term


def _make_dir(word: str):
    want = DIR_OUT if word == "out" else DIR_IN

    def term(pkt: Packet) -> bool:
        return pkt.direction == want
    return term


def _make_text(value: str):
    needle = value.lower()

    def term(pkt: Packet) -> bool:
        return (needle in pkt.src.lower() or needle in pkt.dst.lower()
                or needle in (pkt.info or "").lower()
                or needle in (pkt.protocol or "").lower()
                or needle in (pkt.domain or "").lower()
                or needle in (pkt.process or "").lower())
    return term
