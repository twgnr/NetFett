"""Export erfasster Daten nach CSV oder JSON – rein (keine GUI/Sockets).

Drei Datensätze: die Paketliste, die Verbindungen (Conversations) und die
kontaktierten Domains. Jede ``export_*``-Funktion liefert den fertigen Text;
das Schreiben in eine Datei übernimmt die GUI.
"""
from __future__ import annotations

import csv
import io
import json

from .analyze import conversations, domains
from .models import Packet

CSV, JSON = "csv", "json"

_PACKET_FIELDS = ["number", "time", "src", "src_port", "dst", "dst_port",
                  "protocol", "l4", "length", "direction", "domain", "info"]
_CONV_FIELDS = ["proto", "endpoint_a", "endpoint_b", "packets", "bytes",
                "a2b_packets", "a2b_bytes", "b2a_packets", "b2a_bytes",
                "duration_s", "bits_per_s"]
_DOMAIN_FIELDS = ["domain", "packets", "protocols"]


def export_packets(packets: list[Packet], fmt: str = CSV) -> str:
    return _format(_PACKET_FIELDS, [_packet_dict(p) for p in packets], fmt)


def export_conversations(packets: list[Packet], fmt: str = CSV) -> str:
    return _format(_CONV_FIELDS, [_conv_dict(c) for c in conversations(packets)],
                   fmt)


def export_domains(packets: list[Packet], fmt: str = CSV) -> str:
    return _format(_DOMAIN_FIELDS, [_domain_dict(d) for d in domains(packets)],
                   fmt)


# --- Datensatz-Bausteine --------------------------------------------------- #
def _packet_dict(p: Packet) -> dict:
    return {
        "number": p.number, "time": round(p.ts, 6),
        "src": p.src, "src_port": p.src_port if p.src_port is not None else "",
        "dst": p.dst, "dst_port": p.dst_port if p.dst_port is not None else "",
        "protocol": p.protocol, "l4": p.l4, "length": p.length,
        "direction": p.direction, "domain": p.domain, "info": p.info,
    }


def _ep(ip: str, port) -> str:
    return f"{ip}:{port}" if port is not None else ip


def _conv_dict(c) -> dict:
    return {
        "proto": c.proto,
        "endpoint_a": _ep(c.a, c.a_port), "endpoint_b": _ep(c.b, c.b_port),
        "packets": c.packets, "bytes": c.bytes,
        "a2b_packets": c.a2b_pkts, "a2b_bytes": c.a2b_bytes,
        "b2a_packets": c.b2a_pkts, "b2a_bytes": c.b2a_bytes,
        "duration_s": round(c.duration, 6), "bits_per_s": round(c.bps, 1),
    }


def _domain_dict(d) -> dict:
    return {"domain": d.name, "packets": d.packets,
            "protocols": ";".join(d.protocols)}


# --- Formatierung ---------------------------------------------------------- #
def _format(fields: list[str], records: list[dict], fmt: str) -> str:
    if fmt == JSON:
        return json.dumps(records, indent=2, ensure_ascii=False)
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(fields)
    for rec in records:
        writer.writerow([rec[f] for f in fields])
    return buf.getvalue()
