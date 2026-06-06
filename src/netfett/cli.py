"""Kopfloser (Headless-)Modus von NetFett – Capture lesen, analysieren, exportieren.

Beispiele:
    python -m netfett --read mitschnitt.pcapng --stats
    python -m netfett --read x.pcap --export verb.csv --what conversations
"""
from __future__ import annotations

import argparse

from .core.analyze import conversations
from .core.dissect import dissect
from .core.export import export_conversations, export_domains, export_packets
from .core.pcap import merge_captures, read_capture
from .core.stats import Stats


def is_headless(argv) -> bool:
    return "--read" in argv


def _load(paths) -> list:
    records = merge_captures(paths) if len(paths) > 1 else read_capture(paths[0])
    return [dissect(raw, ts, i + 1) for i, (ts, raw) in enumerate(records)]


def run_cli(argv) -> int:
    ap = argparse.ArgumentParser(prog="netfett", add_help=True,
                                 description="NetFett – Headless-Analyse")
    ap.add_argument("--read", nargs="+", metavar="DATEI", required=True,
                    help="Capture-Datei(en) (pcap/pcapng); mehrere = zusammenführen")
    ap.add_argument("--stats", action="store_true", help="Zusammenfassung ausgeben")
    ap.add_argument("--export", metavar="DATEI", help="Analyse exportieren")
    ap.add_argument("--what", choices=["packets", "conversations", "domains"],
                    default="packets")
    ap.add_argument("--format", choices=["csv", "json"], default="csv")
    args = ap.parse_args(argv)

    try:
        packets = _load(args.read)
    except (OSError, ValueError) as exc:
        print(f"Fehler beim Lesen: {exc}")
        return 2
    print(f"{len(packets)} Pakete gelesen aus {', '.join(args.read)}")

    if args.stats or not args.export:
        _print_stats(packets)

    if args.export:
        builder = {"packets": export_packets, "conversations": export_conversations,
                   "domains": export_domains}[args.what]
        try:
            with open(args.export, "w", encoding="utf-8", newline="") as f:
                f.write(builder(packets, args.format))
        except OSError as exc:
            print(f"Export fehlgeschlagen: {exc}")
            return 2
        print(f"Export ({args.what}/{args.format}) → {args.export}")
    return 0


def _print_stats(packets) -> None:
    stats = Stats()
    for p in packets:
        stats.add(p)
    print(f"  Bytes gesamt: {stats.total_bytes}")
    print("  Top-Protokolle:")
    for name, pk, by in stats.top_protocols(8):
        print(f"    {name:<10} {pk:>7} Pakete  {by:>10} Bytes")
    convs = conversations(packets)
    print(f"  Verbindungen: {len(convs)}")
    for c in convs[:8]:
        ap = f":{c.a_port}" if c.a_port else ""
        bp = f":{c.b_port}" if c.b_port else ""
        print(f"    {c.proto:<5} {c.a}{ap} <-> {c.b}{bp}  "
              f"{c.packets} Pakete / {c.bytes} Bytes")
