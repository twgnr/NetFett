"""Englische Texte für Paketliste, Diagramme, Geräte-, Werkzeug- und Profi-Dialoge."""

MESSAGES = {
    # packet_model.py – Spaltenköpfe (COLUMNS bleibt deutsch, Anzeige übersetzt)
    "Nr.": "No.",
    "Zeit": "Time",
    "Quelle": "Source",
    "Ziel": "Destination",
    "Protokoll": "Protocol",
    "Länge": "Length",
    "Ri.": "Dir.",
    "Info": "Info",
    "Name": "Name",
    "Programm": "Program",

    # capture_controller.py
    "[reassembliert: {count} Fragmente]": "[reassembled: {count} fragments]",

    # charts.py / allgemein
    "keine Daten": "no data",
    "gesamt": "total",

    # devices_dialog.py
    "Doppelklick: Hauptansicht auf dieses Gerät filtern":
        "Double-click: filter main view to this device",
    "Geräte-Übersicht": "Devices",
    "Netzwerk scannen": "Scan network",
    "ICMP-Ping-Sweep des lokalen /24 (Adminrechte)":
        "ICMP ping sweep of the local /24 (requires admin rights)",
    "Geräte aus dem Verkehr werden live angezeigt.":
        "Devices seen in traffic are shown live.",
    "Kein lokales Subnetz erkannt.": "No local subnet detected.",
    "Scanne {n} Adressen …": "Scanning {n} addresses …",
    "Scan benötigt Administratorrechte.": "Scan requires administrator rights.",
    "Scan fehlgeschlagen (Netzwerkfehler).": "Scan failed (network error).",
    "{n} Gerät(e) gefunden.": "{n} device(s) found.",

    # tools_dialogs.py
    "Ziel:": "Target:",
    "  Antwort von {addr}: seq={seq}  ": "  Reply from {addr}: seq={seq}  ",
    "Zeitüberschreitung": "timed out",
    "Fehler: Ping benötigt Administratorrechte.":
        "Error: ping requires administrator rights.",
    "Fehler: {exc}": "Error: {exc}",
    "{received}/{sent} Antworten, {loss:.0f}% Verlust":
        "{received}/{sent} replies, {loss:.0f}% loss",
    "Traceroute zu {host} (max. 30 Hops) …": "Traceroute to {host} (max. 30 hops) …",
    "*  (keine Antwort)": "*  (no reply)",
    "Fehler: Traceroute benötigt Administratorrechte.":
        "Error: traceroute requires administrator rights.",
    "Fertig.": "Done.",
    "DNS-Lookup": "DNS Lookup",
    "Auflösung von {host} …": "Resolving {host} …",
    "{n} Adresse(n).": "{n} address(es).",

    # pro_dialogs.py – Einfärbe-Regeln
    "Regel bearbeiten": "Edit Rule",
    "Name:": "Name:",
    "Filter:": "Filter:",
    "z. B.  tcp dst port 443": "e.g.  tcp dst port 443",
    "Hintergrund": "Background",
    "Farbe…": "Color…",
    "Schriftfarbe": "Foreground",
    "Farbe wählen": "Choose Color",
    "Regel": "Rule",
    "Einfärbe-Regeln": "Coloring Rules",
    "Erste passende Regel bestimmt die Farbe (von oben nach unten).":
        "The first matching rule determines the color (top to bottom).",
    "Aktiv": "Enabled",
    "Filter": "Filter",
    "Neu": "New",
    "Bearbeiten": "Edit",
    "Entfernen": "Remove",
    "Neue Regel": "New rule",
    # Standard-Regelnamen aus core.coloring (nur Anzeige)
    "Fehler/Reset": "Errors/Reset",

    # pro_dialogs.py – IO-Graph
    "IO-Graph": "I/O Graph",
    "Durchsatz": "Throughput",
    "Filter-Linien (leer = alles):": "Filter lines (empty = all):",
    "Filter {n}, z. B. tcp / dns / host 1.1.1.1":
        "Filter {n}, e.g. tcp / dns / host 1.1.1.1",
    "Einheit:": "Unit:",
    "Bytes/s": "Bytes/s",
    "Pakete/s": "Packets/s",
    "Aktualisieren": "Refresh",
    "Alle": "All",

    # pro_dialogs.py – IOC-Abgleich
    "IOC-Abgleich": "IOC Matching",
    "Blockliste laden…": "Load blocklist…",
    "Liste laden (eine IP/CIDR/Domain je Zeile, # = Kommentar).":
        "Load a list (one IP/CIDR/domain per line, # = comment).",
    "Schwere": "Severity",
    "Indikator/Beschreibung": "Indicator/Description",
    "Paket": "Packet",
    "Treffer markieren": "Mark matches",
    "Blockliste laden": "Load Blocklist",
    "Textdateien (*.txt *.ioc *.csv);;Alle Dateien (*)":
        "Text files (*.txt *.ioc *.csv);;All files (*)",
    "NetFett – Fehler": "NetFett – Error",
    "Keine Indikatoren gefunden.": "No indicators found.",
    "{n} Treffer.": "{n} match(es).",
    "{n} Treffer markiert.": "{n} match(es) marked.",

    # pro_dialogs.py – Topologie
    "Netzwerk-Topologie": "Network Topology",
    "{nodes} Hosts, {edges} Verbindungen  (gelb = lokal, grün = entfernt; "
    "Kantendicke = Volumen)":
        "{nodes} hosts, {edges} connections  (yellow = local, green = remote; "
        "edge width = volume)",

    # pro_dialogs.py – Objekte exportieren
    "Extrahierte Objekte": "Extracted Objects",
    "{n} Objekt(e) aus dem HTTP-Verkehr": "{n} object(s) from HTTP traffic",
    "URL/Quelle": "URL/Source",
    "Typ": "Type",
    "Größe": "Size",
    "Speichern…": "Save…",
    "Alle speichern…": "Save all…",
    "Objekt speichern": "Save Object",
    "Zielordner wählen": "Choose Target Folder",

    # pro_dialogs.py – TCP-Stream-Graph
    "0 … {tmax:.2f} s   (blau=Client, orange=Server)":
        "0 … {tmax:.2f} s   (blue=client, orange=server)",
    "TCP-Stream-Graph": "TCP Stream Graph",
    "Darstellung:": "View:",
    "Sequenznummer": "Sequence number",
    "Durchsatz (B/s)": "Throughput (B/s)",
    "Window": "Window",

    # pro_dialogs.py – Decode As
    "Port wird als gewähltes Protokoll zerlegt:":
        "Port is dissected as the chosen protocol:",
    "Hinzufügen": "Add",
    "Als Protokoll:": "As protocol:",

    # pro_dialogs.py – Flow-Graph
    "Flow-Graph": "Flow Graph",
    "{events} Pakete zwischen {hosts} Top-Hosts (max. {max})":
        "{events} packets between {hosts} top hosts (max. {max})",
}
