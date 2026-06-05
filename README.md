# NetFett

**NetFett** ist ein schlanker, Wireshark-ähnlicher Netzwerk-Monitor in **reinem
Python** mit **PySide6**-Oberfläche. Er erfasst ein- und ausgehenden IPv4-Verkehr
über einen Windows-Raw-Socket (`SIO_RCVALL`) – **ohne Npcap/WinPcap und ohne
Fremd-Dependencies** (außer PySide6).

> Erfassen · Zerlegen · Filtern · Visualisieren · Analysieren – alles offline.

---

## Funktionen

**Erfassung & Anzeige**
- Live-Mitschnitt allen IPv4-Verkehrs einer Schnittstelle (ein-/ausgehend)
- Paketliste mit Nr., Zeit, Quelle/Ziel (inkl. Port), Protokoll, Länge,
  Richtung (▲ aus / ▼ ein) und Wireshark-ähnlicher Info-Zeile
- Schicht-Detailansicht (Baum) und Hexdump mit **Byte-Hervorhebung**:
  Schicht/Feld anklicken → die zugehörigen Bytes leuchten in Hex **und** ASCII
- Detail-**Kontextmenü**: Feldwert kopieren oder direkt **als Filter anwenden**
  (z. B. Quelle → `host …`, Ziel-Port → `dst port …`)
- Auto-Scroll, der bei Live-Erfassung der neuesten Zeile folgt
- **Zeitformat** umschaltbar: relativ (seit Start), Tageszeit oder absolut (Epoch)
- Pakete **markieren** (Strg+M, hervorgehoben), „nächste Markierung" (F8)

**Protokoll-Zerlegung (Dissector)**
- IPv4 **und IPv6** (inkl. Extension-Header), TCP, UDP, ICMP, ICMPv6
- Anwendungsschicht: DNS, mDNS, TLS, HTTP (leichtgewichtige Erkennung)
- **IP-Klassifizierung** (offline): erkennt Sonderbereiche (privat, Loopback,
  CGNAT, Link-local, Multicast, Dokumentation …) und bekannte DNS-Resolver
- **TLS-Handshake**: Server-Name (**SNI**), ausgehandelte **Version** und
  **Cipher-Suite** (Client-/Server-Hello)
- **HTTP**: Start-/Statuszeile (Methode, Pfad, Status) und **alle Header** in der
  Detailansicht → erkennbar, welche Domain kontaktiert wird (auch ohne DNS)
- Ports vieler bekannter Dienste werden benannt

**Anzeigefilter** (kompakte, robuste Filtersprache)
```
tcp                      udp        icmp        dns        tls       http       https
host <ip>                src <ip>   dst <ip>
port <n>                 src port <n>           dst port <n>
in                       out
<freitext>               not <term> / ! <term>  <a> or <b>
```
Beispiele: `tcp dst port 443`, `dns or mdns`, `host 192.168.0.10 not port 53`
Die zuletzt genutzten Filter stehen als **Historie** (▼) im Filterfeld bereit.

**Live-Statistik & Visualisierung**
- Durchsatz-Graph (B/s, ein/aus) und Pakete-Graph (P/s, ein/aus)
- **Donut-Diagramm** der Protokollverteilung (Klick auf Segment/Legende setzt
  einen Protokollfilter)
- **Balken-Diagramm** der Top-Talkers
- **IO-Zeitdiagramm** pro Verbindung (Bytes/s je Richtung) im Verbindungs-Dialog
- Statistik-Panel: Top-Protokolle (nach Volumen, mit %) und Top-Talkers als
  Tabelle – alle Diagramme/Tabellen aktualisieren sich im Sekundentakt

**Analyse**
- **Verbindungen (Conversations):** Aggregation pro Flow mit Paketen/Bytes je
  Richtung, Dauer und Durchsatz
- **Follow TCP Stream:** seq-korrekte Rekonstruktion des Byte-Stroms, Client/
  Server farblich getrennt, umschaltbar ASCII ⇄ Hex
- **Experten-Infos:** TCP-Resets, mögliche Retransmissions, ICMP-Unreachable,
  **Port-/Host-Scan-Erkennung**, **Beaconing** (periodische Verbindungen →
  C2-Verdacht) und **Klartext-Credentials** (HTTP-Basic-Auth, FTP `USER/PASS`)
- **TCP-Gesundheit:** je Verbindung Handshake-RTT, Retransmissions, Dup-ACKs
  und Zero-Window-Ereignisse
- **Protokoll-Hierarchie:** Baum der Protokollverteilung nach Paketen/Bytes
- **Besuchte Domains:** Übersicht aller kontaktierten Domains (aus DNS-Queries,
  TLS-SNI und HTTP-Host), Doppelklick setzt sie als Filter
- **Namensauflösung (Reverse-DNS):** PTR-Namen der Gegenstellen im
  Verbindungs-Dialog sowie als optionale **Spalte** in der Paketliste
  (Ansicht → Namensspalte; gecacht, im Hintergrund)
- **Sequenzdiagramm:** Paketfluss einer Verbindung (Client ↔ Server über die
  Zeit) – im Verbindungs-Dialog über *Sequenz…*
- **Suche** (Strg+F / F3) springt durch die angezeigten Pakete
- **Kontextmenü** (Rechtsklick): Stream folgen, als Filter setzen (Verbindung/
  Host/Port)

**Langzeit-Erfassung**
- **Live-Mitschnitt** direkt in eine PCAP-Datei (Streaming – kein RAM-Stau)
- **Ringpuffer/Paketlimit**: nur die letzten *N* Pakete im Speicher halten
- **Aufnahme-Filter**: uninteressante Pakete schon vor dem Speichern verwerfen
  (gleiche Syntax wie der Anzeigefilter), Nummerierung bleibt lückenlos

**Werkzeuge** (Menü *Werkzeuge*)
- **Ping** und **Traceroute** (ICMP, eigener Raw-Socket – Adminrechte nötig)
- **DNS-Lookup** (Vorwärts- und Reverse-Auflösung, ohne erhöhte Rechte)

**Dateien & Export**
- PCAP **öffnen** und **speichern** – klassisch (`.pcap`) oder als modernes
  **`.pcapng`** (beides von Wireshark lesbar); optional nur die aktuell
  **angezeigten** Pakete speichern
- **Export** der Paketliste, Verbindungen oder Domains nach **CSV** oder **JSON**

**Bedienung**
- Umschaltbares **dunkles oder helles Design** (Ansicht → Helles Design)
- Paketliste **sortierbar** (Klick auf den Spaltenkopf) und Spalten **ein-/
  ausblendbar** (Rechtsklick auf den Spaltenkopf)
- **Einstellungen bleiben erhalten** (Design, Fenstergröße, Paketlimit,
  Auto-Scroll, Aufnahme-Filter u. a. – via QSettings)

---

## Installation

Voraussetzung: **Python ≥ 3.11** (Windows für die Live-Erfassung).

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

Damit wird PySide6 installiert und das Konsolenskript `netfett` angelegt.

## Start

```powershell
# Komfortabel über das Konsolenskript …
netfett
# … oder als Modul:
python -m netfett
```

> **Hinweis:** Die **Live-Erfassung** benötigt unter Windows
> **Administratorrechte** (Raw-Socket / `SIO_RCVALL`). Starte die PowerShell
> bzw. NetFett „Als Administrator". Das **Öffnen und Analysieren von
> PCAP-Dateien** funktioniert ohne erhöhte Rechte.

### Schnellstart
1. Schnittstelle (lokale IPv4-Adresse) oben links wählen
2. **▶ Start** – Pakete laufen ein
3. Optional filtern, z. B. `tcp dst port 443`
4. Paket anklicken → Details + Hex; Rechtsklick → **TCP-Stream folgen**
5. Menü **Analyse** → Verbindungen / Experten-Infos / Protokoll-Hierarchie

---

## Architektur

Klare Trennung zwischen **reiner Logik** (`core/`, ohne GUI/I/O – vollständig per
Unit-Test geprüft) und **Oberfläche** (`gui/`).

```
src/netfett/
├─ __main__.py            Einstiegspunkt (QApplication + Hauptfenster, Dark-Theme)
├─ core/                  reine, getestete Logik
│  ├─ capture.py          Windows-Raw-Socket (SIO_RCVALL), Hintergrund-Thread
│  ├─ dissect.py          Paketzerlegung IPv4/TCP/UDP/ICMP/DNS/TLS/HTTP
│  ├─ models.py           Packet / Layer (Datenmodelle)
│  ├─ displayfilter.py    Anzeigefilter (Text → Packet-Prädikat)
│  ├─ stats.py            laufende Statistik (Durchsatz, Pakete/s, Verteilung)
│  ├─ analyze.py          Conversations, Follow-Stream, Experten-Infos,
│  │                      Hierarchie, besuchte Domains
│  ├─ pcap.py             PCAP lesen/schreiben + PcapWriter (Streaming-Mitschnitt)
│  ├─ resolve.py          Reverse-DNS (IP → Hostname), gecacht, nebenläufig
│  ├─ ipinfo.py           Offline-IP-Klassifizierung (Sonderbereiche/Dienste)
│  ├─ export.py           CSV/JSON-Export (Pakete, Verbindungen, Domains)
│  ├─ tools.py            Ping, Traceroute, DNS-Lookup (ICMP-Bausteine testbar)
│  ├─ interfaces.py       lokale IPv4-Adressen ermitteln
│  └─ protocols.py        Protokoll-/Portnamen, ICMP-Typen
└─ gui/
   ├─ main_window.py      Hauptfenster: verdrahtet alle Bausteine
   ├─ capture_controller.py  Brücke Capture-Thread → Qt (gepuffert, flüssig)
   ├─ packet_model.py     Tabellenmodell der Paketliste
   ├─ graph_widget.py     Live-Graph (eigener QPainter)
   ├─ charts.py           Donut- und Balken-Diagramme (eigener QPainter)
   ├─ theme.py            Farbschema dunkel/hell + Chrome-Stylesheets
   ├─ tools_dialogs.py    Dialoge: Ping, Traceroute, DNS-Lookup
   └─ analysis_dialogs.py Dialoge: Verbindungen, Experten-Infos, Follow-Stream,
                          Protokoll-Hierarchie
```

Der Raw-Socket liefert Pakete **ab dem IPv4-Kopf** (keine Ethernet-Schicht);
entsprechend wird der PCAP-Link-Type `RAW` (101) verwendet.

---

## Tests

```powershell
pip install pytest
pytest
```

Die `core`-Schicht ist ohne GUI testbar; die Tests decken Dissector,
Anzeigefilter, Statistik/PCAP und die Analysefunktionen ab.

---

## Einschränkungen

- **Nur Windows** für die Live-Erfassung (`SIO_RCVALL`); PCAP-Analyse ist
  plattformunabhängig.
- **IPv6** wird zerlegt und (best-effort über einen zweiten Raw-Socket) auch
  live erfasst; Nicht-IP-Protokolle (z. B. ARP) liefert der Raw-Socket nicht.
- Erfordert **Administratorrechte** für die Erfassung.
- Der Dissector ist bewusst **leichtgewichtig** (die wichtigsten Protokolle),
  keine vollständige Wireshark-Abdeckung.

## Lizenz

Privates/Lern-Projekt – siehe Repository.
