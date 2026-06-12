# NetFett

**NetFett** ist ein vollwertiger Netzwerk-Monitor und Protokoll-Analyzer in **reinem
Python** mit **PySide6**-Oberfläche. Er erfasst ein- und ausgehenden IPv4-/IPv6-
Verkehr über einen Windows-Raw-Socket (`SIO_RCVALL`) – **ohne Npcap/WinPcap**.
Abhängigkeiten: **PySide6** (GUI) und **cryptography** (nur für die optionale
TLS-Entschlüsselung); die gesamte Analyse-Logik kommt ohne Fremd-Deps aus.

> Erfassen · Zerlegen · Filtern · Visualisieren · Analysieren – alles offline.

---

## Funktionen

**Erfassung & Anzeige**
- Live-Mitschnitt allen IPv4-Verkehrs einer Schnittstelle (ein-/ausgehend)
- Paketliste mit Nr., Zeit, Quelle/Ziel (inkl. Port), Protokoll, Länge,
  Richtung (▲ aus / ▼ ein) und kompakter Info-Zeile
- Schicht-Detailansicht (Baum) und – umschaltbar per Reiter – **Hex** oder
  **Inhalt**: die tatsächlichen Nutzdaten als **Klartext** (unverschlüsselt)
  bzw. als **Bytes/Hex** (verschlüsselt, z. B. TLS), mit Richtungsangabe
- Hexdump mit **Byte-Hervorhebung**: Schicht/Feld anklicken → die zugehörigen
  Bytes leuchten in Hex **und** ASCII
- Detail-**Kontextmenü**: Feldwert kopieren oder direkt **als Filter anwenden**
  (z. B. Quelle → `host …`, Ziel-Port → `dst port …`)
- Auto-Scroll, der bei Live-Erfassung der neuesten Zeile folgt
- **Zeitformat** umschaltbar: relativ (seit Start), Tageszeit oder absolut (Epoch)
- Pakete **markieren** (Strg+M, hervorgehoben), „nächste Markierung" (F8)

**Protokoll-Zerlegung (Dissector)**
- IPv4 **und IPv6** (inkl. Extension-Header), TCP, UDP, ICMP, ICMPv6
- **TCP-Optionen** (MSS, Window-Scale, SACK, Timestamps) werden ausgewertet
- **IP-Fragment-Reassemblierung** (IPv4 **und** IPv6): zersplitterte Datagramme
  werden zusammengesetzt; das letzte Fragment zeigt das vollständige Protokoll
- Anwendungsschicht: DNS, mDNS, **DHCP**, **NTP**, **QUIC**, TLS, HTTP,
  **HTTP/2** (h2c) mit **HPACK-Header-Dekodierung** (RFC 7541, inkl. Huffman +
  dynamischer Tabelle; über TLS nach Entschlüsselung), **SMB/SMB2** (inkl.
  Kommando, Dateiname/Pfad), **SIP** und **RTP** (heuristisch)
- **Klartext-Mail**: **SMTP** (inkl. MAIL FROM/RCPT TO/AUTH), **POP3**, **IMAP**
  – mit Richtungs- und Auffälligkeits-Markierung
- **FTP-Steuerkanal** (Befehle/Antworten) und **SSH** (Versions-Banner +
  Klartext-Handshake-Nachrichten wie KEXINIT/NEWKEYS)
- „**Decode As**": Port→Protokoll erzwingen (z. B. 8443 als TLS)
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
- **Donut-Diagramm** der Verteilung – umschaltbar zwischen **Protokollen**,
  **Programmen** und **Kategorien** (Browser, Kommunikation, System, E-Mail,
  Medien …); Klick auf Segment/Legende setzt einen passenden Filter
- **Balken-Diagramm** der Top-Talkers
- **IO-Zeitdiagramm** pro Verbindung (Bytes/s je Richtung) im Verbindungs-Dialog
- Statistik-Panel: Top-Protokolle (nach Volumen, mit %) und Top-Talkers als
  Tabelle – alle Diagramme/Tabellen aktualisieren sich im Sekundentakt

**Analyse**
- **Verbindungen (Conversations):** Aggregation pro Flow mit Paketen/Bytes je
  Richtung, Dauer und Durchsatz
- **Follow TCP Stream:** seq-korrekte Rekonstruktion des Byte-Stroms, Client/
  Server farblich getrennt, umschaltbar ASCII ⇄ Hex
- **Experten-Infos:** TCP-Resets, Retransmissions, ICMP-Unreachable,
  **Port-/Host-Scan**, **Beaconing**, **Klartext-Credentials**,
  **DNS-Tunneling**, **Exfiltration** (großer Upload) und **Erstkontakte**
  (neue externe Hosts). Zusätzlich:
  - **TLS-Hygiene:** veraltete TLS-Version (SSLv3/1.0/1.1), schwache Cipher,
    selbst-signierte/abgelaufene Zertifikate, SNI↔Zertifikats-Mismatch
  - **DNS-Auffälligkeiten:** DGA-Verdacht (zufällige Domains), hohe
    NXDOMAIN-Rate je Host, DNS-Amplification (Antwort ≫ Anfrage)
  - **Scan/Verbindung:** SYN-Flood/Half-Open, hohe Verbindungs-Fehlerrate,
    riskante Ziel-Ports (Telnet/RDP/VNC/DB/Malware), Telnet-Klartext-Login
  - **Volumen/DoS/Tunneling:** Traffic-Spitzen/Floods je Host,
    ICMP-Tunneling (große Echo-Nutzlast), NTP-monlist (Amplification)
- **TCP-Probleme markieren:** Retransmission/Dup-ACK/Out-of-Order je Paket in
  der Liste hervorheben (Analyse-Menü)
- **Service-Response-Time:** Antwortzeiten je Protokoll (DNS/HTTP/SMB2)
- **Flow-Graph:** globales Leiterdiagramm aller Verbindungen (Top-Hosts)
- **TLS-Zertifikate:** Subject/Aussteller/Gültigkeit aus dem Handshake
- **TCP-Gesundheit:** je Verbindung Handshake-RTT, Retransmissions, Dup-ACKs
  und Zero-Window-Ereignisse
- **Protokoll-Hierarchie:** Baum der Protokollverteilung nach Paketen/Bytes
- **DNS-Analyse:** Anfrage↔Antwort-Korrelation, Antwortzeiten, NXDOMAIN-Rate,
  meistgefragte Namen und aufgelöste A/AAAA/CNAME-Adressen
- **Endpunkte & Ports:** Volumen je einzelner Host (gesendet/empfangen),
  Top-Dienst-Ports und Paketgrößen-Verteilung; bei geladener GeoIP-DB zusätzlich
  **Land / ASN** je Host
- **GeoIP (optional):** Land/Stadt/ASN über MaxMind-**GeoLite2**-Dateien
  (`Werkzeuge → GeoIP-Datenbank laden`). Benötigt das optionale Paket
  `maxminddb` (`pip install netfett[geoip]`) und eine selbst beschaffte
  GeoLite2-`.mmdb`; NetFett bringt keine GeoIP-Daten mit
- **Verbindungs-Status:** TCP-Lebenszyklus je Flow (established / FIN /
  zurückgesetzt / fehlgeschlagen), Aufbauzeit und Dauer
- **RTP-Streams:** je SSRC Paketzahl, **Paketverlust** und **Jitter** (RFC 3550)
- **JA3/JA3S-Fingerprint** des TLS-Handshakes (in der Detailansicht)
- **TLS-Entschlüsselung** mit einer `SSLKEYLOGFILE` (TLS 1.2/1.3, AEAD): Schlüssel
  über *Werkzeuge → TLS-Schlüssel laden* einlesen, dann im Follow-Stream
  *Entschlüsseln* – zeigt den Klartext statt der verschlüsselten Bytes
- **Netzwerk-Topologie:** Knoten-Kanten-Diagramm „wer redet mit wem"
  (Hosts als Knoten, Verbindungsvolumen = Kantendicke)
- **Geräte-Übersicht / IP-Scan:** aktiver **ICMP-Ping-Sweep** des lokalen
  Subnetzes mit angereicherten Geräte-Infos – **Gerätename** (NetBIOS, **mDNS/
  Bonjour**, **SNMP sysName** oder Reverse-DNS), **MAC** (aus der ARP-Tabelle),
  **Hersteller** (OUI; optional
  Wiresharks `manuf`), **Web-Adresse** (Port 80/443, ggf. Seitentitel) und RTT
  – **plus** je Gerät ein **kleiner Live-Durchsatz-Graph** (▲ gesendet / ▼ empf.).
  **Doppelklick** auf ein Gerät filtert die Hauptansicht darauf; ein Klick auf
  die **Web-Adresse** öffnet sie im Browser.
- **IO-Graph:** Durchsatz/Pakete über Zeit mit bis zu 5 eigenen Filter-Linien
- **IOC-/Threat-Abgleich:** Blockliste (IPs/CIDRs/Domains) aus Datei laden,
  Treffer melden und in der Paketliste markieren
- **Datei-/Objekt-Extraktion:** Objekte aus HTTP- (auch entschlüsselten TLS-)
  Strömen herauslösen, ansehen (Text/Bild) und speichern
- **TCP-Stream-Graphen:** Sequenznummer, Durchsatz und Window über die Zeit
- **Gefilterte Statistik** und **„Decode As"** (Port→Protokoll erzwingen)
- **Programmverkehr:** grafische Live-Aufschlüsselung des Verkehrs **nach
  Programmen** – Donut (Volumen), **Verlaufsgraph** (Bytes/s je Top-Programm)
  und Tabelle. Zusätzlich optionale **Programm-Spalte** in der Paketliste
  (Ansicht → Programmspalte). Die Zuordnung Paket→Programm erfolgt über die
  Windows-Verbindungstabellen (lokaler Port → PID → Programm) – nur bei
  Live-Erfassung und am vollständigsten als Administrator.
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
- **WHOIS** (TCP/43, mit Referral – Halter/Netzbereich einer Domain/IP)

**Hilfe**
- Eingebautes **Handbuch** (Menü *Hilfe → Handbuch*, Taste **F1**) mit Anleitung
  zu Erfassung, Filtern, Analyse, TLS-Entschlüsselung und Werkzeugen

**Dateien & Export**
- PCAP/**PCAPNG öffnen** (auch **mehrere Dateien zusammenführen**) und
  **speichern** – klassisch (`.pcap`) oder modern (`.pcapng`); optional nur die
  aktuell **angezeigten** Pakete speichern
- **Rotierender Mitschnitt** in Ringdateien (nach Größe, begrenzte Anzahl)
- **Export** der Paketliste, Verbindungen oder Domains nach **CSV** oder **JSON**

**Bedienung**
- Umschaltbares **dunkles oder helles Design** (Ansicht → Helles Design)
- Paketliste **sortierbar** (Klick auf den Spaltenkopf) und Spalten **ein-/
  ausblendbar** (Rechtsklick auf den Spaltenkopf)
- **Benutzerdefinierte Einfärbe-Regeln** (Ansicht → Einfärbe-Regeln): Zeilen
  nach eigenen Filterausdrücken einfärben, mit Editor und Speicherung
- **Einstellungen bleiben erhalten** (Design, Fenstergröße, Paketlimit,
  Auto-Scroll, Aufnahme-Filter u. a. – via QSettings)
- **Profile** (benannte Einstellungs-Sätze: speichern/laden/löschen),
  **Gehe zu Paket** (Strg+G), **Paket-Kommentare** (Rechtsklick; Export als
  pcapng-Kommentar) und **zuletzt geöffnete Dateien**

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
4. Paket anklicken → Details + Hex/Inhalt; Rechtsklick → **TCP-Stream folgen**
5. Menü **Analyse** → Verbindungen / Experten-Infos / Topologie …
6. **F1** öffnet das eingebaute Handbuch.

### Kommandozeile (Headless, ohne GUI)
```powershell
# Mitschnitt einlesen und Zusammenfassung ausgeben
python -m netfett --read mitschnitt.pcapng --stats
# Verbindungen als CSV exportieren (mehrere Dateien werden zusammengeführt)
python -m netfett --read a.pcap b.pcap --export verbindungen.csv --what conversations
```
Datensätze: `--what packets|conversations|domains`, Format `--format csv|json`.

---

## Architektur

Klare Trennung zwischen **reiner Logik** (`core/`, ohne GUI/I/O – vollständig per
Unit-Test geprüft) und **Oberfläche** (`gui/`).

```
src/netfett/
├─ __main__.py            Einstiegspunkt (GUI oder Headless, UAC-Elevation)
├─ cli.py                 Headless-Modus (--read/--stats/--export)
├─ elevate.py             Windows-UAC-Elevation (Neustart als Administrator)
├─ core/                  reine, getestete Logik
│  ├─ capture.py          Windows-Raw-Socket (SIO_RCVALL), Hintergrund-Thread
│  ├─ dissect.py          Paketzerlegung IPv4/IPv6/TCP/UDP/ICMP/DNS/DHCP/NTP/
│  │                      QUIC/TLS/HTTP (+ TCP-Optionen, Decode-As)
│  ├─ models.py           Packet / Layer (Datenmodelle)
│  ├─ displayfilter.py    Anzeigefilter (Text → Packet-Prädikat)
│  ├─ stats.py            laufende Statistik (Durchsatz, Pakete/s, Verteilung)
│  ├─ analyze.py          Conversations, Follow-Stream, Experten-Infos,
│  │                      Hierarchie, besuchte Domains
│  ├─ pcap.py             PCAP lesen/schreiben + PcapWriter (Streaming-Mitschnitt)
│  ├─ reassemble.py       IP-Fragment-Reassemblierung (IPv4/IPv6)
│  ├─ scan.py             aktiver IP-Scan (Ping-Sweep + Geräte-Anreicherung)
│  ├─ arp.py              ARP-Tabelle lesen (IP → MAC, GetIpNetTable)
│  ├─ oui.py              MAC-OUI → Hersteller (+ optional manuf-Datei)
│  ├─ netbios.py          NetBIOS-Namensabfrage (Gerätename im LAN)
│  ├─ mdns.py             mDNS/Bonjour-Namensabfrage (.local-Hostname)
│  ├─ snmp.py             SNMPv1-GET für sysName (Gerätename)
│  ├─ hoststats.py        Durchsatz-Statistik je Host-IP (Geräte-Übersicht)
│  ├─ resolve.py          Reverse-DNS (IP → Hostname), gecacht, nebenläufig
│  ├─ ipinfo.py           Offline-IP-Klassifizierung (Sonderbereiche/Dienste)
│  ├─ ja3.py              JA3/JA3S-Fingerprinting aus TLS-Hello
│  ├─ tlskeys.py          SSLKEYLOGFILE + Schlüsselableitung (HKDF/PRF)
│  ├─ tlsdecrypt.py       AEAD-Record-Entschlüsselung (cryptography)
│  ├─ tlssession.py       ganze TLS-Verbindung entschlüsseln
│  ├─ extract.py          HTTP-Objekt-/Datei-Extraktion
│  ├─ procmap.py          Paket→Programm via Windows-Verbindungstabellen
│  ├─ content.py          Nutzdaten gewinnen + Klartext/Bytes einordnen
│  ├─ categories.py       Verkehr nach Kategorie (Browser/System/…) einordnen
│  ├─ coloring.py         benutzerdefinierte Einfärbe-Regeln (Filter→Farbe)
│  ├─ ioc.py              IOC-/Threat-Abgleich gegen Blockliste
│  ├─ export.py           CSV/JSON-Export (Pakete, Verbindungen, Domains)
│  ├─ tools.py            Ping, Traceroute, DNS-Lookup (ICMP-Bausteine testbar)
│  ├─ whois.py            WHOIS (TCP/43, mit Referral)
│  ├─ interfaces.py       lokale IPv4-/IPv6-Adressen ermitteln
│  └─ protocols.py        Protokoll-/Portnamen, ICMP-Typen
└─ gui/
   ├─ main_window.py      Hauptfenster: verdrahtet alle Bausteine
   ├─ capture_controller.py  Brücke Capture-Thread → Qt (gepuffert, flüssig)
   ├─ packet_model.py     Tabellenmodell der Paketliste (Sortierung, Regeln)
   ├─ graph_widget.py     Live-Graph (eigener QPainter)
   ├─ charts.py           Donut/Balken/Mehrlinien-Diagramme (eigener QPainter)
   ├─ theme.py            Farbschema dunkel/hell + Chrome-Stylesheets
   ├─ tools_dialogs.py    Dialoge: Ping, Traceroute, DNS-Lookup, WHOIS
   ├─ analysis_dialogs.py Dialoge: Verbindungen, Experten-Infos, Follow-Stream,
   │                      Hierarchie, Domains, DNS, Endpunkte, Status, …
   ├─ pro_dialogs.py      Coloring-Rules, IO-Graph, IOC, Topologie, Objekte,
   │                      Stream-Graph, Decode-As
   └─ help_dialog.py      In-App-Handbuch und „Über"
```

Der Raw-Socket liefert Pakete **ab dem IPv4-Kopf** (keine Ethernet-Schicht);
entsprechend wird der PCAP-Link-Type `RAW` (101) verwendet.

---

## Tests

```powershell
pip install pytest
pytest
```

Die `core`-Schicht ist ohne GUI testbar; die über 130 Tests decken Dissector,
Anzeigefilter, Statistik/PCAP(NG), Analyse, TLS-Krypto, IP-Klassifizierung,
Kategorien, Coloring/IOC, Objekt-Extraktion und den Headless-Modus ab.

---

## Einschränkungen

- **Nur Windows** für die Live-Erfassung (`SIO_RCVALL`); PCAP-Analyse ist
  plattformunabhängig.
- **IPv6** wird zerlegt und (best-effort über einen zweiten Raw-Socket) auch
  live erfasst; Nicht-IP-Protokolle (z. B. ARP) liefert der Raw-Socket nicht.
- Erfordert **Administratorrechte** für die Erfassung.
- Der Dissector deckt die wichtigsten Protokolle ab (inkl. HTTP/2, SMB, SIP,
  RTP), erhebt aber keinen Anspruch auf lückenlose Vollständigkeit. HTTP/2 nur im
  Klartext (h2c); über TLS erst nach Entschlüsselung. RTP-Erkennung ist
  heuristisch (keine festen Ports).

## Lizenz

Privates/Lern-Projekt – siehe Repository.
