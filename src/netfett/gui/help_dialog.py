"""In-App-Benutzerdokumentation (Handbuch) und „Über"-Dialog."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout,
)

from .. import __version__

_HELP_HTML = """
<h2>NetFett – Kurzanleitung</h2>
<p><b>NetFett</b> erfasst und analysiert Netzwerkverkehr (IPv4/IPv6) über einen
Windows-Raw-Socket – ähnlich Wireshark, aber schlank und in reinem Python.</p>

<h3>1. Erfassen</h3>
<ul>
<li>Oben links die <b>Schnittstelle</b> (lokale IP) wählen, dann <b>▶ Start</b>.</li>
<li><b>Live-Erfassung benötigt Administratorrechte.</b> Ohne Rechte:
<i>Aufnahme → Als Administrator neu starten…</i> oder eine PCAP-Datei öffnen.</li>
<li><b>Auto-Scroll</b> folgt den neuesten Paketen. <b>Leeren</b> verwirft alles.</li>
</ul>

<h3>2. Filtern &amp; Suchen</h3>
<p>Der <b>Anzeigefilter</b> oben akzeptiert u. a.:</p>
<pre>tcp  udp  icmp  dns  tls  http  https  arp
smtp  imap  pop3  mail  ftp  ssh
host &lt;ip&gt;   src &lt;ip&gt;   dst &lt;ip&gt;
port &lt;n&gt;   src port &lt;n&gt;   dst port &lt;n&gt;
in   out   not &lt;term&gt;   &lt;a&gt; or &lt;b&gt;   Freitext</pre>
<p>Mehrere Begriffe = UND. Beispiel: <code>tcp dst port 443 not host 10.0.0.5</code>.
<code>mail</code> trifft SMTP/IMAP/POP3. Mit <i>Analyse → Suchen</i> (Strg+F) im
Inhalt suchen. Dieselbe Syntax gilt für den <b>Aufnahme-Filter</b>
(<i>Aufnahme → Aufnahme-Filter</i>), der Pakete schon vor dem Mitschnitt
verwirft.</p>

<h3>3. Paket ansehen</h3>
<ul>
<li><b>Detailbaum</b>: Schichten und Felder; ein Feld anklicken hebt die Bytes
im <b>Hex</b>-Reiter hervor.</li>
<li><b>Inhalt</b>-Reiter: Nutzdaten als <b>Klartext</b> (unverschlüsselt) bzw.
als <b>Bytes</b> (z. B. TLS).</li>
<li>Rechtsklick auf eine Zeile: Stream folgen, als Filter setzen u. a.
Rechtsklick auf den Spaltenkopf blendet Spalten ein/aus.</li>
<li><b>Strg+M</b> markiert ein Paket, <b>F8</b> springt zur nächsten Markierung.</li>
</ul>

<h3>4. Visualisierung</h3>
<p>Rechts das <b>Statistik-Panel</b> mit Live-Graphen und einem Donut, der
zwischen <b>Protokollen</b>, <b>Programmen</b> und <b>Kategorien</b> umschaltbar
ist. Weitere Diagramme unter <i>Analyse</i> (IO-Graph, Topologie, Sequenz,
Stream-Graph).</p>

<h3>5. Analyse (Menü Analyse)</h3>
<ul>
<li><b>Verbindungen</b>: je Verbindung folgen, Sequenz-/Stream-Graph, Objekte
extrahieren, Namen auflösen.</li>
<li><b>Experten-Infos</b>: RST, Retransmissions, Scans, Beaconing,
Klartext-Passwörter.</li>
<li><b>DNS-Analyse</b>, <b>Endpunkte &amp; Ports</b>, <b>Verbindungs-Status</b>,
<b>Programmverkehr</b>, <b>Besuchte Domains</b>, <b>IOC-Abgleich</b>.</li>
<li><b>Geräte-Übersicht / IP-Scan</b>: lokales Netz per Ping durchsuchen und je
Gerät den Live-Durchsatz als kleinen Graphen sehen (Scan braucht Adminrechte).</li>
<li><b>GeoIP (optional)</b>: <i>Werkzeuge → GeoIP-Datenbank laden</i> öffnet eine
MaxMind-GeoLite2-Datei (Country/City/ASN). Danach zeigt <i>Endpunkte &amp;
Ports</i> eine Spalte <b>Land / ASN</b>. Benötigt <code>pip install maxminddb</code>
und eine selbst beschaffte <code>.mmdb</code>.</li>
<li><i>Ansicht → Statistik nur auf Filter</i> beschränkt Analysen auf den Filter.</li>
<li><b>Service-Response-Time</b>, <b>Flow-Graph</b>, <b>TCP-Probleme markieren</b>
(Retransmission/Dup-ACK), <b>Gehe zu Paket</b> (Strg+G).</li>
<li><b>Profile</b> (Ansicht → Profile) speichern Filter/Farben/Spalten;
Rechtsklick auf ein Paket → <b>Kommentar</b> (auch als pcapng-Kommentar).</li>
</ul>

<h3>6. TLS entschlüsseln</h3>
<ol>
<li>Im Browser die Umgebungsvariable <code>SSLKEYLOGFILE</code> setzen und surfen.</li>
<li>In NetFett: <i>Werkzeuge → TLS-Schlüssel laden (SSLKEYLOGFILE)</i>.</li>
<li>Eine TLS-Verbindung öffnen → <i>Stream folgen</i> → <b>Entschlüsseln</b>.</li>
<li>Bei HTTP/2 die <b>Ansicht „HTTP/2-Header"</b> wählen: NetFett dekodiert die
HPACK-komprimierten Header (auch nach TLS-Entschlüsselung).</li>
</ol>

<h3>7. Werkzeuge &amp; Export</h3>
<p><b>Ping</b>, <b>Traceroute</b>, <b>DNS-Lookup</b>, <b>WHOIS</b> (Menü Werkzeuge).
Export nach <b>CSV/JSON</b> (Analyse → Exportieren) und <b>PCAP/PCAPNG</b>.</p>

<h3>8. Headless / Kommandozeile</h3>
<pre>python -m netfett --read mitschnitt.pcapng --stats
python -m netfett --read x.pcap --export verb.csv --what conversations</pre>

<h3>Grenzen</h3>
<p>Kein Ethernet/ARP (Raw-Socket liefert ab dem IP-Kopf), keine
Länder-GeoIP-Datenbank, keine TLS-Entschlüsselung ohne passende Schlüssel.
HTTP/2-Header sind über TLS nur nach Entschlüsselung lesbar.</p>
"""


class HelpDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetFett – Handbuch")
        self.resize(680, 640)
        lay = QVBoxLayout(self)
        browser = QTextBrowser(self)
        browser.setOpenExternalLinks(True)
        browser.setHtml(_HELP_HTML)
        lay.addWidget(browser)
        box = QDialogButtonBox(QDialogButtonBox.Close, self)
        box.rejected.connect(self.reject)
        lay.addWidget(box)


def about_text() -> str:
    return (f"<h3>NetFett {__version__}</h3>"
            "<p>Schlanker, Wireshark-ähnlicher Netzwerk-Monitor in reinem "
            "Python (PySide6).</p>"
            "<p>Erfassen · Zerlegen · Filtern · Visualisieren · Analysieren – "
            "lokal und offline.</p>")
