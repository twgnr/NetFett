"""In-App-Benutzerdokumentation (ausführliches Handbuch) und „Über"-Dialog."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout,
)

from .. import __version__

_HELP_HTML = """
<h1>NetFett – Handbuch</h1>
<p><b>NetFett</b> erfasst und analysiert Netzwerkverkehr (IPv4/IPv6) über einen
Windows-Raw-Socket – ein vollwertiger Netzwerk-Monitor in reinem Python. Dieses
Handbuch erklärt <i>jede</i> Ansicht: was angezeigt wird, wo man es findet und wie
man es interpretiert.</p>

<h3>Inhalt</h3>
<ul>
<li><a href="#start">1. Schnelleinstieg &amp; Rechte</a></li>
<li><a href="#layout">2. Aufbau des Hauptfensters</a></li>
<li><a href="#toolbar">3. Werkzeugleiste (oben)</a></li>
<li><a href="#graphs">4. Live-Graphen (Durchsatz / Pakete)</a></li>
<li><a href="#list">5. Die Paketliste – Spalten &amp; Farben</a></li>
<li><a href="#detail">6. Detailbaum, Hex und Inhalt</a></li>
<li><a href="#filter">7. Anzeigefilter (Syntax)</a></li>
<li><a href="#stats">8. Statistik-Panel (rechts)</a></li>
<li><a href="#statusbar">9. Statusleiste (unten)</a></li>
<li><a href="#analyse">10. Menü „Analyse" – alle Auswertungen</a></li>
<li><a href="#tools">11. Menü „Werkzeuge"</a></li>
<li><a href="#view">12. Menü „Ansicht"</a></li>
<li><a href="#capture">13. Menü „Aufnahme" (Mitschnitt/Filter)</a></li>
<li><a href="#tls">14. TLS entschlüsseln &amp; HTTP/2</a></li>
<li><a href="#interpret">15. Werte richtig interpretieren</a></li>
<li><a href="#keys">16. Tastenkürzel</a></li>
<li><a href="#limits">17. Grenzen</a></li>
</ul>

<hr>
<h2 id="start">1. Schnelleinstieg &amp; Rechte</h2>
<ol>
<li>Oben links die <b>Schnittstelle</b> (lokale IP-Adresse) wählen.</li>
<li><b>▶ Start</b> klicken – die Liste füllt sich mit Live-Paketen.</li>
<li>Eine Zeile anklicken → unten erscheinen Detailbaum, Hex und Inhalt.</li>
<li><b>■ Stopp</b> beendet die Erfassung; <b>Leeren</b> verwirft alle Pakete.</li>
</ol>
<p><b>Wichtig – Administratorrechte:</b> Die Live-Erfassung benötigt einen
Raw-Socket und damit Adminrechte. Steht im Fenstertitel <i>(Administrator)</i>,
ist alles bereit. Andernfalls: <i>Aufnahme → Als Administrator neu starten…</i>
oder eine vorhandene PCAP-Datei öffnen (das geht ohne Sonderrechte).</p>

<h2 id="layout">2. Aufbau des Hauptfensters</h2>
<p>Das Fenster ist von oben nach unten in drei höhenverstellbare Bereiche geteilt
(Trennlinien ziehbar), plus ein andockbares Panel rechts:</p>
<ul>
<li><b>Oben – Live-Graphen:</b> Durchsatz (B/s) und Paketrate (P/s).</li>
<li><b>Mitte – Paketliste:</b> eine Zeile je Paket (das Herzstück).</li>
<li><b>Unten – Paketdetails:</b> links der Schicht-Baum, rechts die Reiter
<i>Hex</i> und <i>Inhalt</i>.</li>
<li><b>Rechts – Statistik-Panel:</b> Verteilungen und Top-Talkers (per Toolbar-
Schalter <i>Statistik</i> ein-/ausblendbar).</li>
</ul>

<h2 id="toolbar">3. Werkzeugleiste (oben)</h2>
<table border="1" cellspacing="0" cellpadding="4">
<tr><th>Element</th><th>Funktion</th></tr>
<tr><td><b>Schnittstelle</b></td><td>Lokale IP, auf der erfasst wird. Bei mehreren
Netzwerkkarten die passende wählen.</td></tr>
<tr><td><b>▶ Start / ■ Stopp</b></td><td>Live-Erfassung starten/stoppen.</td></tr>
<tr><td><b>Leeren</b></td><td>Verwirft alle erfassten Pakete und Statistiken.</td></tr>
<tr><td><b>⤓ Auto-Scroll</b></td><td>Wenn aktiv, springt die Liste stets zur
neuesten Zeile. Zum Zurückblättern abschalten.</td></tr>
<tr><td><b>Statistik</b></td><td>Blendet das rechte Statistik-Panel ein/aus.</td></tr>
<tr><td><b>PCAP öffnen…</b></td><td>Liest eine gespeicherte Aufzeichnung
(<code>.pcap</code>/<code>.pcapng</code>) zur Offline-Analyse.</td></tr>
<tr><td><b>PCAP speichern…</b></td><td>Schreibt die aktuellen Pakete in eine Datei
(pcapng erhält auch Paket-Kommentare).</td></tr>
<tr><td><b>Filter</b></td><td>Anzeigefilter – siehe <a href="#filter">Abschnitt 7</a>.
Eingabe wird bei Fehler rot; <span style="color:#888">▼</span> zeigt die
zuletzt benutzten Filter.</td></tr>
</table>

<h2 id="graphs">4. Live-Graphen</h2>
<p>Die beiden oberen Diagramme zeigen die letzten ~60 Sekunden:</p>
<ul>
<li><b>Durchsatz (B/s):</b> übertragene Bytes pro Sekunde.</li>
<li><b>Pakete (P/s):</b> Pakete pro Sekunde.</li>
</ul>
<p>Beide trennen <b>eingehend</b> und <b>ausgehend</b> farblich. So erkennt man auf
einen Blick Lastspitzen und ob gerade gesendet oder empfangen wird.</p>

<h2 id="list">5. Die Paketliste – Spalten &amp; Farben</h2>
<p>Jede Zeile ist ein Paket. Die Spalten:</p>
<table border="1" cellspacing="0" cellpadding="4">
<tr><th>Spalte</th><th>Bedeutung / Interpretation</th></tr>
<tr><td><b>Nr.</b></td><td>Fortlaufende Erfassungsnummer (stabil, auch beim
Filtern/Sortieren).</td></tr>
<tr><td><b>Zeit</b></td><td>Zeitstempel. Format umschaltbar (<i>Ansicht →
Zeitformat</i>): <b>Relativ</b> (Sekunden seit dem 1. Paket), <b>Uhrzeit</b>
(Tageszeit) oder <b>Absolut</b> (Epoch-Sekunden).</td></tr>
<tr><td><b>Quelle / Ziel</b></td><td>Absender- und Empfänger-IP, bei TCP/UDP mit
Port. Mit aktiver <i>Namensspalte</i> zusätzlich der Reverse-DNS-Name.</td></tr>
<tr><td><b>Protokoll</b></td><td>Höchste erkannte Schicht (z. B. TLS, DNS, HTTP,
SMTP, SSH). Bestimmt auch die dezente Zeilentönung.</td></tr>
<tr><td><b>Länge</b></td><td>Paketgröße in Bytes (ab dem IP-Kopf – es gibt keinen
Ethernet-Rahmen, siehe <a href="#limits">Grenzen</a>).</td></tr>
<tr><td><b>Ri.</b></td><td>Richtung: <span style="color:#ffb454">▲ ausgehend</span>
(von diesem PC) bzw. <span style="color:#5aa9ff">▼ eingehend</span>.</td></tr>
<tr><td><b>Info</b></td><td>Kompakte Kurzbeschreibung: TCP-Flags, DNS-Namen,
HTTP-Anfragezeile, TLS-SNI, reassemblierte Fragmente usw.</td></tr>
<tr><td><b>Name</b></td><td>(optional) Reverse-DNS der Gegenstelle.</td></tr>
<tr><td><b>Programm</b></td><td>(optional) Lokaler Prozess der Verbindung
(Name/PID), sofern zuordenbar.</td></tr>
</table>
<p><b>Farben &amp; Hervorhebungen:</b></p>
<ul>
<li><b>Protokoll-Tönung</b> (im dunklen Design): z. B. TLS bläulich, DNS violett,
HTTP gelblich – zur schnellen optischen Gruppierung.</li>
<li><b>Eigene Einfärbe-Regeln</b> (<i>Ansicht → Einfärbe-Regeln</i>) haben
Vorrang vor der Protokoll-Tönung.</li>
<li><span style="background:#3a2f0a">&nbsp;Amber + fett&nbsp;</span> = <b>manuell
markiertes</b> Paket (Strg+M).</li>
<li><span style="background:#3a2a10">&nbsp;Amber&nbsp;</span> = <b>TCP-Problem</b>,
wenn <i>Analyse → TCP-Probleme markieren</i> aktiv ist. Maus darüber zeigt den
<b>Grund</b> (Retransmission/Dup-ACK/Out-of-Order mit Erklärung).</li>
<li>Ein <b>💬 im Tooltip</b> zeigt, dass die Zeile einen Kommentar trägt.</li>
</ul>
<p><b>Bedienung der Liste:</b></p>
<ul>
<li><b>Sortieren:</b> Spaltenkopf anklicken.</li>
<li><b>Spalten ein-/ausblenden:</b> Rechtsklick auf den Spaltenkopf.</li>
<li><b>Rechtsklick auf eine Zeile:</b> <i>TCP-Stream folgen</i>, Verbindung/Host/
Port <i>als Filter</i> übernehmen, oder einen <i>Kommentar</i> hinzufügen.</li>
<li><b>Strg+M</b> markiert/entmarkiert, <b>F8</b> springt zur nächsten Markierung,
<b>Strg+G</b> springt zu einer Paketnummer.</li>
</ul>

<h2 id="detail">6. Detailbaum, Hex und Inhalt</h2>
<p>Klick auf ein Paket füllt den unteren Bereich:</p>
<ul>
<li><b>Detailbaum (links):</b> alle Protokollschichten als aufklappbarer Baum
(IP → TCP/UDP → Anwendung) mit Feldname und Wert. <b>Ein Feld anklicken</b> hebt
die zugehörigen Bytes im Hex-Reiter farbig hervor. Rechtsklick: <i>Wert/Feld
kopieren</i> oder das Feld <i>als Filter</i> übernehmen.</li>
<li><b>Reiter „Hex":</b> klassischer Hexdump mit ASCII-Spalte; die zum gewählten
Feld gehörenden Bytes leuchten in Hex <i>und</i> ASCII.</li>
<li><b>Reiter „Inhalt":</b> die Nutzdaten als <b>Klartext</b> (unverschlüsselt,
z. B. HTTP/DNS/Mail) bzw. als <b>Bytes</b> (verschlüsselt, z. B. TLS), mit
Richtungsangabe.</li>
</ul>

<h2 id="filter">7. Anzeigefilter (Syntax)</h2>
<p>Das Filterfeld blendet Pakete aus, ohne sie zu verwerfen. Mehrere Begriffe
werden mit <b>UND</b> verknüpft; <code>or</code> verknüpft mit ODER,
<code>not</code> negiert.</p>
<pre>Protokolle:  tcp  udp  icmp  igmp  arp  dns  mdns  tls  http  https
             smtp  imap  pop3  mail  ftp  ssh
Adressen:    host &lt;ip&gt;     src &lt;ip&gt;     dst &lt;ip&gt;
Ports:       port &lt;n&gt;      src port &lt;n&gt;   dst port &lt;n&gt;
Richtung:    in           out
Logik:       not &lt;term&gt;    &lt;a&gt; or &lt;b&gt;     beliebiger Freitext</pre>
<p>Beispiele:</p>
<pre>tcp dst port 443 not host 10.0.0.5
dns or mdns
mail                      (= SMTP/IMAP/POP3)
host 192.168.0.10 out</pre>
<p>Ungültige Eingaben färben das Feld rot. Mit <i>Analyse → Suchen</i> (Strg+F)
durchsucht man zusätzlich den <b>Inhalt</b> der Pakete; <b>F3</b> = weitersuchen.
Tipp: Ein Klick auf ein Donut-Segment im Statistik-Panel setzt automatisch den
passenden Protokoll-/Programmfilter.</p>

<h2 id="stats">8. Statistik-Panel (rechts)</h2>
<p>Aktualisiert sich im Sekundentakt:</p>
<ul>
<li><b>Verteilungs-Donut</b> – per Auswahlfeld umschaltbar zwischen
<b>Protokollen</b>, <b>Programmen</b> und <b>Kategorien</b> (jeweils nach
Byte-Volumen). <b>Klick auf ein Segment</b> filtert die Liste entsprechend
(Kategorien dienen nur der Übersicht).</li>
<li><b>Tabelle darunter:</b> dieselben Werte als Pakete, Bytes und Prozent.</li>
<li><b>Top-Talkers</b> – die volumenstärksten Verbindungen (Quelle ⇄ Ziel) als
Balken und Tabelle.</li>
</ul>
<p>Mit <i>Ansicht → Statistik nur auf Filter</i> beziehen sich Auswertungen nur
auf die aktuell sichtbaren (gefilterten) Pakete.</p>

<h2 id="statusbar">9. Statusleiste (unten)</h2>
<p>Links der aktuelle Zustand (Bereit/Erfassung läuft/Filter aktiv/Fehler …),
rechts die Zähler:</p>
<ul>
<li><b>Pakete: angezeigt / gesamt</b> – Differenz = vom Anzeigefilter ausgeblendet.</li>
<li><b>(Ring N)</b> – ein Paketlimit (Ringpuffer) ist gesetzt.</li>
<li><b>verworfen N</b> – so viele Pakete hat der <i>Aufnahme</i>-Filter verworfen.</li>
<li><b>▼ / ▲</b> – insgesamt empfangene bzw. gesendete Datenmenge.</li>
</ul>

<h2 id="analyse">10. Menü „Analyse" – alle Auswertungen</h2>
<p>Alle Auswertungen öffnen sich in eigenen Fenstern. Doppelklick auf eine Zeile
setzt meist einen passenden Filter bzw. springt zum Paket.</p>

<h3>Verbindungen</h3>
<p>Alle Flows: <i>Protokoll, Endpunkt A, Endpunkt B, Pakete, A→B, B→A, Bytes,
Dauer, Durchsatz</i>. Rechtsklick je Verbindung: <i>Stream folgen</i>,
<i>Sequenzdiagramm</i>, <i>TCP-Stream-Graph</i>, <i>Objekte extrahieren</i>,
<i>Namen auflösen</i>. <b>So liest man es:</b> hohe „B→A" bei kleiner „A→B" = Download;
sehr kurze Dauer mit wenigen Paketen = abgebrochene/abgelehnte Verbindung.</p>

<h3>Experten-Infos</h3>
<p>Automatisch erkannte Auffälligkeiten: <i>Schwere, Kategorie, Beschreibung,
Paket</i>. Schweregrade: <b>info</b> (z. B. Erstkontakt zu neuem Host) ·
<b>note</b> (z. B. TCP-Reset) · <b>warn</b> (z. B. Scan, ICMP-Fehler,
DNS-Tunneling) · <b>error</b> (z. B. Klartext-Passwörter, Exfiltration).
Kategorien u. a. TCP, ICMP, Security, Erstkontakt. Doppelklick springt zum Paket.</p>

<h3>TCP-Gesundheit</h3>
<p>Je Verbindung: <i>Endpunkt A/B, Pakete, RTT, Retrans., Dup-ACK, Zero-Win</i>.
<b>Interpretation:</b> hohe <i>Retrans.</i> (Wiederholungen) oder <i>Dup-ACK</i>
deuten auf Paketverlust; <i>Zero-Win</i> &gt; 0 bedeutet, ein Empfänger war
überlastet (Empfangsfenster voll); <i>RTT</i> ist die gemessene Laufzeit.</p>

<h3>Protokoll-Hierarchie</h3>
<p>Baum aller Protokolle mit Anteil an Paketen und Bytes – zeigt die
Zusammensetzung des Verkehrs.</p>

<h3>Besuchte Domains</h3>
<p>Aus DNS-Anfragen und TLS-SNI gesammelte <i>Domain, Pakete, Quelle</i> – ein
schneller Überblick „wohin wurde verbunden".</p>

<h3>DNS-Analyse</h3>
<p><i>Name, Typ, Anfragen, Antworten, NXDOMAIN, Ø-Zeit, Adressen</i>.
<b>Interpretation:</b> viele <i>NXDOMAIN</i> (nicht existierende Namen) können auf
Tippfehler, Schadsoftware-Domains oder Such-Suffixe hinweisen; <i>Ø-Zeit</i> ist
die mittlere Antwortzeit des Resolvers.</p>

<h3>Endpunkte &amp; Ports</h3>
<p>Drei Teile: <b>Hosts</b> nach Volumen (<i>Host, Pakete, Bytes, ↑ gesendet,
↓ empfangen</i>, mit geladener GeoIP-DB zusätzlich <i>Land/ASN</i>),
<b>Dienst-Ports</b> (<i>Port, Dienst, L4, Pakete, Bytes</i>) und ein
<b>Paketgrößen-Histogramm</b>. Doppelklick filtert auf den Host bzw. Port.</p>

<h3>Verbindungs-Status</h3>
<p>TCP-Lebenszyklus je Flow: <i>Endpunkt A/B, Zustand, Aufbau, Dauer, Pakete</i>.
Farbcodierung des Zustands: <span style="color:#f85149">rot</span> =
<i>Zurückgesetzt (RST)</i> oder <i>Fehlgeschlagen (keine Antwort)</i>,
<span style="color:#d29922">amber</span> = <i>Aufbau (SYN/ACK)</i> oder
<i>Unvollständig</i>, neutral = sauber etabliert/geschlossen. <i>Aufbau</i> ist die
Handshake-Dauer.</p>

<h3>RTP-Streams</h3>
<p>VoIP-/Medienströme: <i>SSRC, Quelle, Ziel, PT (Payload-Typ), Pakete, Verlust,
Jitter, Dauer</i>. Hoher <i>Verlust</i> oder <i>Jitter</i> = schlechte Sprach-/
Videoqualität.</p>

<h3>Programmverkehr</h3>
<p>Aggregiert nach lokalem Programm: <i>Programm, Pakete, Bytes, ↑ gesendet,
↓ empfangen</i> – zeigt, welche Anwendung wie viel Netzlast erzeugt.</p>

<h3>Netzwerk-Topologie</h3>
<p>Grafische Karte der Kommunikationsbeziehungen (wer spricht mit wem).</p>

<h3>Geräte-Übersicht / IP-Scan</h3>
<p>Durchsucht das lokale Netz (Ping-Scan, <b>braucht Adminrechte</b>) und zeigt je
Gerät eine Karte mit <i>Gerätename, MAC, Hersteller, Web-Adresse</i> und einem
kleinen Live-Durchsatzgraphen. <b>Doppelklick</b> auf eine Karte filtert die
Hauptliste auf dieses Gerät; <b>Klick auf die Web-Adresse</b> öffnet sie im
Browser.</p>

<h3>IO-Graph</h3>
<p>Zeitverlauf des Verkehrs, umschaltbar zwischen <i>Bytes/s</i> und
<i>Pakete/s</i> – gut, um Spitzen einem Zeitpunkt zuzuordnen.</p>

<h3>IOC-Abgleich</h3>
<p>Gleicht Domains/IPs gegen bekannte Indikatoren ab: <i>Schwere,
Indikator/Beschreibung, Paket</i>.</p>

<h3>Service-Response-Time</h3>
<p>Antwortzeiten je Protokoll (DNS/HTTP/SMB2): <i>Protokoll, Anfragen, Ø, Min,
Max</i> – zeigt, welcher Dienst langsam antwortet.</p>

<h3>Flow-Graph</h3>
<p>Globales Leiterdiagramm der wichtigsten Verbindungen über die Zeit – jede
Zeile ein Ereignis, Pfeile zeigen die Richtung.</p>

<h3>Weitere Punkte</h3>
<ul>
<li><b>TCP-Probleme markieren</b> (Umschalter): hebt Retransmissions/Dup-ACK/
Out-of-Order in der Liste amber hervor; der Grund steht im Tooltip.</li>
<li><b>Gehe zu Paket…</b> (Strg+G): springt zu einer Paketnummer.</li>
<li><b>Suchen / Weitersuchen</b> (Strg+F / F3): Volltextsuche im Inhalt.</li>
<li><b>Exportieren</b>: Pakete, Verbindungen oder Domains als CSV/JSON.</li>
</ul>

<h2 id="tools">11. Menü „Werkzeuge"</h2>
<ul>
<li><b>Ping / Traceroute / DNS-Lookup / WHOIS</b>: Netzdiagnose direkt aus
NetFett. WHOIS folgt automatisch dem zuständigen Registry-Server.</li>
<li><b>TLS-Schlüssel laden (SSLKEYLOGFILE)</b>: lädt Sitzungsschlüssel für die
TLS-Entschlüsselung (siehe <a href="#tls">Abschnitt 14</a>).</li>
<li><b>GeoIP-Datenbank laden (GeoLite2)</b>: lädt eine MaxMind-<code>.mmdb</code>
(Country/City/ASN). Danach zeigt <i>Endpunkte &amp; Ports</i> eine Spalte
<i>Land/ASN</i>. Benötigt das Paket <code>maxminddb</code> und eine selbst
beschaffte DB – NetFett bringt keine GeoIP-Daten mit.</li>
</ul>

<h2 id="view">12. Menü „Ansicht"</h2>
<ul>
<li><b>Zeitformat</b>: Relativ / Uhrzeit / Absolut (siehe Spalte „Zeit").</li>
<li><b>Markierung umschalten</b> (Strg+M), <b>Nächste Markierung</b> (F8),
<b>Alle Markierungen löschen</b>.</li>
<li><b>Namensspalte (Reverse-DNS)</b> und <b>Programmspalte</b> ein-/ausblenden.</li>
<li><b>Einfärbe-Regeln…</b>: eigene Regeln (Name, Filter, Farbe) anlegen; sie
färben passende Zeilen ein – ideal, um wichtigen Verkehr hervorzuheben.</li>
<li><b>Statistik nur auf Filter</b>: Auswertungen auf die sichtbaren Pakete
beschränken.</li>
<li><b>Decode As…</b>: einem Port ein Protokoll fest zuordnen (z. B. „8443 als
TLS"), wenn die automatische Erkennung nicht greift.</li>
<li><b>Profile</b>: aktuelle Einstellungen (Filter, Farben, Spalten …) unter einem
Namen <i>speichern</i>, später <i>laden</i> oder <i>löschen</i>.</li>
<li><b>Helles Design</b>: zwischen dunklem und hellem Thema wechseln.</li>
</ul>

<h2 id="capture">13. Menü „Aufnahme"</h2>
<ul>
<li><b>Mitschnitt in Datei…</b>: schreibt während der Erfassung live in eine
PCAP-Datei (Umschalter).</li>
<li><b>Paketlimit (Ringpuffer)…</b>: begrenzt die Zahl gehaltener Pakete; ältere
fallen heraus (schont Speicher bei Langzeit-Erfassung).</li>
<li><b>Aufnahme-Filter…</b>: verwirft uninteressante Pakete bereits <i>vor</i> dem
Mitschnitt/der Anzeige (gleiche Syntax wie der Anzeigefilter). Reduziert
Datenmenge; verworfene Pakete erscheinen als „verworfen N" in der Statusleiste.</li>
<li><b>Mitschnitt mit Rotation…</b>: schreibt in mehrere, rollierende Dateien
fester Größe (z. B. für Dauerbetrieb).</li>
<li><b>Zuletzt geöffnet</b>: schneller Zugriff auf kürzlich geöffnete PCAPs.</li>
<li><b>Als Administrator neu starten…</b>: nur ohne Adminrechte sichtbar – nötig
für die Live-Erfassung.</li>
</ul>

<h2 id="tls">14. TLS entschlüsseln &amp; HTTP/2</h2>
<ol>
<li>Im Browser die Umgebungsvariable <code>SSLKEYLOGFILE</code> auf eine Datei
setzen und damit surfen (der Browser schreibt dort die Sitzungsschlüssel).</li>
<li>In NetFett: <i>Werkzeuge → TLS-Schlüssel laden</i> und diese Datei wählen.</li>
<li>Eine TLS-Verbindung per Rechtsklick → <i>TCP-Stream folgen</i> öffnen und auf
<b>Entschlüsseln (TLS)</b> klicken – der Klartext erscheint.</li>
<li>Bei <b>HTTP/2</b> im Stream-Fenster die Ansicht <b>„HTTP/2-Header"</b> wählen:
NetFett dekodiert die HPACK-komprimierten Header (auch nach Entschlüsselung).</li>
</ol>
<p>Ohne passende Schlüssel bleibt TLS verschlüsselt – das ist technisch bedingt.</p>

<h2 id="interpret">15. Werte richtig interpretieren</h2>
<ul>
<li><b>Richtung (▲/▼):</b> bezieht sich immer auf <i>diesen</i> PC. ▲ = von hier
gesendet, ▼ = hier empfangen.</li>
<li><b>TCP-Probleme:</b> <i>Retransmission</i> = ein Segment wurde erneut gesendet
(Verlust); <i>Dup-ACK</i> = der Empfänger fordert ein fehlendes Segment an;
<i>Out-of-Order</i> = ein Segment kam verspätet/vertauscht an. Einzelne Vorfälle
sind normal – Häufungen deuten auf eine schlechte Strecke.</li>
<li><b>Verbindungs-Status:</b> rot = zurückgesetzt/keine Antwort (Problem oder
geblockt), amber = noch im Aufbau/unvollständig, neutral = ok.</li>
<li><b>Erstkontakt (Experten-Info):</b> erste Verbindung zu einem neuen externen
Host – meist harmlos, in Summe aber ein guter „was ist neu"-Indikator.</li>
<li><b>Klartext-Passwörter (error):</b> Anmeldedaten in HTTP-Basic/FTP/SMTP wurden
unverschlüsselt übertragen – ein echtes Sicherheitsrisiko.</li>
</ul>

<h2 id="keys">16. Tastenkürzel</h2>
<table border="1" cellspacing="0" cellpadding="4">
<tr><th>Taste</th><th>Funktion</th></tr>
<tr><td>F1</td><td>Dieses Handbuch</td></tr>
<tr><td>Strg+F</td><td>Im Inhalt suchen</td></tr>
<tr><td>F3</td><td>Weitersuchen</td></tr>
<tr><td>Strg+G</td><td>Gehe zu Paketnummer</td></tr>
<tr><td>Strg+M</td><td>Markierung umschalten</td></tr>
<tr><td>F8</td><td>Nächste Markierung</td></tr>
<tr><td>Doppelklick</td><td>In Auswertungen: Filter setzen / zum Paket springen</td></tr>
</table>

<h2 id="limits">17. Grenzen</h2>
<p>NetFett erfasst über einen Raw-Socket <b>ab dem IP-Kopf</b> – es gibt daher
<b>kein Ethernet/ARP</b> und keine MAC-Adressen im Mitschnitt. Weiter ohne
Funktion: eine Länder-GeoIP-Datenbank ist nicht enthalten (optional nachladbar),
und TLS lässt sich nur mit passenden Schlüsseln entschlüsseln.</p>

<h3>Headless / Kommandozeile</h3>
<pre>python -m netfett --read mitschnitt.pcapng --stats
python -m netfett --read x.pcap --export verb.csv --what conversations</pre>
"""


class HelpDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetFett – Handbuch")
        self.resize(820, 760)
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
            "<p>Vollwertiger Netzwerk-Monitor und Protokoll-Analyzer in reinem "
            "Python (PySide6).</p>"
            "<p>Live-Erfassung, Tiefen-Analyse, TLS-Entschlüsselung, "
            "Sicherheits-Auswertungen und Visualisierung – lokal und offline.</p>"
            "<p>Copyright &copy; Tobias Wagner. Alle Rechte vorbehalten.</p>")
