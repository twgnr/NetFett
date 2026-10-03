"""English strings for the analysis dialogs (gui/analysis_dialogs.py)."""

MESSAGES = {
    # Conversations
    "Verbindungen": "Conversations",
    "Protokoll": "Protocol",
    "Endpunkt A": "Address A",
    "Endpunkt B": "Address B",
    "Pakete": "Packets",
    "Bytes": "Bytes",
    "Dauer": "Duration",
    "Durchsatz": "Throughput",
    "{convs} Verbindung(en) aus {packets} Paketen":
        "{convs} conversation(s) from {packets} packets",
    "Verlauf – Verbindung wählen": "Timeline – select a conversation",
    "Verlauf  {a} ⇄ {b}": "Timeline  {a} ⇄ {b}",
    "Stream folgen": "Follow Stream",
    "Als Filter setzen": "Apply as Filter",
    "Sequenz…": "Sequence…",
    "Paketfluss als Sequenzdiagramm": "Packet flow as sequence diagram",
    "Stream-Graph…": "Stream Graph…",
    "Objekte…": "Objects…",
    "Dateien/Objekte aus HTTP (auch entschlüsselt)":
        "Files/objects from HTTP (also decrypted)",
    "Namen auflösen": "Resolve Names",
    "Reverse-DNS (PTR) der Endpunkt-IPs": "Reverse DNS (PTR) of endpoint IPs",
    "Löse auf …": "Resolving …",
    "Objekte": "Objects",
    "Keine HTTP-Objekte gefunden (evtl. verschlüsselt – Schlüssel laden?).":
        "No HTTP objects found (possibly encrypted – load keys?).",
    # Expert information
    "Experten-Infos": "Expert Information",
    "keine": "none",
    "{n} Befund(e)   ({summary})": "{n} finding(s)   ({summary})",
    "Schwere": "Severity",
    "Kategorie": "Category",
    "Beschreibung": "Summary",
    "Paket": "Packet",
    "Kein auffälliger Verkehr erkannt. 🎉": "No suspicious traffic detected. 🎉",
    # Protocol hierarchy
    "Protokoll-Hierarchie": "Protocol Hierarchy",
    "{n} Paket(e) gesamt": "{n} packet(s) total",
    "% Pakete": "% Packets",
    # Follow stream
    "TCP-Stream  {a} ⇄ {b}": "TCP Stream  {a} ⇄ {b}",
    "Entschlüsseln (TLS)": "Decrypt (TLS)",
    "TLS mit geladener SSLKEYLOGFILE entschlüsseln":
        "Decrypt TLS using the loaded SSLKEYLOGFILE",
    "Ansicht:": "Show as:",
    "HTTP/2-Header": "HTTP/2 headers",
    "Beide": "Both directions",
    "Nur Client": "Client only",
    "Nur Server": "Server only",
    "TLS-Entschlüsselung": "TLS Decryption",
    "Keine HTTP/2-HEADERS-Frames gefunden. (Nur bei HTTP/2-Verkehr; TLS ggf. "
    "erst entschlüsseln.)":
        "No HTTP/2 HEADERS frames found. (HTTP/2 traffic only; decrypt TLS "
        "first if needed.)",
    "Keine Nutzdaten in dieser Richtung.": "No payload in this direction.",
    # TCP health
    "TCP-Gesundheit": "TCP Health",
    "Retrans.": "Retrans.",
    "{n} TCP-Verbindung(en), {issues} mit Auffälligkeiten":
        "{n} TCP connection(s), {issues} with issues",
    # Domains
    "Besuchte Domains": "Visited Domains",
    "{n} eindeutige Domain(s) aus {packets} Paketen (DNS / TLS-SNI / HTTP-Host)":
        "{n} unique domain(s) from {packets} packets (DNS / TLS SNI / HTTP Host)",
    "Domain": "Domain",
    "Quelle": "Source",
    # Sequence
    "Sequenzdiagramm": "Sequence Diagram",
    "{n} Paket(e)  ·  {client}  →  {server}": "{n} packet(s)  ·  {client}  →  {server}",
    # DNS
    "DNS-Analyse": "DNS Analysis",
    "Name": "Name",
    "Typ": "Type",
    "Anfragen": "Requests",
    "Antworten": "Answers",
    "Ø-Zeit": "Avg. time",
    "Adressen": "Addresses",
    "{n} Namen · {q} Anfragen · {nx} NXDOMAIN":
        "{n} names · {q} requests · {nx} NXDOMAIN",
    # Endpoints
    "Endpunkte & Ports": "Endpoints & Ports",
    "Hosts (nach Volumen)": "Hosts (by volume)",
    "Host": "Host",
    "↑ gesendet": "↑ sent",
    "↓ empfangen": "↓ received",
    "Land / ASN": "Country / ASN",
    "Dienst-Ports (nach Volumen)": "Service Ports (by volume)",
    "Port": "Port",
    "Dienst": "Service",
    "Paketgrößen-Verteilung": "Packet Length Distribution",
    # Connection states
    "Verbindungs-Status": "Connection States",
    "Zustand": "State",
    "Aufbau": "Setup",
    "{n} TCP-Verbindung(en), {bad} auffällig": "{n} TCP connection(s), {bad} abnormal",
    # Process traffic
    "Programmverkehr": "Traffic by Program",
    "Programm": "Program",
    "Verkehr nach Programm": "Traffic by program",
    "Verlauf nach Programm": "Timeline by program",
    "Viel Verkehr ohne Programmzuordnung – Prozesszuordnung gibt es nur bei "
    "Live-Erfassung und am besten als Administrator.":
        "Much traffic without a program assignment – process mapping is only "
        "available for live captures, ideally run as administrator.",
    # Service response time
    "Service-Response-Time": "Service Response Time",
    "{n} Protokoll(e) mit Antwortzeiten": "{n} protocol(s) with response times",
    # RTP
    "RTP-Streams": "RTP Streams",
    "{n} RTP-Stream(s)": "{n} RTP stream(s)",
    "Ziel": "Destination",
    "Verlust": "Lost",
}
