"""Englische Übersetzungen für netfett.core.analyze (Experten-Infos, TCP-Flags, Zustände)."""

MESSAGES = {
    # --- Experten-Infos: Befundtexte (zur Laufzeit übersetzt) -------------- #
    "ICMP-Fehler": "ICMP error",
    "Verbindungs-Reset (RST) {src} → {dst}": "Connection reset (RST) {src} → {dst}",
    "Mögliche Retransmission (seq={seq}, len={length})":
        "Possible retransmission (seq={seq}, len={length})",
    "Möglicher Port-Scan: {src} sendete SYN an {n} Ports":
        "Possible port scan: {src} sent SYN to {n} ports",
    "Möglicher Host-Scan: {src} sendete SYN an {n} Hosts":
        "Possible host scan: {src} sent SYN to {n} hosts",
    "Erster Kontakt: {label}": "First contact: {label}",
    "Mögliches Beaconing: {src} → {dst}:{dport} alle ~{mean:.1f}s ({n}×, CV={cv:.2f})":
        "Possible beaconing: {src} → {dst}:{dport} every ~{mean:.1f}s ({n}×, CV={cv:.2f})",
    "HTTP Basic-Auth im Klartext: {cred} ({src} → {dst})":
        "HTTP Basic Auth in cleartext: {cred} ({src} → {dst})",
    "FTP-Benutzer im Klartext: {value} ({src} → {dst})":
        "FTP user in cleartext: {value} ({src} → {dst})",
    "FTP-Passwort im Klartext: {value} ({src} → {dst})":
        "FTP password in cleartext: {value} ({src} → {dst})",
    "Mögliches DNS-Tunneling: {src} → {base} ({cnt} Anfragen, {subs} eindeutige "
    "Subdomains, Ø {avg} Zeichen)":
        "Possible DNS tunneling: {src} → {base} ({cnt} queries, {subs} unique "
        "subdomains, avg. {avg} chars)",
    "Großes ausgehendes Volumen: {mb:.1f} MB → {dst}":
        "Large outbound volume: {mb:.1f} MB → {dst}",
    "Veraltete TLS-Version {version}: {src} ⇄ {dst}":
        "Outdated TLS version {version}: {src} ⇄ {dst}",
    "Schwache Cipher-Suite {cipher}: {src} → {dst}":
        "Weak cipher suite {cipher}: {src} → {dst}",
    "Selbst-signiertes Zertifikat: {subj} ({src})":
        "Self-signed certificate: {subj} ({src})",
    "Abgelaufenes Zertifikat: {subj} (gültig bis {date})":
        "Expired certificate: {subj} (valid until {date})",
    "Zertifikat noch nicht gültig: {subj} (ab {date})":
        "Certificate not yet valid: {subj} (from {date})",
    "SNI ≠ Zertifikat: angefragt {sni}, Zertifikat {subj}":
        "SNI ≠ certificate: requested {sni}, certificate {subj}",
    "DGA-Verdacht (zufällig wirkende Domain): {name}":
        "Suspected DGA (random-looking domain): {name}",
    "DNS-Amplification: Antwort {resp} B ≫ Anfrage {req} B ({name})":
        "DNS amplification: response {resp} B ≫ query {req} B ({name})",
    "Hohe NXDOMAIN-Rate: {host} erhielt {nx}/{total} NXDOMAIN (nicht gefunden) – "
    "DGA-/Schadsoftware-Verdacht":
        "High NXDOMAIN rate: {host} received {nx}/{total} NXDOMAIN (not found) – "
        "suspected DGA/malware",
    "Telnet (Klartext-Login): {src} → {dst} – Anmeldedaten werden unverschlüsselt "
    "übertragen":
        "Telnet (cleartext login): {src} → {dst} – credentials are transmitted "
        "unencrypted",
    "Verbindung zu riskantem Dienst {service} (Port {port}): {src} → {dst}":
        "Connection to risky service {service} (port {port}): {src} → {dst}",
    "Viele unvollständige Verbindungen (SYN-Flood/Half-Open): {src} sendete {sent} "
    "SYN, erhielt nur {got} SYN/ACK":
        "Many incomplete connections (SYN flood/half-open): {src} sent {sent} SYN, "
        "received only {got} SYN/ACK",
    "Hohe Verbindungs-Fehlerrate: {host} erhielt {rst} RST":
        "High connection failure rate: {host} received {rst} RST",
    "Traffic-Spitze/Flood: {src} mit {cnt} Paketen/s":
        "Traffic spike/flood: {src} with {cnt} packets/s",
    "Mögliches ICMP-Tunneling: {src} – {cnt} Echo-Pakete mit großer Nutzlast "
    "(≥{size} B)":
        "Possible ICMP tunneling: {src} – {cnt} echo packets with large payload "
        "(≥{size} B)",
    "NTP mode 7 (monlist) – Amplification-Risiko: {src} ⇄ {dst}":
        "NTP mode 7 (monlist) – amplification risk: {src} ⇄ {dst}",

    # --- TCP-Expert-Flags je Paket (Tooltip) ------------------------------- #
    "Retransmission – Segment Seq={seq} ({n} Bytes) wurde bereits gesendet "
    "(vermutlich Paketverlust)":
        "Retransmission – segment Seq={seq} ({n} bytes) was already sent "
        "(probable packet loss)",
    "Out-of-Order – Seq={seq} liegt vor dem bereits empfangenen Ende {hi} "
    "(Segment kam verspätet/vertauscht)":
        "Out-of-order – Seq={seq} lies before the already received end {hi} "
        "(segment arrived late/reordered)",
    "Dup-ACK #{n} – ACK={ack} wiederholt; der Empfänger fordert ein fehlendes "
    "Segment erneut an":
        "Dup ACK #{n} – ACK={ack} repeated; the receiver is requesting a missing "
        "segment again",

    # --- Bezeichner, die im Core deutsch bleiben (GUI übersetzt bei Anzeige) #
    # Experten-Info-Kategorie (Finding.category)
    "Erstkontakt": "First contact",
    # Verbindungszustände (ConnState.state)
    "Zurückgesetzt (RST)": "Reset (RST)",
    "Geschlossen (FIN)": "Closed (FIN)",
    "Aktiv (established)": "Active (established)",
    "Aufbau (SYN/ACK)": "Opening (SYN/ACK)",
    "Fehlgeschlagen (keine Antwort)": "Failed (no response)",
    "Unvollständig": "Incomplete",
}
