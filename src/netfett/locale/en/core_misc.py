"""Englische Übersetzungen für Kern-Hilfsmodule (Capture, ETW, PCAP, GeoIP, TLS, CLI …)."""

MESSAGES: dict[str, str] = {
    # cli.py
    "NetFett – Headless-Analyse": "NetFett – headless analysis",
    "DATEI": "FILE",
    "Capture-Datei(en) (pcap/pcapng); mehrere = zusammenführen":
        "Capture file(s) (pcap/pcapng); multiple = merge",
    "Zusammenfassung ausgeben": "Print summary",
    "Analyse exportieren": "Export analysis",
    "Fehler beim Lesen: {exc}": "Error while reading: {exc}",
    "{n} Pakete gelesen aus {files}": "{n} packets read from {files}",
    "Export fehlgeschlagen: {exc}": "Export failed: {exc}",
    "  Bytes gesamt: {n}": "  Total bytes: {n}",
    "  Top-Protokolle:": "  Top protocols:",
    "    {name:<10} {pk:>7} Pakete  {by:>10} Bytes":
        "    {name:<10} {pk:>7} packets {by:>10} bytes",
    "  Verbindungen: {n}": "  Conversations: {n}",
    "{packets} Pakete / {bytes} Bytes": "{packets} packets / {bytes} bytes",

    # core/displayfilter.py
    "Ungültiger Port: {value!r}": "Invalid port: {value!r}",

    # core/coloring.py – Namen der Standard-Regeln (bleiben in den Daten deutsch,
    # die GUI übersetzt sie bei der Anzeige)
    "Fehler/Reset": "Errors/Reset",

    # core/procmap.py – Bezeichner (bleibt in den Daten deutsch)
    "unbekannt": "unknown",

    # core/etw.py
    "ungültige GUID: {text}": "invalid GUID: {text}",
    "ETW-Backend unterstützt nur 64-Bit-Python.":
        "The ETW backend only supports 64-bit Python.",
    "{name}: {size} statt {want}": "{name}: {size} instead of {want}",
    "Struktur-Layout passt nicht: {details}": "Structure layout mismatch: {details}",
    "ETW gibt es nur unter Windows.": "ETW is only available on Windows.",
    "Zugriff verweigert – ETW-Mitschnitt erfordert Administratorrechte.":
        "Access denied – ETW capture requires administrator rights.",
    "StartTrace fehlgeschlagen (Fehler {rc}).": "StartTrace failed (error {rc}).",
    "EnableTraceEx2 fehlgeschlagen (Fehler {rc}).": "EnableTraceEx2 failed (error {rc}).",
    "OpenTrace fehlgeschlagen (Fehler {err}).": "OpenTrace failed (error {err}).",
    "ProcessTrace endete mit Fehler {rc}.": "ProcessTrace ended with error {rc}.",
    "Event-Verarbeitung: {exc}": "Event processing: {exc}",

    # core/capture.py
    "SIO_RCVALL wird nur unter Windows unterstützt.":
        "SIO_RCVALL is only supported on Windows.",
    "Zugriff verweigert – bitte NetFett als Administrator starten.":
        "Access denied – please run NetFett as administrator.",
    "Schnittstelle konnte nicht geöffnet werden: {exc}":
        "Could not open interface: {exc}",

    # core/pcap.py
    "Datei zu kurz für PCAP.": "File too short for PCAP.",
    "Keine gültige PCAP-Datei (falsche Magic-Number).":
        "Not a valid PCAP file (wrong magic number).",
    "Keine gültige pcapng-Datei.": "Not a valid pcapng file.",

    # core/whois.py
    "(Referral {ref} nicht erreichbar: {exc})": "(Referral {ref} unreachable: {exc})",

    # core/geoip.py
    "GeoIP nicht verfügbar – Paket 'maxminddb' fehlt (pip install maxminddb).":
        "GeoIP not available – package 'maxminddb' is missing (pip install maxminddb).",
    "Konnte GeoIP-Datenbank nicht laden: {exc}": "Could not load GeoIP database: {exc}",
    "GeoIP-Datenbank geladen: {path}": "GeoIP database loaded: {path}",
    "GeoIP: Bibliothek 'maxminddb' nicht installiert.":
        "GeoIP: library 'maxminddb' not installed.",
    "GeoIP: keine Datenbank geladen.": "GeoIP: no database loaded.",
    "GeoIP: {n} Datenbank(en) geladen.": "GeoIP: {n} database(s) loaded.",

    # core/ioc.py
    "Treffer auf {hit}: {src} → {dst}": "Match on {hit}: {src} → {dst}",

    # core/extract.py
    "objekt": "object",

    # core/tlssession.py
    "cryptography-Bibliothek nicht verfügbar.": "cryptography library not available.",
    "Keine TLS-Schlüssel geladen (SSLKEYLOGFILE).": "No TLS keys loaded (SSLKEYLOGFILE).",
    "Kein vollständiger TLS-Strom rekonstruierbar.":
        "Could not reconstruct a complete TLS stream.",
    "ClientHello/ServerHello nicht gefunden.": "ClientHello/ServerHello not found.",
    "Cipher-Suite 0x{cipher_id:04x} nicht unterstützt.":
        "Cipher suite 0x{cipher_id:04x} not supported.",
    "Passende TLS-1.3-Secrets fehlen in der Keylog.":
        "Matching TLS 1.3 secrets are missing from the key log.",
    "Master-Secret (CLIENT_RANDOM) fehlt in der Keylog.":
        "Master secret (CLIENT_RANDOM) is missing from the key log.",
    "Entschlüsselung lieferte keine Daten (falsche/fehlende Schlüssel?).":
        "Decryption produced no data (wrong/missing keys?).",
    "{version}, Cipher 0x{cipher_id:04x} – entschlüsselt.":
        "{version}, cipher 0x{cipher_id:04x} – decrypted.",

    # core/oui.py
    "(zufällige MAC)": "(random MAC)",
}
