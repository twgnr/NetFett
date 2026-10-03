# NetFett

*[Deutsche Version](README.de.md)*

**NetFett** is a full-featured network monitor and protocol analyzer written in **pure
Python** with a **PySide6** user interface. It captures incoming and outgoing IPv4/IPv6
traffic via a Windows raw socket (`SIO_RCVALL`) – **without Npcap/WinPcap**.
Dependencies: **PySide6** (GUI) and **cryptography** (only for the optional
TLS decryption); all of the analysis logic works without third-party dependencies.

> Capture · Dissect · Filter · Visualize · Analyze – all offline.

> **Language:** The user interface is available in **English (default) and German**
> (*View → Sprache / Language*, takes effect after a restart). Menu names below
> refer to the English interface.

---

## Features

**Capture & display**
- Live capture of all IPv4 traffic on an interface (incoming/outgoing)
- Packet list with No., time, source/destination (incl. port), protocol, length,
  direction (▲ out / ▼ in) and a compact info line
- Layer detail view (tree) and – switchable via tabs – **Hex** or
  **Content**: the actual payload as **plain text** (unencrypted)
  or as **bytes/hex** (encrypted, e.g. TLS), with direction indicator
- Hex dump with **byte highlighting**: click a layer/field → the corresponding
  bytes light up in hex **and** ASCII
- Detail **context menu**: copy a field value or **apply it as a filter** directly
  (e.g. source → `host …`, destination port → `dst port …`)
- Auto-scroll that follows the newest row during live capture
- Switchable **time format**: relative (since start), time of day or absolute (epoch)
- **Mark** packets (Ctrl+M, highlighted), "next mark" (F8)

**Protocol dissection (dissector)**
- IPv4 **and IPv6** (incl. extension headers), TCP, UDP, ICMP, ICMPv6
- **TCP options** (MSS, window scale, SACK, timestamps) are decoded
- **IP fragment reassembly** (IPv4 **and** IPv6): fragmented datagrams
  are reassembled; the last fragment shows the complete protocol
- Application layer: DNS, mDNS, **DHCP**, **NTP**, **QUIC**, TLS, HTTP,
  **HTTP/2** (h2c) with **HPACK header decoding** (RFC 7541, incl. Huffman +
  dynamic table; over TLS after decryption), **SMB/SMB2** (incl.
  command, file name/path), **SIP** and **RTP** (heuristic)
- **Plain-text mail**: **SMTP** (incl. MAIL FROM/RCPT TO/AUTH), **POP3**, **IMAP**
  – with direction and anomaly marking
- **FTP control channel** (commands/replies) and **SSH** (version banner +
  plain-text handshake messages such as KEXINIT/NEWKEYS)
- "**Decode As**": force port→protocol mapping (e.g. 8443 as TLS)
- **IP classification** (offline): detects special ranges (private, loopback,
  CGNAT, link-local, multicast, documentation …) and well-known DNS resolvers
- **TLS handshake**: server name (**SNI**), negotiated **version** and
  **cipher suite** (Client/Server Hello)
- **HTTP**: request/status line (method, path, status) and **all headers** in the
  detail view → shows which domain is contacted (even without DNS)
- Ports of many well-known services are named

**Display filter** (compact, robust filter language)
```
tcp                      udp        icmp        dns        tls       http       https
host <ip>                src <ip>   dst <ip>
port <n>                 src port <n>           dst port <n>
in                       out
<free text>              not <term> / ! <term>  <a> or <b>
```
Examples: `tcp dst port 443`, `dns or mdns`, `host 192.168.0.10 not port 53`
Recently used filters are available as a **history** (▼) in the filter field.

**Live statistics & visualization**
- Throughput graph (B/s, in/out) and packet graph (P/s, in/out)
- **Donut chart** of the distribution – switchable between **protocols**,
  **programs** and **categories** (browser, communication, system, e-mail,
  media …); clicking a segment/legend entry sets a matching filter
- **Bar chart** of the top talkers
- **IO time chart** per connection (bytes/s per direction) in the connections dialog
- Statistics panel: top protocols (by volume, with %) and top talkers as a
  table – all charts/tables refresh every second

**Analysis**
- **Conversations:** aggregation per flow with packets/bytes per
  direction, duration and throughput
- **Follow TCP Stream:** sequence-correct reconstruction of the byte stream, client/
  server color-coded, switchable ASCII ⇄ hex
- **Expert info:** TCP resets, retransmissions, ICMP unreachable,
  **port/host scans**, **beaconing**, **plain-text credentials**,
  **DNS tunneling**, **exfiltration** (large upload) and **first contacts**
  (new external hosts). Additionally:
  - **TLS hygiene:** outdated TLS version (SSLv3/1.0/1.1), weak ciphers,
    self-signed/expired certificates, SNI↔certificate mismatch
  - **DNS anomalies:** suspected DGA (random domains), high
    NXDOMAIN rate per host, DNS amplification (response ≫ query)
  - **Scan/connection:** SYN flood/half-open, high connection failure rate,
    risky destination ports (Telnet/RDP/VNC/DB/malware), Telnet plain-text login
  - **Volume/DoS/tunneling:** traffic spikes/floods per host,
    ICMP tunneling (large echo payload), NTP monlist (amplification)
- **Mark TCP problems:** highlight retransmission/dup-ACK/out-of-order per packet in
  the list (*Analyze* menu)
- **Service response time:** response times per protocol (DNS/HTTP/SMB2)
- **Flow graph:** global ladder diagram of all connections (top hosts)
- **TLS certificates:** subject/issuer/validity from the handshake
- **TCP health:** per connection handshake RTT, retransmissions, dup ACKs
  and zero-window events
- **Protocol hierarchy:** tree of the protocol distribution by packets/bytes
- **DNS analysis:** query↔response correlation, response times, NXDOMAIN rate,
  most-queried names and resolved A/AAAA/CNAME addresses
- **Endpoints & ports:** volume per individual host (sent/received),
  top service ports and packet size distribution; with a GeoIP database loaded,
  also **country / ASN** per host
- **GeoIP (optional):** country/city/ASN via MaxMind **GeoLite2** files
  (*Tools → Load GeoIP Database*). Requires the
  optional package `maxminddb` (`pip install netfett[geoip]`) and a GeoLite2 `.mmdb`
  you obtain yourself; NetFett does not ship any GeoIP data
- **Connection state:** TCP lifecycle per flow (established / FIN /
  reset / failed), setup time and duration
- **RTP streams:** per SSRC packet count, **packet loss** and **jitter** (RFC 3550)
- **JA3/JA3S fingerprint** of the TLS handshake (in the detail view)
- **TLS decryption** with an `SSLKEYLOGFILE` (TLS 1.2/1.3, AEAD): load the keys
  via *Tools → Load TLS Keys*, then click
  *Decrypt* in Follow Stream – shows the plain text instead of the
  encrypted bytes
- **Network topology:** node-edge diagram of "who talks to whom"
  (hosts as nodes, connection volume = edge thickness)
- **Device overview / IP scan:** active **ICMP ping sweep** of the local
  subnet with enriched device info – **device name** (NetBIOS, **mDNS/
  Bonjour**, **SNMP sysName** or reverse DNS), **MAC** (from the ARP table),
  **vendor** (OUI; optionally Wireshark's `manuf`), **web address** (port 80/443,
  page title if available) and RTT – **plus** a **small live throughput graph** per
  device (▲ sent / ▼ received).
  **Double-click** a device to filter the main view on it; clicking the
  **web address** opens it in the browser.
- **IO graph:** throughput/packets over time with up to 5 custom filter lines
- **IOC/threat matching:** load a blocklist (IPs/CIDRs/domains) from a file,
  report hits and mark them in the packet list
- **File/object extraction:** extract objects from HTTP (including decrypted TLS)
  streams, view them (text/image) and save them
- **TCP stream graphs:** sequence number, throughput and window over time
- **Filtered statistics** and **"Decode As"** (force port→protocol)
- **Program traffic:** graphical live breakdown of traffic **by
  program** – donut (volume), **history graph** (bytes/s per top program)
  and table. Additionally an optional **program column** in the packet list
  (*View → Program Column*). Packets are mapped to
  programs via the Windows connection tables (local port → PID → program) – only
  during live capture and most complete when running as administrator.
- **Visited domains:** overview of all contacted domains (from DNS queries,
  TLS SNI and HTTP Host); double-click to set one as a filter
- **Name resolution (reverse DNS):** PTR names of remote peers in the
  connections dialog and as an optional **column** in the packet list
  (*View → Name Column*; cached, in the background)
- **Sequence diagram:** packet flow of a connection (client ↔ server over
  time) – in the conversations dialog
- **Search** (Ctrl+F / F3) jumps through the displayed packets
- **Context menu** (right-click): follow stream, set as filter (connection/
  host/port)

**Long-term capture**
- **Live capture** directly into a PCAP file (streaming – no RAM build-up)
- **Ring buffer/packet limit**: keep only the last *N* packets in memory
- **Capture filter**: discard uninteresting packets before they are stored
  (same syntax as the display filter); numbering stays gapless

**Tools** (*Tools* menu)
- **Ping** and **traceroute** (ICMP, own raw socket – admin rights required)
- **DNS lookup** (forward and reverse resolution, no elevated rights needed)
- **WHOIS** (TCP/43, with referral – registrant/network range of a domain/IP)

**Help**
- Built-in **manual** (*Help → Manual*, key **F1**) with guidance
  on capture, filters, analysis, TLS decryption and tools (German and English)

**Files & export**
- **Open** PCAP/**PCAPNG** (also **merge multiple files**) and
  **save** – classic (`.pcap`) or modern (`.pcapng`); optionally save only the
  currently **displayed** packets
- **Rotating capture** into ring files (by size, limited count)
- **Export** the packet list, conversations or domains to **CSV** or **JSON**

**Usability**
- Switchable **dark or light theme** (*View → Light Theme*)
- **Language: German or English** (*View → Sprache / Language*; applied after a
  restart, NetFett offers to restart right away)
- Packet list **sortable** (click the column header) and columns can be
  **shown/hidden** (right-click the column header)
- **Custom coloring rules** (*View → Coloring Rules*):
  color rows by your own filter expressions, with editor and persistence
- **Settings are persisted** (theme, window size, packet limit,
  auto-scroll, capture filter, etc. – via QSettings)
- **Profiles** (named settings sets: save/load/delete),
  **Go to packet** (Ctrl+G), **packet comments** (right-click; exported as
  pcapng comments) and **recently opened files**

---

## Download (Windows)

Grab the latest **`NetFett-<version>-win64.exe`** from the
[Releases page](https://github.com/twgnr/NetFett/releases) – a single file, no
installation and no Python needed. Windows SmartScreen may warn on first start
because the file is not code-signed (*More info → Run anyway*). Compare the file
with the published `.sha256` checksum if in doubt.

## Installation from source

Requirement: **Python ≥ 3.11** (Windows for live capture).

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

This installs PySide6 and creates the `netfett` console script.

### Building the .exe yourself
```powershell
pip install -e .[build]
python packaging/make_icon.py      # only needed if the icon is missing
python packaging/build.py          # → dist/NetFett-<version>-win64.exe
```

## Running

```powershell
# Conveniently via the console script …
netfett
# … or as a module:
python -m netfett
```

> **Note:** **Live capture** on Windows requires
> **administrator rights** (raw socket / `SIO_RCVALL`). Start PowerShell
> or NetFett "as administrator". **Opening and analyzing
> PCAP files** works without elevated rights.

### Quick start
1. Select the interface (local IPv4 address) at the top left
2. **▶ Start** – packets start coming in
3. Optionally filter, e.g. `tcp dst port 443`
4. Click a packet → details + hex/content; right-click → **Follow TCP stream**
5. **Analyze** menu → conversations / expert info / topology …
6. **F1** opens the built-in manual.

### Command line (headless, no GUI)
```powershell
# Read a capture and print a summary
python -m netfett --read capture.pcapng --stats
# Export conversations as CSV (multiple files are merged)
python -m netfett --read a.pcap b.pcap --export conversations.csv --what conversations
```
Datasets: `--what packets|conversations|domains`, format `--format csv|json`.

---

## Architecture

Clear separation between **pure logic** (`core/`, no GUI/I/O – fully covered by
unit tests) and **user interface** (`gui/`).

```
src/netfett/
├─ __main__.py            entry point (GUI or headless, UAC elevation)
├─ cli.py                 headless mode (--read/--stats/--export)
├─ elevate.py             Windows UAC elevation (restart as administrator)
├─ core/                  pure, tested logic
│  ├─ capture.py          Windows raw socket (SIO_RCVALL), background thread
│  ├─ dissect.py          packet dissection IPv4/IPv6/TCP/UDP/ICMP/DNS/DHCP/NTP/
│  │                      QUIC/TLS/HTTP (+ TCP options, Decode As)
│  ├─ models.py           Packet / Layer (data models)
│  ├─ displayfilter.py    display filter (text → packet predicate)
│  ├─ stats.py            running statistics (throughput, packets/s, distribution)
│  ├─ analyze.py          conversations, follow stream, expert info,
│  │                      hierarchy, visited domains
│  ├─ pcap.py             PCAP read/write + PcapWriter (streaming capture)
│  ├─ reassemble.py       IP fragment reassembly (IPv4/IPv6)
│  ├─ scan.py             active IP scan (ping sweep + device enrichment)
│  ├─ arp.py              read ARP table (IP → MAC, GetIpNetTable)
│  ├─ oui.py              MAC OUI → vendor (+ optional manuf file)
│  ├─ netbios.py          NetBIOS name query (device name on the LAN)
│  ├─ mdns.py             mDNS/Bonjour name query (.local hostname)
│  ├─ snmp.py             SNMPv1 GET for sysName (device name)
│  ├─ hoststats.py        throughput statistics per host IP (device overview)
│  ├─ resolve.py          reverse DNS (IP → hostname), cached, concurrent
│  ├─ ipinfo.py           offline IP classification (special ranges/services)
│  ├─ ja3.py              JA3/JA3S fingerprinting from TLS Hello
│  ├─ tlskeys.py          SSLKEYLOGFILE + key derivation (HKDF/PRF)
│  ├─ tlsdecrypt.py       AEAD record decryption (cryptography)
│  ├─ tlssession.py       decrypt an entire TLS connection
│  ├─ extract.py          HTTP object/file extraction
│  ├─ procmap.py          packet→program via Windows connection tables
│  ├─ content.py          extract payload + classify plain text/bytes
│  ├─ categories.py       classify traffic by category (browser/system/…)
│  ├─ coloring.py         custom coloring rules (filter→color)
│  ├─ ioc.py              IOC/threat matching against a blocklist
│  ├─ export.py           CSV/JSON export (packets, conversations, domains)
│  ├─ tools.py            ping, traceroute, DNS lookup (testable ICMP building blocks)
│  ├─ whois.py            WHOIS (TCP/43, with referral)
│  ├─ interfaces.py       determine local IPv4/IPv6 addresses
│  └─ protocols.py        protocol/port names, ICMP types
└─ gui/
   ├─ main_window.py      main window: wires all components together
   ├─ capture_controller.py  bridge capture thread → Qt (buffered, smooth)
   ├─ packet_model.py     table model of the packet list (sorting, rules)
   ├─ graph_widget.py     live graph (custom QPainter)
   ├─ charts.py           donut/bar/multi-line charts (custom QPainter)
   ├─ theme.py            dark/light color scheme + chrome stylesheets
   ├─ tools_dialogs.py    dialogs: ping, traceroute, DNS lookup, WHOIS
   ├─ analysis_dialogs.py dialogs: conversations, expert info, follow stream,
   │                      hierarchy, domains, DNS, endpoints, state, …
   ├─ pro_dialogs.py      coloring rules, IO graph, IOC, topology, objects,
   │                      stream graph, Decode As
   └─ help_dialog.py      in-app manual and "About"
```

The raw socket delivers packets **starting at the IPv4 header** (no Ethernet layer);
accordingly, the PCAP link type `RAW` (101) is used.

---

## Tests

```powershell
pip install pytest
pytest
```

The `core` layer is testable without a GUI; the more than 130 tests cover the dissector,
display filter, statistics/PCAP(NG), analysis, TLS crypto, IP classification,
categories, coloring/IOC, object extraction and headless mode.

---

## Limitations

- **Windows only** for live capture (`SIO_RCVALL`); PCAP analysis is
  platform-independent.
- **IPv6** is dissected and (best effort, via a second raw socket) also
  captured live; the raw socket does not deliver non-IP protocols (e.g. ARP).
- Requires **administrator rights** for capturing.
- The dissector covers the most important protocols (incl. HTTP/2, SMB, SIP,
  RTP) but makes no claim to complete coverage. HTTP/2 only in
  plain text (h2c); over TLS only after decryption. RTP detection is
  heuristic (no fixed ports).

## License

[MIT](LICENSE) © 2026 Tobias Wagner. The Windows executable bundles third-party
components (including Qt/PySide6 under LGPL-3.0) – see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
