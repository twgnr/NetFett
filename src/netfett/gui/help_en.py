"""English translation of the in-app manual (mirrors ``help_dialog._HELP_HTML``)."""
from __future__ import annotations

HELP_HTML_EN = """
<h1>NetFett – Manual</h1>
<p><b>NetFett</b> captures and analyzes network traffic (IPv4/IPv6) via a
Windows raw socket – a full-featured network monitor in pure Python. This
manual explains <i>every</i> view: what is shown, where to find it and how to
interpret it.</p>

<h3>Contents</h3>
<ul>
<li><a href="#start">1. Quick Start &amp; Permissions</a></li>
<li><a href="#layout">2. Main Window Layout</a></li>
<li><a href="#toolbar">3. Toolbar (top)</a></li>
<li><a href="#graphs">4. Live Graphs (Throughput / Packets)</a></li>
<li><a href="#list">5. The Packet List – Columns &amp; Colors</a></li>
<li><a href="#detail">6. Detail Tree, Hex and Content</a></li>
<li><a href="#filter">7. Display Filter (Syntax)</a></li>
<li><a href="#stats">8. Statistics Panel (right)</a></li>
<li><a href="#statusbar">9. Status Bar (bottom)</a></li>
<li><a href="#analyse">10. "Analysis" Menu – All Analyses</a></li>
<li><a href="#tools">11. "Tools" Menu</a></li>
<li><a href="#view">12. "View" Menu</a></li>
<li><a href="#capture">13. "Capture" Menu (Recording/Filters)</a></li>
<li><a href="#tls">14. Decrypting TLS &amp; HTTP/2</a></li>
<li><a href="#interpret">15. Interpreting the Values</a></li>
<li><a href="#keys">16. Keyboard Shortcuts</a></li>
<li><a href="#limits">17. Limitations</a></li>
</ul>

<hr>
<h2 id="start">1. Quick Start &amp; Permissions</h2>
<ol>
<li>Select the <b>interface</b> (local IP address) at the top left.</li>
<li>Click <b>▶ Start</b> – the list fills with live packets.</li>
<li>Click a row → the detail tree, Hex and Content appear below.</li>
<li><b>■ Stop</b> ends the capture; <b>Clear</b> discards all packets.</li>
</ol>
<p><b>Important – administrator rights:</b> Live capture requires a raw socket
and therefore admin rights. If the window title shows <i>(Administrator)</i>,
everything is ready. Otherwise: <i>Capture → Restart as Administrator…</i>
or open an existing PCAP file (no special rights needed).</p>

<h2 id="layout">2. Main Window Layout</h2>
<p>From top to bottom the window is split into three resizable areas
(drag the dividers), plus a dockable panel on the right:</p>
<ul>
<li><b>Top – Live graphs:</b> throughput (B/s) and packet rate (P/s).</li>
<li><b>Middle – Packet list:</b> one row per packet (the core of the app).</li>
<li><b>Bottom – Packet details:</b> the layer tree on the left, the tabs
<i>Hex</i> and <i>Content</i> on the right.</li>
<li><b>Right – Statistics panel:</b> distributions and top talkers (shown/hidden
via the <i>Statistics</i> toolbar toggle).</li>
</ul>

<h2 id="toolbar">3. Toolbar (top)</h2>
<table border="1" cellspacing="0" cellpadding="4">
<tr><th>Element</th><th>Function</th></tr>
<tr><td><b>Interface</b></td><td>Local IP to capture on. With several network
adapters, pick the right one.</td></tr>
<tr><td><b>▶ Start / ■ Stop</b></td><td>Start/stop live capture.</td></tr>
<tr><td><b>Clear</b></td><td>Discards all captured packets and statistics.</td></tr>
<tr><td><b>⤓ Auto-Scroll</b></td><td>When active, the list always jumps to the
newest row. Turn it off to scroll back.</td></tr>
<tr><td><b>Statistics</b></td><td>Shows/hides the statistics panel on the right.</td></tr>
<tr><td><b>Open PCAP…</b></td><td>Reads a saved capture
(<code>.pcap</code>/<code>.pcapng</code>) for offline analysis.</td></tr>
<tr><td><b>Save PCAP…</b></td><td>Writes the current packets to a file
(pcapng also keeps packet comments).</td></tr>
<tr><td><b>Filter</b></td><td>Display filter – see <a href="#filter">section 7</a>.
The input turns red on errors; <span style="color:#888">▼</span> shows the
recently used filters.</td></tr>
</table>

<h2 id="graphs">4. Live Graphs</h2>
<p>The two upper charts show the last ~60 seconds:</p>
<ul>
<li><b>Throughput (B/s):</b> bytes transferred per second.</li>
<li><b>Packets (P/s):</b> packets per second.</li>
</ul>
<p>Both distinguish <b>incoming</b> and <b>outgoing</b> traffic by color. This lets you
spot load peaks at a glance and see whether data is being sent or received.</p>

<h2 id="list">5. The Packet List – Columns &amp; Colors</h2>
<p>Each row is a packet. The columns:</p>
<table border="1" cellspacing="0" cellpadding="4">
<tr><th>Column</th><th>Meaning / Interpretation</th></tr>
<tr><td><b>No.</b></td><td>Sequential capture number (stable, even when
filtering/sorting).</td></tr>
<tr><td><b>Time</b></td><td>Timestamp. Format switchable (<i>View →
Time Format</i>): <b>Relative</b> (seconds since the first packet), <b>Time of Day</b>
or <b>Absolute</b> (epoch seconds).</td></tr>
<tr><td><b>Source / Destination</b></td><td>Sender and receiver IP, with port for
TCP/UDP. With the <i>name column</i> enabled, the reverse DNS name as well.</td></tr>
<tr><td><b>Protocol</b></td><td>Highest detected layer (e.g. TLS, DNS, HTTP,
SMTP, SSH). Also determines the subtle row tint.</td></tr>
<tr><td><b>Length</b></td><td>Packet size in bytes (from the IP header – there is no
Ethernet frame, see <a href="#limits">Limitations</a>).</td></tr>
<tr><td><b>Dir.</b></td><td>Direction: <span style="color:#ffb454">▲ outgoing</span>
(from this PC) or <span style="color:#5aa9ff">▼ incoming</span>.</td></tr>
<tr><td><b>Info</b></td><td>Compact summary: TCP flags, DNS names,
HTTP request line, TLS SNI, reassembled fragments etc.</td></tr>
<tr><td><b>Name</b></td><td>(optional) Reverse DNS of the remote host.</td></tr>
<tr><td><b>Program</b></td><td>(optional) Local process of the connection
(name/PID), if it can be determined.</td></tr>
</table>
<p><b>Colors &amp; highlights:</b></p>
<ul>
<li><b>Protocol tint</b> (in the dark theme): e.g. TLS bluish, DNS violet,
HTTP yellowish – for quick visual grouping.</li>
<li><b>Custom coloring rules</b> (<i>View → Coloring Rules</i>) take
precedence over the protocol tint.</li>
<li><span style="background:#3a2f0a">&nbsp;Amber + bold&nbsp;</span> = <b>manually
marked</b> packet (Ctrl+M).</li>
<li><span style="background:#3a2a10">&nbsp;Amber&nbsp;</span> = <b>TCP problem</b>,
when <i>Analysis → Mark TCP Problems</i> is active. Hovering shows the
<b>reason</b> (retransmission/dup ACK/out-of-order with explanation).</li>
<li>A <b>💬 in the tooltip</b> indicates that the row carries a comment.</li>
</ul>
<p><b>Using the list:</b></p>
<ul>
<li><b>Sort:</b> click a column header.</li>
<li><b>Show/hide columns:</b> right-click the column header.</li>
<li><b>Right-click a row:</b> <i>Follow TCP Stream</i>, apply connection/host/
port <i>as filter</i>, or add a <i>comment</i>.</li>
<li><b>Ctrl+M</b> marks/unmarks, <b>F8</b> jumps to the next mark,
<b>Ctrl+G</b> jumps to a packet number.</li>
</ul>

<h2 id="detail">6. Detail Tree, Hex and Content</h2>
<p>Clicking a packet fills the lower area:</p>
<ul>
<li><b>Detail tree (left):</b> all protocol layers as an expandable tree
(IP → TCP/UDP → application) with field name and value. <b>Clicking a field</b>
highlights the corresponding bytes in the Hex tab. Right-click: <i>copy
value/field</i> or apply the field <i>as filter</i>.</li>
<li><b>"Hex" tab:</b> classic hex dump with ASCII column; the bytes belonging to
the selected field light up in hex <i>and</i> ASCII.</li>
<li><b>"Content" tab:</b> the payload as <b>plain text</b> (unencrypted,
e.g. HTTP/DNS/mail) or as <b>bytes</b> (encrypted, e.g. TLS), with the
direction.</li>
</ul>

<h2 id="filter">7. Display Filter (Syntax)</h2>
<p>The filter field hides packets without discarding them. Multiple terms
are combined with <b>AND</b>; <code>or</code> combines with OR,
<code>not</code> negates.</p>
<pre>Protocols:  tcp  udp  icmp  igmp  arp  dns  mdns  tls  http  https
            smtp  imap  pop3  mail  ftp  ssh
Addresses:  host &lt;ip&gt;     src &lt;ip&gt;     dst &lt;ip&gt;
Ports:      port &lt;n&gt;      src port &lt;n&gt;   dst port &lt;n&gt;
Direction:  in           out
Logic:      not &lt;term&gt;    &lt;a&gt; or &lt;b&gt;     any free text</pre>
<p>Examples:</p>
<pre>tcp dst port 443 not host 10.0.0.5
dns or mdns
mail                      (= SMTP/IMAP/POP3)
host 192.168.0.10 out</pre>
<p>Invalid input turns the field red. With <i>Analysis → Find</i> (Ctrl+F)
you can additionally search the <b>content</b> of the packets; <b>F3</b> = find next.
Tip: clicking a donut segment in the statistics panel automatically sets the
matching protocol/program filter.</p>

<h2 id="stats">8. Statistics Panel (right)</h2>
<p>Updates every second:</p>
<ul>
<li><b>Distribution donut</b> – switchable via a selector between
<b>protocols</b>, <b>programs</b> and <b>categories</b> (each by
byte volume). <b>Clicking a segment</b> filters the list accordingly
(categories are for overview only).</li>
<li><b>Table below:</b> the same values as packets, bytes and percent.</li>
<li><b>Top talkers</b> – the highest-volume connections (source ⇄ destination) as
bars and a table.</li>
</ul>
<p>With <i>View → Statistics on Filter Only</i>, analyses only consider the
currently visible (filtered) packets.</p>

<h2 id="statusbar">9. Status Bar (bottom)</h2>
<p>On the left the current state (Ready/Capturing/Filter active/Error …),
on the right the counters:</p>
<ul>
<li><b>Packets: shown / total</b> – the difference was hidden by the display filter.</li>
<li><b>(Ring N)</b> – a packet limit (ring buffer) is set.</li>
<li><b>dropped N</b> – this many packets were discarded by the <i>capture</i> filter.</li>
<li><b>▼ / ▲</b> – total amount of data received or sent.</li>
</ul>

<h2 id="analyse">10. "Analysis" Menu – All Analyses</h2>
<p>All analyses open in their own windows. Double-clicking a row usually
sets a matching filter or jumps to the packet.</p>

<h3>Conversations</h3>
<p>All flows: <i>protocol, endpoint A, endpoint B, packets, A→B, B→A, bytes,
duration, throughput</i>. Right-click per connection: <i>Follow Stream</i>,
<i>Sequence Diagram</i>, <i>TCP Stream Graph</i>, <i>Extract Objects</i>,
<i>Resolve Names</i>. <b>How to read it:</b> high "B→A" with small "A→B" = download;
very short duration with few packets = aborted/rejected connection.</p>

<h3>Expert Information</h3>
<p>Automatically detected anomalies: <i>severity, category, description,
packet</i>. Severity levels: <b>info</b> (e.g. first contact with a new host) ·
<b>note</b> (e.g. TCP reset) · <b>warn</b> (e.g. scan, ICMP error,
DNS tunneling) · <b>error</b> (e.g. plaintext passwords, exfiltration).
Categories include TCP, ICMP, Security, TLS, DNS, First Contact. Double-click jumps
to the packet. Detected among others:</p>
<ul>
<li><b>TLS hygiene:</b> outdated TLS version (SSLv3/1.0/1.1), weak
cipher suites, self-signed/expired certificates, SNI↔certificate mismatch.</li>
<li><b>DNS:</b> DGA suspicion (random-looking domains), high NXDOMAIN rate per
host (malware trying many names), DNS amplification (response ≫ query).</li>
<li><b>Scan/connection:</b> SYN flood/half-open, high connection failure rate
(many RSTs), connections to risky ports (Telnet/RDP/VNC/databases/known
malware ports), Telnet plaintext login.</li>
<li><b>Volume/DoS:</b> traffic spikes/floods per host, possible ICMP tunneling
(large/regular echo payload), NTP "monlist" (amplification risk).</li>
<li><b>Classic:</b> port/host scan, beaconing (C2 suspicion),
plaintext passwords, DNS tunneling, exfiltration, first contacts.</li>
</ul>

<h3>TCP Health</h3>
<p>Per connection: <i>endpoint A/B, packets, RTT, retrans., dup ACK, zero win</i>.
<b>Interpretation:</b> high <i>retrans.</i> (retransmissions) or <i>dup ACK</i>
indicate packet loss; <i>zero win</i> &gt; 0 means a receiver was
overloaded (receive window full); <i>RTT</i> is the measured round-trip time.</p>

<h3>Protocol Hierarchy</h3>
<p>Tree of all protocols with their share of packets and bytes – shows the
composition of the traffic.</p>

<h3>Visited Domains</h3>
<p><i>Domain, packets, source</i> collected from DNS queries and TLS SNI – a
quick overview of "where did we connect to".</p>

<h3>DNS Analysis</h3>
<p><i>Name, type, queries, responses, NXDOMAIN, avg. time, addresses</i>.
<b>Interpretation:</b> many <i>NXDOMAIN</i> (non-existent names) can point to
typos, malware domains or search suffixes; <i>avg. time</i> is
the resolver's mean response time.</p>

<h3>Endpoints &amp; Ports</h3>
<p>Three parts: <b>hosts</b> by volume (<i>host, packets, bytes, ↑ sent,
↓ received</i>, plus <i>country/ASN</i> when a GeoIP DB is loaded),
<b>service ports</b> (<i>port, service, L4, packets, bytes</i>) and a
<b>packet size histogram</b>. Double-click filters on the host or port.</p>

<h3>Connection States</h3>
<p>TCP life cycle per flow: <i>endpoint A/B, state, setup, duration, packets</i>.
State color coding: <span style="color:#f85149">red</span> =
<i>Reset (RST)</i> or <i>Failed (no response)</i>,
<span style="color:#d29922">amber</span> = <i>Setup (SYN/ACK)</i> or
<i>Incomplete</i>, neutral = cleanly established/closed. <i>Setup</i> is the
handshake duration.</p>

<h3>RTP Streams</h3>
<p>VoIP/media streams: <i>SSRC, source, destination, PT (payload type), packets, loss,
jitter, duration</i>. High <i>loss</i> or <i>jitter</i> = poor voice/
video quality.</p>

<h3>Program Traffic</h3>
<p>Aggregated by local program: <i>program, packets, bytes, ↑ sent,
↓ received</i> – shows which application generates how much network load.</p>

<h3>Network Topology</h3>
<p>Graphical map of communication relationships (who talks to whom).</p>

<h3>Device Overview / IP Scan</h3>
<p>Scans the local network (ping scan, <b>requires admin rights</b>) and shows a card
per device with <i>device name, MAC, vendor, web address</i> and a
small live throughput graph. <b>Double-clicking</b> a card filters the
main list to this device; <b>clicking the web address</b> opens it in the
browser.</p>

<h3>IO Graph</h3>
<p>Traffic over time, switchable between <i>bytes/s</i> and
<i>packets/s</i> – useful for matching peaks to a point in time.</p>

<h3>IOC Matching</h3>
<p>Matches domains/IPs against known indicators: <i>severity,
indicator/description, packet</i>.</p>

<h3>Service Response Time</h3>
<p>Response times per protocol (DNS/HTTP/SMB2): <i>protocol, requests, avg, min,
max</i> – shows which service responds slowly.</p>

<h3>Flow Graph</h3>
<p>Global ladder diagram of the most important connections over time – each
row an event, arrows show the direction.</p>

<h3>Further Items</h3>
<ul>
<li><b>Mark TCP Problems</b> (toggle): highlights retransmissions/dup ACKs/
out-of-order segments in amber in the list; the reason is shown in the tooltip.</li>
<li><b>Go to Packet…</b> (Ctrl+G): jumps to a packet number.</li>
<li><b>Find / Find Next</b> (Ctrl+F / F3): full-text search in the content.</li>
<li><b>Export</b>: packets, conversations or domains as CSV/JSON.</li>
</ul>

<h2 id="tools">11. "Tools" Menu</h2>
<ul>
<li><b>Ping / Traceroute / DNS Lookup / WHOIS</b>: network diagnostics directly from
NetFett. WHOIS automatically follows the responsible registry server.</li>
<li><b>Load TLS Keys (SSLKEYLOGFILE)</b>: loads session keys for
TLS decryption (see <a href="#tls">section 14</a>).</li>
<li><b>Load GeoIP Database (GeoLite2)</b>: loads a MaxMind <code>.mmdb</code>
(Country/City/ASN). <i>Endpoints &amp; Ports</i> then shows a
<i>country/ASN</i> column. Requires the <code>maxminddb</code> package and a
database you obtain yourself – NetFett does not ship any GeoIP data.</li>
</ul>

<h2 id="view">12. "View" Menu</h2>
<ul>
<li><b>Time Format</b>: Relative / Time of Day / Absolute (see the "Time" column).</li>
<li><b>Toggle Mark</b> (Ctrl+M), <b>Next Mark</b> (F8),
<b>Clear All Marks</b>.</li>
<li>Show/hide the <b>Name Column (Reverse DNS)</b> and the <b>Program Column</b>.</li>
<li><b>Coloring Rules…</b>: create custom rules (name, filter, color); they
color matching rows – ideal for highlighting important traffic.</li>
<li><b>Statistics on Filter Only</b>: restrict analyses to the visible
packets.</li>
<li><b>Decode As…</b>: permanently assign a protocol to a port (e.g. "8443 as
TLS") when automatic detection does not apply.</li>
<li><b>Profiles</b>: <i>save</i> the current settings (filters, colors, columns …) under a
name, <i>load</i> or <i>delete</i> them later.</li>
<li><b>Light Theme</b>: switch between the dark and light theme.</li>
<li><b>Sprache / Language</b>: switch the user interface between Deutsch and
English. The change takes effect after restarting NetFett (you will be asked
whether to restart now).</li>
</ul>

<h2 id="capture">13. "Capture" Menu</h2>
<ul>
<li><b>Record to File…</b>: writes live to a PCAP file during capture
(toggle).</li>
<li><b>Packet Limit (Ring Buffer)…</b>: limits the number of packets kept; older ones
are dropped (saves memory during long-term capture).</li>
<li><b>Capture Filter…</b>: discards uninteresting packets <i>before</i>
recording/display (same syntax as the display filter). Reduces
the amount of data; discarded packets appear as "dropped N" in the status bar.</li>
<li><b>Rotating Capture…</b>: writes to several rotating files of
fixed size (e.g. for continuous operation).</li>
<li><b>Recent Files</b>: quick access to recently opened PCAPs.</li>
<li><b>Restart as Administrator…</b>: only visible without admin rights – required
for live capture.</li>
</ul>

<h2 id="tls">14. Decrypting TLS &amp; HTTP/2</h2>
<ol>
<li>Set the environment variable <code>SSLKEYLOGFILE</code> to a file for the
browser and browse with it (the browser writes the session keys there).</li>
<li>In NetFett: <i>Tools → Load TLS Keys</i> and select that file.</li>
<li>Open a TLS connection via right-click → <i>Follow TCP Stream</i> and click
<b>Decrypt (TLS)</b> – the plaintext appears.</li>
<li>For <b>HTTP/2</b>, choose the <b>"HTTP/2 Headers"</b> view in the stream window:
NetFett decodes the HPACK-compressed headers (also after decryption).</li>
</ol>
<p>Without matching keys, TLS stays encrypted – that is a technical necessity.</p>

<h2 id="interpret">15. Interpreting the Values</h2>
<ul>
<li><b>Direction (▲/▼):</b> always relative to <i>this</i> PC. ▲ = sent from
here, ▼ = received here.</li>
<li><b>TCP problems:</b> <i>Retransmission</i> = a segment was sent again
(loss); <i>Dup ACK</i> = the receiver requests a missing segment;
<i>Out-of-Order</i> = a segment arrived late/out of sequence. Isolated incidents
are normal – clusters point to a poor link.</li>
<li><b>Connection states:</b> red = reset/no response (problem or
blocked), amber = still being set up/incomplete, neutral = ok.</li>
<li><b>First contact (expert info):</b> first connection to a new external
host – usually harmless, but overall a good "what's new" indicator.</li>
<li><b>Plaintext passwords (error):</b> credentials in HTTP Basic/FTP/SMTP were
transmitted unencrypted – a real security risk.</li>
</ul>

<h2 id="keys">16. Keyboard Shortcuts</h2>
<table border="1" cellspacing="0" cellpadding="4">
<tr><th>Key</th><th>Function</th></tr>
<tr><td>F1</td><td>This manual</td></tr>
<tr><td>Ctrl+F</td><td>Find in content</td></tr>
<tr><td>F3</td><td>Find next</td></tr>
<tr><td>Ctrl+G</td><td>Go to packet number</td></tr>
<tr><td>Ctrl+M</td><td>Toggle mark</td></tr>
<tr><td>F8</td><td>Next mark</td></tr>
<tr><td>Double-click</td><td>In analyses: set filter / jump to packet</td></tr>
</table>

<h2 id="limits">17. Limitations</h2>
<p>NetFett captures via a raw socket <b>from the IP header onward</b> – so there is
<b>no Ethernet/ARP</b> and no MAC addresses in the capture. Also not
available: a country GeoIP database is not included (can be loaded optionally),
and TLS can only be decrypted with matching keys.</p>

<h3>Headless / Command Line</h3>
<pre>python -m netfett --read capture.pcapng --stats
python -m netfett --read x.pcap --export conv.csv --what conversations</pre>
"""
