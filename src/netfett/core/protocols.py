"""Konstanten und Namen für IP-Protokolle und bekannte Ports."""
from __future__ import annotations

# IP-Protokollnummern (Auszug der gängigsten).
IP_PROTO = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# Bekannte Ports -> Anwendungsprotokoll (für Info-Spalte / App-Schicht-Erkennung).
WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC", 137: "NETBIOS",
    138: "NETBIOS", 139: "NETBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "SYSLOG", 515: "LPD", 520: "RIP", 587: "SMTP", 631: "IPP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1701: "L2TP", 1723: "PPTP", 1812: "RADIUS",
    1900: "SSDP", 2049: "NFS", 3128: "HTTP-PROXY", 3306: "MySQL",
    3389: "RDP", 5060: "SIP", 5061: "SIP", 5353: "mDNS", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    27017: "MongoDB",
}

# ICMP-Typen (Auszug).
ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo (ping) request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded",
    12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply",
}


def proto_name(num: int) -> str:
    return IP_PROTO.get(num, f"IP-Proto {num}")


def port_app(port: int) -> str:
    """Anwendungsprotokoll-Name eines Ports oder leerer String."""
    return WELL_KNOWN_PORTS.get(port, "")


def app_for_ports(sport: int, dport: int) -> str:
    """App-Protokoll aus dem (kleineren bzw. bekannten) Port ableiten."""
    return port_app(dport) or port_app(sport)
