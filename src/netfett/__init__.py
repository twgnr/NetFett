"""NetFett – ein vollwertiger Netzwerk-Monitor und Protokoll-Analyzer (PySide6, reines Python).

Erfasst ein- und ausgehenden IPv4-Verkehr über einen Windows-Raw-Socket
(``SIO_RCVALL``) – ohne Npcap/WinPcap und ohne Fremd-Dependencies. Bietet eine
Paketliste, eine Schicht-Detailansicht, eine Hex-Ansicht sowie grafische
Live-Auswertung (Durchsatz ein/aus, Pakete/s, Protokollverteilung).
"""
from __future__ import annotations

__version__ = "0.1.0"
