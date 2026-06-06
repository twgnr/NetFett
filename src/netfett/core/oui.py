"""MAC-OUI → Hersteller. Kleine eingebaute Liste plus optionale ``manuf``-Datei.

Die vollständige IEEE-OUI-Datenbank ist groß und wird nicht mitgeliefert; für
breite Abdeckung kann Wiresharks ``manuf``-Datei geladen werden (auto-erkannt,
falls Wireshark installiert ist).
"""
from __future__ import annotations

import os

# Auszug gängiger Hersteller (OUI = erste 3 MAC-Bytes, Großbuchstaben, 6 Hex).
_OUI: dict[str, str] = {
    "001451": "Apple", "0017F2": "Apple", "3C0754": "Apple", "F0DBF8": "Apple",
    "A4C361": "Apple", "DC2B2A": "Apple",
    "FCFBFB": "Cisco", "00000C": "Cisco", "00163E": "Xensource",
    "001A11": "Google", "3C5AB4": "Google", "F4F5E8": "Google",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "001E101": "", "00059A": "Cisco",
    "001B63": "Apple", "D850E6": "ASUSTek", "1C872C": "ASUSTek",
    "F46D04": "ASUSTek", "001D60": "ASUSTek",
    "00248C": "ASUSTek", "0026B9": "Dell", "B8CA3A": "Dell", "F8BC12": "Dell",
    "001A2B": "AVM (Fritz!Box)", "3810D5": "AVM (Fritz!Box)",
    "C0C1C0": "Cisco", "001124": "Apple",
    "0050F2": "Microsoft", "000D3A": "Microsoft", "C83F26": "Microsoft",
    "0017AB": "Nintendo", "001CC0": "Intel", "00AA00": "Intel",
    "001B77": "Intel", "3C970E": "Intel", "A0C589": "Intel",
    "002618": "Samsung", "F0E77E": "Samsung", "5CF6DC": "Samsung",
    "001632": "Samsung", "8C7712": "Samsung",
    "001882": "Huawei", "00259E": "Huawei", "286ED4": "Huawei",
    "286C07": "Xiaomi", "640980": "Xiaomi", "F8A45F": "Xiaomi",
    "50C7BF": "TP-Link", "C46E1F": "TP-Link", "EC086B": "TP-Link",
    "001CDF": "Belkin", "B4750E": "Belkin", "000C29": "VMware",
    "005056": "VMware", "080027": "VirtualBox", "525400": "QEMU/KVM",
    "0017C8": "Kyocera", "001B78": "HP", "002264": "HP", "3863BB": "HP",
}


def vendor(mac: str) -> str:
    """Hersteller zu einer MAC oder „"; berücksichtigt lokal verwaltete MACs."""
    if not mac:
        return ""
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    if len(key) == 6:
        # Bit 1 des ersten Oktetts gesetzt → lokal/zufällig administriert.
        try:
            if int(key[:2], 16) & 0x02:
                return "(zufällige MAC)"
        except ValueError:
            pass
    return _OUI.get(key, "")


def load_manuf(path: str) -> int:
    """Lädt eine Wireshark-``manuf``-Datei nach. Gibt die Anzahl Einträge zurück."""
    added = 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 2)
                if len(parts) < 2:
                    continue
                prefix = parts[0]
                if "/" in prefix:                  # maskierte Einträge überspringen
                    continue
                key = prefix.replace(":", "").replace("-", "").upper()
                if len(key) == 6:
                    _OUI.setdefault(key, parts[1])
                    added += 1
    except OSError:
        return 0
    return added


def autoload() -> int:
    """Versucht, Wiresharks ``manuf`` aus Standardpfaden zu laden."""
    candidates = [
        r"C:\Program Files\Wireshark\manuf",
        r"C:\Program Files (x86)\Wireshark\manuf",
        "/usr/share/wireshark/manuf",
        os.path.expanduser("~/.config/wireshark/manuf"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return load_manuf(path)
    return 0
