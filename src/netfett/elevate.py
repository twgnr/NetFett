"""Windows-UAC-Elevation: Administratorstatus prüfen und neu starten.

Die Live-Erfassung braucht einen Raw-Socket und damit Administratorrechte. Über
:func:`relaunch_as_admin` kann sich NetFett selbst neu starten – Windows zeigt
dann den UAC-Bestätigungsdialog. Außerhalb von Windows sind beide Funktionen
gutmütige No-ops.
"""
from __future__ import annotations

import ctypes
import os
import sys


def is_admin() -> bool:
    """True, wenn der Prozess mit Administratorrechten läuft."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False        # nicht Windows oder nicht ermittelbar


def relaunch_as_admin() -> bool:
    """Startet dieselbe Anwendung mit UAC-Elevation neu.

    Gibt ``True`` zurück, wenn der elevierte Prozess gestartet wurde (der
    Aufrufer sollte sich dann beenden), sonst ``False`` (kein Windows, bereits
    Admin, oder UAC abgebrochen)."""
    if sys.platform != "win32" or is_admin():
        return False
    try:
        if getattr(sys, "frozen", False):       # PyInstaller-Build (.exe)
            program, params, workdir = sys.executable, "", \
                os.path.dirname(sys.executable)
        else:
            # Arbeitsverzeichnis = Ordner, der das Paket „netfett" enthält,
            # damit „python -m netfett" auch ohne Installation funktioniert.
            program, params = sys.executable, "-m netfett"
            workdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", program, params, workdir, 1)   # 1 = SW_SHOWNORMAL
        return int(rc) > 32                     # >32 = Erfolg (ShellExecute)
    except (AttributeError, OSError):
        return False
