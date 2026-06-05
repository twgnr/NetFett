"""Einstiegspunkt von NetFett: startet die Qt-Anwendung und das Hauptfenster.

Aufruf:  ``python -m netfett``  oder – nach Installation – ``netfett``.
Hinweis: Für die Live-Erfassung sind unter Windows Administratorrechte nötig
(Raw-Socket / ``SIO_RCVALL``). Das Öffnen von PCAP-Dateien funktioniert ohne.
"""
from __future__ import annotations

import sys


def main() -> int:
    from PySide6.QtWidgets import QApplication

    from .gui import theme
    from .gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("NetFett")
    theme.apply(app, dark=True)          # Standard: dunkles Design
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
