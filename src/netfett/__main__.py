"""Einstiegspunkt von NetFett: startet die Qt-Anwendung und das Hauptfenster.

Aufruf:  ``python -m netfett``  oder – nach Installation – ``netfett``.
Hinweis: Für die Live-Erfassung sind unter Windows Administratorrechte nötig
(Raw-Socket / ``SIO_RCVALL``). Das Öffnen von PCAP-Dateien funktioniert ohne.
"""
from __future__ import annotations

import sys


def main() -> int:
    from PySide6.QtWidgets import QApplication

    from .gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("NetFett")
    app.setStyleSheet(_STYLE)
    win = MainWindow()
    win.show()
    return app.exec()


# Dezentes dunkles Thema, passend zu den Graph-/Tabellenfarben.
_STYLE = """
QWidget { background:#0d1117; color:#c9d1d9; }
QToolBar { background:#161b22; border:0; spacing:4px; padding:3px; }
QLineEdit, QComboBox { background:#0d1117; border:1px solid #30363d;
    border-radius:4px; padding:3px 6px; }
QTableView { background:#0d1117; gridline-color:#21262d;
    selection-background-color:#1f6feb; selection-color:#ffffff; }
QHeaderView::section { background:#161b22; color:#8b949e; border:0;
    border-right:1px solid #21262d; padding:4px 6px; }
QTreeWidget { background:#0d1117; border:1px solid #21262d; }
QTreeWidget::item:selected { background:#1f6feb; color:#ffffff; }
QPlainTextEdit { background:#0d1117; border:1px solid #21262d; }
QStatusBar { background:#161b22; color:#8b949e; }
QToolButton:hover, QToolButton:focus { background:#21262d; border-radius:4px; }
QMenu { background:#161b22; border:1px solid #30363d; }
"""


if __name__ == "__main__":
    sys.exit(main())
