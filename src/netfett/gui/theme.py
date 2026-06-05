"""Zentrales Farbschema (dunkel/hell) für Chrome und Custom-Widgets.

Die selbstgezeichneten Widgets (Graphen, Diagramme) lesen ihre Grundfarben aus
:data:`THEME`; das Qt-Chrome wird über ein Stylesheet gesetzt. So lässt sich per
:func:`apply` zwischen Dunkel- und Hell-Design umschalten.
"""
from __future__ import annotations


class _Theme:
    def __init__(self) -> None:
        self.set_dark(True)

    def set_dark(self, dark: bool) -> None:
        self.dark = dark
        if dark:
            self.bg = "#0d1117"
            self.panel = "#161b22"
            self.grid = "#1c2533"
            self.text = "#c9d1d9"
            self.muted = "#8b949e"
        else:
            self.bg = "#ffffff"
            self.panel = "#f6f8fa"
            self.grid = "#d8dee4"
            self.text = "#1f2328"
            self.muted = "#656d76"


THEME = _Theme()


_DARK_QSS = """
QWidget { background:#0d1117; color:#c9d1d9; }
QToolBar { background:#161b22; border:0; spacing:4px; padding:3px; }
QMenuBar { background:#161b22; color:#c9d1d9; }
QMenuBar::item:selected { background:#21262d; }
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
QMenu::item:selected { background:#1f6feb; color:#ffffff; }
QPushButton { background:#21262d; border:1px solid #30363d; border-radius:4px;
    padding:4px 10px; }
QPushButton:hover { background:#30363d; }
QPushButton:disabled { color:#6e7681; }
"""

_LIGHT_QSS = """
QWidget { background:#ffffff; color:#1f2328; }
QToolBar { background:#f6f8fa; border:0; spacing:4px; padding:3px; }
QMenuBar { background:#f6f8fa; color:#1f2328; }
QMenuBar::item:selected { background:#eaeef2; }
QLineEdit, QComboBox { background:#ffffff; border:1px solid #d0d7de;
    border-radius:4px; padding:3px 6px; }
QTableView { background:#ffffff; gridline-color:#eaeef2;
    selection-background-color:#0969da; selection-color:#ffffff; }
QHeaderView::section { background:#f6f8fa; color:#656d76; border:0;
    border-right:1px solid #eaeef2; padding:4px 6px; }
QTreeWidget { background:#ffffff; border:1px solid #d0d7de; }
QTreeWidget::item:selected { background:#0969da; color:#ffffff; }
QPlainTextEdit { background:#ffffff; border:1px solid #d0d7de; }
QStatusBar { background:#f6f8fa; color:#656d76; }
QToolButton:hover, QToolButton:focus { background:#eaeef2; border-radius:4px; }
QMenu { background:#ffffff; border:1px solid #d0d7de; }
QMenu::item:selected { background:#0969da; color:#ffffff; }
QPushButton { background:#f6f8fa; border:1px solid #d0d7de; border-radius:4px;
    padding:4px 10px; }
QPushButton:hover { background:#eaeef2; }
QPushButton:disabled { color:#8c959f; }
"""


def apply(app, dark: bool) -> None:
    """Setzt Design-Farben und Chrome-Stylesheet der Anwendung."""
    THEME.set_dark(dark)
    app.setStyleSheet(_DARK_QSS if dark else _LIGHT_QSS)
