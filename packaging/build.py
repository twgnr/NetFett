"""Baut die ausführbare Windows-Anwendung ``dist/NetFett-<version>-win64.exe``.

Voraussetzung (im venv):  pip install -e .[build]
Aufruf:                  python packaging/build.py

Ergebnis ist eine einzelne .exe (PyInstaller „onefile", ohne Konsolenfenster)
plus eine ``.sha256``-Datei mit der Prüfsumme für die Release-Seite.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from netfett import __version__  # noqa: E402

BUILD = ROOT / "build"
DIST = ROOT / "dist"
ICON = ROOT / "src" / "netfett" / "gui" / "netfett.ico"
NAME = f"NetFett-{__version__}-win64"

_VERSION_INFO = """\
VSVersionInfo(
  ffi=FixedFileInfo(filevers={tup}, prodvers={tup}, mask=0x3f, flags=0x0,
                    OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Tobias Wagner'),
      StringStruct('FileDescription', 'NetFett – Network Monitor and Protocol Analyzer'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', 'NetFett'),
      StringStruct('LegalCopyright', 'Copyright (c) 2026 Tobias Wagner – MIT License'),
      StringStruct('OriginalFilename', '{name}.exe'),
      StringStruct('ProductName', 'NetFett'),
      StringStruct('ProductVersion', '{ver}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def _version_file() -> Path:
    nums = [int(x) for x in __version__.split(".")[:3]]
    tup = tuple(nums + [0] * (4 - len(nums)))
    path = BUILD / "version_info.txt"
    path.parent.mkdir(exist_ok=True)
    path.write_text(_VERSION_INFO.format(tup=tup, ver=__version__, name=NAME),
                    encoding="utf-8")
    return path


def main() -> int:
    if not ICON.exists():
        print("Icon fehlt – zuerst: python packaging/make_icon.py")
        return 1
    PyInstaller.__main__.run([
        str(ROOT / "packaging" / "launcher.py"),
        "--name", NAME,
        "--onefile",
        "--windowed",                                   # kein Konsolenfenster
        "--noconfirm",
        "--clean",
        "--icon", str(ICON),
        "--version-file", str(_version_file()),
        "--paths", str(ROOT / "src"),
        # Kataloge werden zur Laufzeit dynamisch importiert (i18n).
        "--collect-submodules", "netfett.locale",
        "--add-data", f"{ICON}{';' if sys.platform == 'win32' else ':'}netfett/gui",
        "--distpath", str(DIST),
        "--workpath", str(BUILD / "pyinstaller"),
        "--specpath", str(BUILD),
    ])
    exe = DIST / f"{NAME}.exe"
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    (DIST / f"{NAME}.exe.sha256").write_text(f"{digest}  {exe.name}\n",
                                             encoding="ascii")
    print(f"\nFertig: {exe}  ({exe.stat().st_size / 1e6:.1f} MB)")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
