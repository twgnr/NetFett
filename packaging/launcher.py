"""Startskript für den PyInstaller-Build (``netfett/__main__.py`` nutzt relative Importe)."""
import sys

from netfett.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
