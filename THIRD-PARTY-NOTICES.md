# Third-Party Notices

NetFett itself is licensed under the [MIT License](LICENSE).

The Windows executable (`NetFett-<version>-win64.exe`) bundles the following
third-party components. Each remains under its own license.

| Component | License | Source |
|---|---|---|
| Qt 6 (via PySide6) | LGPL-3.0 | https://www.qt.io/ · https://code.qt.io/ |
| PySide6 / shiboken6 (Qt for Python) | LGPL-3.0 | https://code.qt.io/cgit/pyside/pyside-setup.git/ |
| Python 3.12 runtime | PSF License 2.0 | https://www.python.org/ |
| cryptography | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| OpenSSL 3 (in Python and cryptography) | Apache-2.0 | https://www.openssl.org/ |
| cffi | MIT | https://github.com/python-cffi/cffi |
| pycparser | BSD-3-Clause | https://github.com/eliben/pycparser |
| PyInstaller bootloader | GPL-2.0 with bootloader exception | https://github.com/pyinstaller/pyinstaller |

## Qt / PySide6 (LGPL-3.0)

Qt and PySide6 are used under the GNU Lesser General Public License v3.0
(https://www.gnu.org/licenses/lgpl-3.0.html), which builds on the GNU General
Public License v3.0 (https://www.gnu.org/licenses/gpl-3.0.html). They are used
unmodified, as published on PyPI.

The complete source code of NetFett and the build script
(`packaging/build.py`) are available in this repository. You can therefore
replace the bundled Qt/PySide6 libraries with a modified or different version
by installing it in a Python environment and rebuilding the executable, or by
running NetFett directly from source (`pip install -e .` and `python -m netfett`).

## PyInstaller

The executable is built with PyInstaller. Its bootloader is licensed under the
GPL-2.0 with a special exception that allows distributing the resulting
executable under any license.

## Optional, not bundled

- `maxminddb` (Apache-2.0) – only if installed separately for GeoIP support.
- MaxMind GeoLite2 databases are **not** included; they are subject to MaxMind's
  own license terms.
