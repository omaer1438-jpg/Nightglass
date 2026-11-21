# PyInstaller spec for the personal Windows build. Build with:  python scripts/build.py
# Heavy tools are NOT bundled (plan 8.3): tools\, bin\ and envs\ sit next to Nightglass.exe.
# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.utils.win32.versioninfo import (FixedFileInfo, StringFileInfo, StringStruct, StringTable,
                                                 VarFileInfo, VarStruct, VSVersionInfo)

import sys

sys.path.insert(0, SPECPATH)  # noqa: F821 - defined by PyInstaller
from core import __version__  # noqa: E402

hiddenimports = collect_submodules("adapters") + collect_submodules("phonenumbers") + collect_submodules("dns")

a = Analysis(
    ["app/__main__.py"],
    pathex=["."],
    datas=[("app/theme.qss", "app"), ("app/assets", "app/assets")],
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "pytestqt", "_pytest", "pygments", "setuptools", "pkg_resources", "distutils",
              "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtQml", "PySide6.QtQuick",
              "PySide6.Qt3DCore", "PySide6.QtMultimedia", "PySide6.QtPdf"],
    noarchive=False,
)
# The Python excludes above don't stop Qt plugins from pulling these DLLs in (~38 MB, unused by a Widgets app).
_UNUSED = ("opengl32sw", "qt6quick", "qt6qml", "qt6pdf", "qt6virtualkeyboard", "qtvirtualkeyboard", "qpdf")
a.binaries = [b for b in a.binaries if not any(k in b[0].lower() for k in _UNUSED)]

_v = tuple(int(p) for p in __version__.split(".")) + (0,)
version = VSVersionInfo(
    ffi=FixedFileInfo(filevers=_v, prodvers=_v),
    kids=[StringFileInfo([StringTable("040904B0", [
              StringStruct("ProductName", "Nightglass"), StringStruct("FileDescription", "Nightglass OSINT workbench"),
              StringStruct("FileVersion", __version__), StringStruct("ProductVersion", __version__),
              StringStruct("OriginalFilename", "Nightglass.exe"),
              StringStruct("LegalCopyright", "Private build - personal use only")])]),
          VarFileInfo([VarStruct("Translation", [0x0409, 1200])])],
)

pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Nightglass",
    console=False,
    icon="app/assets/nightglass.ico",
    version=version,
)
coll = COLLECT(exe, a.binaries, a.datas, name="Nightglass")
