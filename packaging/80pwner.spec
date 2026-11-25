# 80PWNER PyInstaller spec — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.
#
# Builds standalone, Python-free bundles for Linux, Windows and macOS:
#
#   pip install -e '.[analysis]' pyinstaller
#   pyinstaller --noconfirm --clean packaging/80pwner.spec
#
# Output: dist/80pwner/ (onedir — Qt loads much faster than onefile).
# The GitHub release workflow runs this on every OS and attaches archives.

import os

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 (injected by PyInstaller)
ENTRY = os.path.join(SPECPATH, "run_80pwner.py")  # noqa: F821

block_cipher = None

# --- application data (banner art, QSS themes, bundled fonts) ---------------
datas = collect_data_files("eightypwner")

# --- native backends --------------------------------------------------------
binaries: list[tuple[str, str]] = []
hiddenimports: list[str] = collect_submodules("eightypwner")

for package in ("capstone", "keystone", "lief", "elftools", "pygdbmi"):
    try:
        binaries += collect_dynamic_libs(package)
    except Exception:
        pass
    try:
        hiddenimports += collect_submodules(package)
    except Exception:
        pass

hiddenimports += ["capstone", "keystone", "lief", "pygdbmi"]

a = Analysis(
    [ENTRY],
    pathex=[os.path.join(ROOT, "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # We only import QtCore/QtGui/QtWidgets; drop the heavy optional stacks.
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtWebEngineQuick",
        "PySide6.QtQml",
        "PySide6.QtQuick",
        "PySide6.QtQuickWidgets",
        "PySide6.QtQuick3D",
        "PySide6.Qt3DCore",
        "PySide6.Qt3DRender",
        "PySide6.QtMultimedia",
        "PySide6.QtMultimediaWidgets",
        "PySide6.QtCharts",
        "PySide6.QtDataVisualization",
        "PySide6.QtPdf",
        "PySide6.QtPdfWidgets",
        "PySide6.QtDesigner",
        "PySide6.QtHelp",
        "PySide6.QtTest",
        "tkinter",
        "pytest",
        "numpy",
        "matplotlib",
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="80pwner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX frequently trips Windows AV; skip it
    console=True,  # launched from a terminal: keep stdout for --version/logs
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="80pwner",
)
