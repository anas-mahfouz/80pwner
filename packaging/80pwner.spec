# 80PWNER PyInstaller spec — by Anas Mahfouz (The80)
# Builds standalone bundles (do not run as part of the normal build).
#
#   pip install pyinstaller
#   pyinstaller packaging/80pwner.spec          # (Linux/macOS/Windows)
# Output lands in dist/80pwner/ (onedir keeps Qt fast-loading).
#
# The QSS themes + bundled fonts ship as package data; binaries/hidden imports
# for the engines (LIEF, capstone, gmpy2 …) get pulled by PyInstaller's hooks.

import sys

block_cipher = None

a = Analysis(
    ["run_80pwner.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "eightypwner",       # top-level package (digit-prefixed dist id)
        "eightypwner.cli",
        "PySide6.QtWidgets",
        "PySide6.QtGui",
        "PySide6.QtCore",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
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
    console=False,               # GUI app on every OS; logs go to the log dir
    disable_windowed_traceback=False,
    version=None,
    upx=False,                   # UPX often trips AV on windows; skip
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="80pwner",
)

# macOS: optional app bundle — uncomment to build an .app
# if sys.platform == "darwin":
#     app = BUNDLE(coll, name="80PWNER.app", icon=None, bundle_identifier="local.the80.80pwner")
