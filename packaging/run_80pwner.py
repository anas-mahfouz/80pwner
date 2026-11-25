# 80PWNER PyInstaller entry point — by Anas Mahfouz (The 80)

"""Entry script for PyInstaller bundles (see packaging/80pwner.spec)."""

from eightypwner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
