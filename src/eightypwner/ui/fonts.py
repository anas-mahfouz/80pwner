# 80PWNER — by Anas Mahfouz (The80)

"""Monospace font selection (spec §5): default JetBrains Mono, fallback chain."""

from __future__ import annotations

from PySide6.QtGui import QFontDatabase

CANDIDATES = ("JetBrains Mono", "Fira Code", "Cascadia Code", "Consolas", "DejaVu Sans Mono")


def resolve_monospace(preferred: str = "") -> str:
    """Return the first installed family from the preferred name or candidates."""
    installed = QFontDatabase.families() if hasattr(QFontDatabase, "families") else []
    for family in ([preferred] if preferred else []) + list(CANDIDATES):
        if family and family in installed:
            return family
    return "Monospace"
