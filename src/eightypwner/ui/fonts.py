# 80PWNER — by Anas Mahfouz (The 80)

"""Monospace font handling (spec §5, revision C).

JetBrains Mono (OFL) is bundled so the QSS look is identical on every OS; if
registration fails (e.g. restricted environments) the loader falls back to a
per-OS candidate chain, ending in the generic "Monospace".
"""

from __future__ import annotations

import logging
from importlib import resources

from PySide6.QtGui import QFontDatabase

log = logging.getLogger(__name__)

MONO_FAMILY = "JetBrains Mono"
BUNDLED = ("JetBrainsMono-Regular.ttf", "JetBrainsMono-Bold.ttf")

# Fallback chain when the bundled font is unavailable.
CANDIDATES = ("Fira Code", "Cascadia Code", "Consolas", "DejaVu Sans Mono")


def load_bundled_fonts() -> list[str]:
    """Register the bundled JetBrains Mono files; returns loaded family names."""
    loaded: list[str] = []
    try:
        root = resources.files("eightypwner.assets.fonts")
        for filename in BUNDLED:
            font_file = root.joinpath(filename)
            font_id = QFontDatabase.addApplicationFont(str(font_file))
            if font_id == -1:
                log.warning("Could not load bundled font %s", filename)
                continue
            fams = QFontDatabase.applicationFontFamilies(font_id)
            loaded.extend(fams)
    except Exception:
        log.debug("Bundled font loading failed", exc_info=True)
    if loaded:
        log.info("Bundled fonts: %s", ", ".join(sorted(set(loaded))))
    return loaded


def installed_families() -> tuple[str, ...]:
    return tuple(QFontDatabase.families())


def resolve_monospace(preferred: str = "") -> str:
    """Best available mono family: user preference → bundled → candidates."""
    families = installed_families()
    for candidate in ([preferred] if preferred else []) + [MONO_FAMILY, *CANDIDATES]:
        if candidate and candidate in families:
            return candidate
    return "Monospace"
