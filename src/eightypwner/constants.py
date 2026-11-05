# 80PWNER — by Anas Mahfouz (The80)

"""Brand constants for 80PWNER. Applied everywhere — window titles, dialogs, CLI."""

from __future__ import annotations

import contextlib
import logging
import sys
from importlib import resources

from eightypwner.ui import banner_font

log = logging.getLogger(__name__)

APP_NAME = "80PWNER"          # short brand (titles, status bar)
APP_BANNER = "THE80-PWNER"    # full banner word (welcome, splash, About, CLI art)
APP_AUTHOR = "Anas Mahfouz (The80)"
APP_HANDLE = "The80"
APP_TAGLINE = "An Integrated GUI Pwn / Binary Analysis Workbench"
APP_VERSION = "0.1.0"
APP_LICENSE = "MIT"

# Qt organisation/app names.
ORG_NAME = "The80"
SETTINGS_APP = "80PWNER"

# Banner split for two-tone rendering ("THE80" accent, "-PWNER" secondary).
BANNER_LEFT, BANNER_RIGHT = "THE80", "-PWNER"

# Accents (revision B): RED — vivid crimson on dark, deep crimson on light.
ACCENT_DARK = "#FF2D3D"
ACCENT_LIGHT = "#C8102E"

# ---------------------------------------------------------------- ASCII banner
# The CLI/GUI art is a *static* FIGlet asset (ansi_shadow font — the zero has a
# solid mid bar and '8' is unmistakable vs 'B'). Regenerate with
#   python tools/gen_banner.py   (pyfiglet — dev-only, never a runtime dep)
BANNER_ASSET = "banner.txt"


def load_banner_art() -> tuple[str, int]:
    """(art, split_column) from the bundled asset; bitmap font as fallback."""
    try:
        raw = resources.files("eightypwner.assets").joinpath(BANNER_ASSET).read_text(
            encoding="utf-8"
        )
        split = _banner_split_default()
        lines: list[str] = []
        for line in raw.splitlines():
            if line.startswith("#"):
                if "two-tone split at column" in line:
                    with contextlib.suppress(ValueError, IndexError):
                        split = int(line.split("column")[1].split()[0])
                continue
            lines.append(line)
        while lines and not lines[-1].strip():
            lines.pop()
        if lines:
            return "\n".join(lines), split
    except (OSError, ModuleNotFoundError):
        log.warning("Bundled banner asset missing; using built-in bitmap font")
    return _glyph_fallback(APP_BANNER), _banner_split_default()


def _banner_split_default() -> int:
    return banner_font.left_cols(BANNER_LEFT)


def ascii_banner(text: str = APP_BANNER) -> str:
    """ASCII banner text; non-banner words use the built-in bitmap font."""
    if text == APP_BANNER:
        return load_banner_art()[0]
    return _glyph_fallback(text)


def _glyph_fallback(text: str) -> str:
    """Built-in bitmap block font (banner_font.py — the banner's true source)."""
    return banner_font.render_text(text, fill="#")


def terminal_banner(banner: str | None = None) -> str:
    """CLI-safe banner: maps glyphs a terminal cannot print to ASCII ("#").

    Checks whether the current stdout encoding can represent the full-block
    character; on failure (or unknown codecs) replaces it with "#".
    """
    text = banner if banner is not None else VERSION_BANNER
    encoding = (getattr(sys.stdout, "encoding", None) or "utf-8").lower()
    try:
        "█".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        text = text.replace("█", "#")
        text = text.replace("—", "-")
    return text


# (The bitmap glyph table lives in eightypwner/ui/banner_font.py —
# the single source of truth also used by tools/gen_banner.py.)

ASCII_ART = ascii_banner()  # module-level so `--version` output stays stable

VERSION_BANNER = f"""{ASCII_ART}

{APP_BANNER} ({APP_NAME}) {APP_VERSION} — {APP_TAGLINE}
by {APP_AUTHOR}
"""

FOOTER_TEXT = f"Made by {APP_HANDLE}"


def window_title(binary_name: str | None) -> str:
    return f"{APP_NAME} — {binary_name}" if binary_name else APP_NAME
