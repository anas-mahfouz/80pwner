# 80PWNER — by Anas Mahfouz (The80)

"""Brand constants for 80PWNER. Applied everywhere — window titles, dialogs, CLI."""

from __future__ import annotations

import contextlib
import logging
from importlib import resources

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
    """(art, split_column) from the bundled asset; glyph art as fallback."""
    try:
        raw = resources.files("eightypwner.assets").joinpath(BANNER_ASSET).read_text(
            encoding="utf-8"
        )
        split = 42  # sane default when the header comment is editable away
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
        log.warning("Bundled banner asset missing; using built-in glyph art")
    return _glyph_fallback(APP_BANNER), 0


def ascii_banner(text: str = APP_BANNER) -> str:
    """ASCII banner text; non-banner words use the tiny built-in glyph font."""
    if text == APP_BANNER:
        return load_banner_art()[0]
    return _glyph_fallback(text)


def _glyph_fallback(text: str) -> str:
    """Tiny built-in block font, used only if the banner asset ever goes missing.
    Every banner character must have a glyph; digits and '-' stay distinctive."""
    lines = ["" for _ in range(7)]
    for char in text:
        glyph = _GLYPHS.get(char)
        if glyph is None:
            raise KeyError(f"No ASCII glyph for {char!r}")
        lines = [line + "  " + cell for line, cell in zip(lines, glyph, strict=True)]
    return "\n".join(line.rstrip() for line in lines)


# Fallback font (see _glyph_fallback): tiny 7-row block glyphs.
_GLYPHS: dict[str, tuple[str, ...]] = {
    " ": (
        "      ",
        "      ",
        "      ",
        "      ",
        "      ",
        "      ",
        "      ",
    ),
    "-": (
        "      ",
        "      ",
        "      ",
        "######",
        "      ",
        "      ",
        "      ",
    ),
    "T": (
        "######",
        "  ##  ",
        "  ##  ",
        "  ##  ",
        "  ##  ",
        "  ##  ",
        "  ##  ",
    ),
    "H": (
        "#    #",
        "#    #",
        "#    #",
        "######",
        "#    #",
        "#    #",
        "#    #",
    ),
    "E": (
        "######",
        "#     ",
        "#     ",
        "####  ",
        "#     ",
        "#     ",
        "######",
    ),
    "0": (  # slashed zero — never confusable with '8' or 'O'
        " #### ",
        "#    #",
        "#   ##",
        "#  # #",
        "# ## #",
        "#    #",
        " #### ",
    ),
    "8": (
        " #### ",
        "#    #",
        "#    #",
        " #### ",
        "#    #",
        "#    #",
        " #### ",
    ),
    "P": (
        "######",
        "#    #",
        "#    #",
        "######",
        "#     ",
        "#     ",
        "#     ",
    ),
    "W": (
        "#    #",
        "#    #",
        "# ## #",
        "# ## #",
        "# ## #",
        "##  ##",
        "#    #",
    ),
    "N": (
        "#    #",
        "##   #",
        "# #  #",
        "#  # #",
        "#   ##",
        "#    #",
        "#    #",
    ),
    "R": (
        "######",
        "#    #",
        "#    #",
        "######",
        "#  #  ",
        "#   # ",
        "#    #",
    ),
    "_": (
        "      ",
        "      ",
        "      ",
        "      ",
        "      ",
        "      ",
        "######",
    ),
}

ASCII_ART = ascii_banner()  # module-level so `--version` output stays stable

VERSION_BANNER = f"""{ASCII_ART}

{APP_BANNER} ({APP_NAME}) {APP_VERSION} — {APP_TAGLINE}
by {APP_AUTHOR}
"""

FOOTER_TEXT = f"Made by {APP_HANDLE}"


def window_title(binary_name: str | None) -> str:
    return f"{APP_NAME} — {binary_name}" if binary_name else APP_NAME
