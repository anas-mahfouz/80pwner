# 80PWNER — by Anas Mahfouz (The80)

"""Brand constants for 80PWNER. Applied everywhere — window titles, dialogs, CLI."""

from __future__ import annotations

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
# Glyph bitmaps (7 rows, # cells) so the CLI art is plain ASCII, readable in any
# terminal — and "8", "0" and "-" are visually distinct (slashed zero).
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


def ascii_banner(text: str = APP_BANNER) -> str:
    """Render *text* with the glyph font; raises on unknown characters."""
    lines = ["" for _ in range(7)]
    for char in text:
        glyph = _GLYPHS.get(char)
        if glyph is None:
            raise KeyError(f"No ASCII glyph for {char!r}")
        lines = [line + "  " + cell for line, cell in zip(lines, glyph, strict=True)]
    return "\n".join(line.rstrip() for line in lines)


ASCII_ART = ascii_banner()  # module-level so `--version` output stays stable

VERSION_BANNER = f"""{ASCII_ART}

{APP_BANNER} ({APP_NAME}) {APP_VERSION} — {APP_TAGLINE}
by {APP_AUTHOR}
"""

FOOTER_TEXT = f"Made by {APP_HANDLE}"


def window_title(binary_name: str | None) -> str:
    return f"{APP_NAME} — {binary_name}" if binary_name else APP_NAME
