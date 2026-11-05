# 80PWNER — by Anas Mahfouz (The80)

"""Brand constants for 80PWNER. Applied everywhere — window titles, dialogs, CLI."""

from __future__ import annotations

APP_NAME = "80PWNER"
APP_AUTHOR = "Anas Mahfouz (The80)"
APP_HANDLE = "The80"
APP_TAGLINE = "An Integrated GUI Pwn / Binary Analysis Workbench"
APP_VERSION = "0.1.0"
APP_LICENSE = "MIT"

# Qt organisation/app names (unused for persistence on Linux — we use JSON settings
# under ~/.80pwner — but useful for QSettings-compatible integrations).
ORG_NAME = "The80"
SETTINGS_APP = "80PWNER"

# Accents (revision B): RED — vivid crimson on dark, deep crimson on light.
ACCENT_DARK = "#FF2D3D"
ACCENT_LIGHT = "#C8102E"

ASCII_ART = r""" ██████╗  █████╗   ██████╗ ██╗    ██╗ ███╗   ██╗ ███████╗ ██████╗
 ██╔══██╗ ██╔══██╗ ██╔════╝ ██║    ██║ ████╗  ██║ ██╔════╝ ██╔══██╗
 ██████╔╝ ███████║ ██║      ██║ █╗ ██║ ██╔██╗ ██║ █████╗   ██████╔╝
 ██╔══██╗ ██╔══██╗ ██║      ██║███╗██║ ██║╚██╗██║ ██╔══╝   ██╔══██╗
 ██████╔╝ ██║  ██║ ╚██████╗ ╚██╔╝██╔╝ ██║ ╚████║ ███████╗ ██║  ██║
 ╚═════╝  ╚═╝  ╚═╝  ╚═════╝   ╚═╝ ╚═╝  ╚═╝  ╚═══╝ ╚══════╝ ╚═╝  ╚═╝"""

VERSION_BANNER = f"""{ASCII_ART}

{APP_NAME} {APP_VERSION} — {APP_TAGLINE}
by {APP_AUTHOR}
"""

FOOTER_TEXT = f"Made by {APP_HANDLE}"

# The window title format from the spec: "80PWNER — <binary name>"
def window_title(binary_name: str | None) -> str:
    return f"{APP_NAME} — {binary_name}" if binary_name else APP_NAME
