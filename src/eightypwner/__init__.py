# 80PWNER — by Anas Mahfouz (The80)

"""80PWNER — An Integrated GUI Pwn / Binary Analysis Workbench.

Educational + CTF use (pwn.college, picoCTF, HackTheBox, local labs).
Analyze and debug binaries you own or are authorized to test.
"""

from __future__ import annotations

from eightypwner.constants import (
    APP_AUTHOR,
    APP_HANDLE,
    APP_NAME,
    APP_TAGLINE,
    APP_VERSION,
    ASCII_ART,
)

__all__ = [
    "APP_AUTHOR",
    "APP_HANDLE",
    "APP_NAME",
    "APP_TAGLINE",
    "APP_VERSION",
    "ASCII_ART",
    "__version__",
]

__version__ = APP_VERSION
