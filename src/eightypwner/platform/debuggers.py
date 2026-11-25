# 80PWNER — by Anas Mahfouz (The 80)

"""Debugger/tool backend detection with per-OS install hints (spec C).

Honest capability map (no silent failure — the UI reports it):

| feature               | Linux  | macOS | Windows          |
|-----------------------|--------|-------|------------------|
| static analysis       | full   | full  | full (ELF/PE/Mach-O via LIEF) |
| live debug (GDB/MI)   | yes    | no¹   | no¹              |
| gdb-specific modules  | yes    | n/a   | n/a              |

¹ GDB/MI is a Linux-first backend; on macOS/Windows we look for a usable GDB
anyway (e.g. mingw/nix) and degrade to static-only with a clear message when
it is absent or incompatible.
"""

from __future__ import annotations

import platform as _platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolStatus:
    name: str
    available: bool
    version: str = ""
    hint: str = ""
    support_level: str = "full"  # "full" | "static-only" | "missing"


def os_name() -> str:
    return sys.platform  # "linux" | "darwin" | "win32"


def _capture(args: list[str]) -> str:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=5, check=False
        )
        return (result.stdout or result.stderr).strip().splitlines()[0][:80]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return ""


def gdb_status() -> ToolStatus:
    """Detect gdb; native Linux = full support, elsewhere = degraded/static"""
    path = shutil.which("gdb")
    system = os_name()
    if not path:
        hint = {
            "linux": "sudo apt install gdb    # or dnf/pacman equivalent",
            "darwin": "brew install gdb      # note: codesign may be required",
            "win32": "winget install -e --id GnuWin32.GDB  # or the mingw-w64 gdb",
        }.get(system, "Install gdb from https://www.gnu.org/software/gdb/")
        return ToolStatus(
            "gdb", False, hint=hint,
            support_level="missing",
        )
    version = _capture(["gdb", "--version"])
    full = system == "linux"
    return ToolStatus(
        "gdb",
        True,
        version=version,
        hint="" if full else "Debugging runs through GDB/MI on Linux; on "
        f"{_platform.system()} support is best-effort (static analysis unaffected).",
        support_level="full" if full else "static-only",
    )


@dataclass(frozen=True)
class BackendsSnapshot:
    tools: list[ToolStatus] = field(default_factory=list)

    def by_name(self, name: str) -> ToolStatus | None:
        return next((t for t in self.tools if t.name == name), None)


def detect_backends() -> BackendsSnapshot:
    return BackendsSnapshot(tools=[gdb_status()])
