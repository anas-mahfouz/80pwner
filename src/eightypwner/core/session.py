# 80PWNER — by Anas Mahfouz (The80)

"""Per-challenge session state stub.

Expanded in Step 2 (binary model) and Step 10 (sessions/notes on SQLite).
The current session owns, at minimum, the active target so the main window and
plugins agree on "the binary".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SessionState:
    binary_path: Path | None = None
    bookmarks: list[str] = field(default_factory=list)

    @property
    def binary_name(self) -> str | None:
        return self.binary_path.name if self.binary_path else None
