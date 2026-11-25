# 80PWNER — by Anas Mahfouz (The 80)

"""Per-challenge session state.

The current session owns, at minimum, the active target so the main window and
plugins agree on "the binary". Step 3 adds per-session annotations: comments
attached to addresses and renamed symbols. These persist as JSON inside the
platform session directory; the full challenge library (notes, findings and
exports) lives in :mod:`eightypwner.core.session_store` (SQLite).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from eightypwner.platform import paths

log = logging.getLogger(__name__)


@dataclass
class SessionState:
    binary_path: Path | None = None
    bookmarks: list[str] = field(default_factory=list)
    # address -> comment text (Step 3: disassembler annotations)
    comments: dict[int, str] = field(default_factory=dict)
    # address -> display name the user gave the symbol at that address
    renamed_symbols: dict[int, str] = field(default_factory=dict)

    @property
    def binary_name(self) -> str | None:
        return self.binary_path.name if self.binary_path else None

    # ------------------------------------------------------------ annotations
    def set_comment(self, address: int, text: str) -> None:
        """Attach (or clear, with empty *text*) a comment at *address*."""
        text = text.strip()
        if text:
            self.comments[address] = text
        else:
            self.comments.pop(address, None)

    def comment_at(self, address: int) -> str | None:
        return self.comments.get(address)

    def rename_symbol(self, address: int, name: str) -> None:
        """Rename the symbol at *address* (empty *name* restores the original)."""
        name = name.strip()
        if name:
            self.renamed_symbols[address] = name
        else:
            self.renamed_symbols.pop(address, None)

    def display_name(self, address: int, original: str) -> str:
        return self.renamed_symbols.get(address, original)

    # ---------------------------------------------------------------- storage
    def annotations_path(self) -> Path:
        """JSON file holding comments/renames for the active binary."""
        directory = paths.session_dir()
        directory.mkdir(parents=True, exist_ok=True)
        stem = self.binary_name or "no-binary"
        return directory / f"annotations-{stem}.json"

    def save_annotations(self) -> bool:
        """Persist comments + renames; best-effort, returns success."""
        payload = {
            "app": "80PWNER",
            "binary": self.binary_name,
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "comments": {hex(addr): text for addr, text in sorted(self.comments.items())},
            "renamed_symbols": {
                hex(addr): name for addr, name in sorted(self.renamed_symbols.items())
            },
        }
        try:
            self.annotations_path().write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            return True
        except OSError:
            log.exception("Could not save session annotations")
            return False

    def load_annotations(self) -> bool:
        """Restore comments + renames saved for the active binary."""
        self.comments.clear()
        self.renamed_symbols.clear()
        path = self.annotations_path()
        if not path.exists():
            return False
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.comments = {
                int(addr, 16): str(text) for addr, text in payload.get("comments", {}).items()
            }
            self.renamed_symbols = {
                int(addr, 16): str(name)
                for addr, name in payload.get("renamed_symbols", {}).items()
            }
            return True
        except (OSError, ValueError, TypeError):
            log.exception("Could not load session annotations from %s", path)
            return False
