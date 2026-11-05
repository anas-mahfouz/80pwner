# 80PWNER — by Anas Mahfouz (The80)

"""About dialog — branding home (spec §2: "80PWNER — by Anas Mahfouz (The80)")."""

from __future__ import annotations

import importlib.util

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from eightypwner.constants import APP_AUTHOR, APP_LICENSE, APP_NAME, APP_TAGLINE, APP_VERSION

# Engines checked for the dependency panel; errors show install hints (spec §7).
_ENGINE_DEPS: dict[str, str] = {
    "capstone": "pip install capstone",
    "elftools": "pip install pyelftools",
    "lief": "pip install lief",
    "gdbmi": "pip install pygdbmi  # and: sudo apt install gdb",
    "pwn": "pip install pwntools",
}


class AboutDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None = None,
        tokens: dict[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME}")

        from eightypwner.ui.banner import ascii_banner_pixmap
        from eightypwner.ui.theme import DARK_TOKENS

        banner = QLabel()
        banner.setPixmap(ascii_banner_pixmap(520, tokens or DARK_TOKENS))
        banner.setAlignment(Qt.AlignmentFlag.AlignCenter)

        heading = QLabel(
            f"<h1>{APP_NAME} {APP_VERSION}</h1>"
            f"<p><b>{APP_TAGLINE}</b></p>"
            f"<p>by <b>{APP_AUTHOR}</b></p>"
        )
        heading.setTextFormat(Qt.TextFormat.RichText)
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)

        deps = QLabel(self._deps_html())
        deps.setTextFormat(Qt.TextFormat.RichText)
        deps.setWordWrap(True)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(banner)
        layout.addWidget(heading)
        layout.addWidget(deps)
        layout.addWidget(buttons)
        self.setMinimumWidth(420)

    @staticmethod
    def _deps_html() -> str:
        rows = []
        for mod, hint in _ENGINE_DEPS.items():
            status = "✅" if importlib.util.find_spec(mod) else "❌"
            rows.append(f"<tr><td>{status}</td><td><code>{mod}</code></td><td>{hint}</td></tr>")
        return (
            "<p><b>Engine dependencies</b> (needed from Step 2 onwards):</p>"
            f"<table>{''.join(rows)}</table>"
            f"<p>License: {APP_LICENSE}</p>"
        )

