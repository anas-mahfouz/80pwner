# 80PWNER — by Anas Mahfouz (The80)

"""Welcome plugin — a placeholder proving the plugin system end-to-end.

Replaced by the real Binary Overview module in Step 2. Styled by the global
theme via ``role`` properties (QSS selectors), so it adapts to dark/light.
"""

from __future__ import annotations

import contextlib
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from eightypwner.constants import APP_AUTHOR, APP_NAME, APP_VERSION, ASCII_ART
from eightypwner.modules.interface import Plugin
from eightypwner.ui.fonts import resolve_monospace


class WelcomePlugin(Plugin):
    name = "Welcome"
    description = "Startup panel with project branding and hints."
    icon = "⌗"

    def widget(self) -> QWidget:
        """Build and return this plugin's panel widget."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addStretch(1)

        logo = QLabel(ASCII_ART)
        logo.setProperty("role", "brandAscii")
        logo.setFont(QFont(resolve_monospace(self.ctx.settings.get("font.mono_family") or "")))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel(
            f"<h1>{APP_NAME} {APP_VERSION}</h1><p><i>by {APP_AUTHOR}</i></p>"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hint = QLabel(
            "Drag & drop a binary here or use <b>File → Open Binary…</b><br>"
            "Modules arrive with each build step — next up: Binary Overview + Checksec.<br>"
            "Toggle theme with <b>Ctrl+Shift+T</b> or the toolbar button."
        )
        hint.setObjectName("welcomeHint")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        for child in (logo, title, hint):
            layout.addWidget(child)
        layout.addStretch(2)

        self._panel = w
        self._hint = hint
        return w

    def on_event(self, topic: str, payload: Any) -> None:
        if topic == "binary_dropped":
            path = payload.get("path", "?") if isinstance(payload, dict) else str(payload)
            icon = payload.get("icon", "") if isinstance(payload, dict) else ""
            self._hint.setText(
                f"{icon} Received binary: <b>{_escape(path)}</b><br>"
                "The Binary Overview module arrives in Step 2."
            )

    def initialize(self, parent: Any = None) -> None:
        # UI touches (the hint label) must happen on the UI thread — use the
        # UiBus bridge when available, or the raw bus otherwise.
        subscribe = (
            self.ctx.ui_bus.subscribe
            if self.ctx.ui_bus is not None
            else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_event)

    def shutdown(self) -> None:
        with contextlib.suppress(Exception):
            self._unsub()


def _escape(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;")
