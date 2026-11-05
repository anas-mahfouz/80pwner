# 80PWNER — by Anas Mahfouz (The80)

"""Welcome plugin — branding panel driven by the theme + plugin registry.

No hardcoded roadmap text: the "Loaded modules" list is generated from the
registry when the main window announces modules_loaded. Styled by theme
tokens so it adapts to dark/light."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from eightypwner.constants import APP_AUTHOR, APP_NAME, APP_VERSION
from eightypwner.modules.interface import Plugin
from eightypwner.ui.banner import BannerWidget
from eightypwner.ui.fonts import resolve_monospace

if TYPE_CHECKING:
    pass


class WelcomePlugin(Plugin):
    name = "Welcome"
    description = "Startup panel with project branding and hints."
    icon = "⌗"

    def widget(self) -> QWidget:
        """Build and return this plugin's panel widget."""
        panel = QWidget()
        self._panel = panel
        layout = QVBoxLayout(panel)
        layout.addStretch(1)

        tokens = self._tokens()
        self._banner = BannerWidget(tokens)
        layout.addWidget(self._banner, 1)

        title = QLabel(f"<h2>{APP_NAME} {APP_VERSION}</h2><p style='margin:0'><i>by {APP_AUTHOR}</i></p>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hint = QLabel(
            "Drag & drop a binary here or use <b>File → Open Binary…</b> (Ctrl+O)<br>"
            "Toggle theme with <b>Ctrl+Shift+T</b> or the toolbar button"
        )
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._modules_caption = QLabel("<b>Loaded modules</b>")
        self._modules_list = QLabel("…")
        for label in (self._modules_caption, self._modules_list):
            label.setAlignment(Qt.AlignmentFlag.AlignLeft)
            label.setFont(QFont(resolve_monospace(self.ctx.settings.get("font.mono_family") or "")))
            label.setEnabled(False)

        for child in (title, hint, self._modules_caption, self._modules_list):
            layout.addWidget(child)
        layout.addStretch(2)
        return panel

    def _modules_caption(self, loaded: bool) -> str:
        return "<b>Loaded modules</b>" if loaded else "<b>Loaded modules</b> (waiting for main window)"

    # ------------------------------------------------------------- lifecycle
    def initialize(self, parent: Any = None) -> None:
        # UI touches (labels, banner repaint) must happen on the UI thread.
        subscribe = (
            self.ctx.ui_bus.subscribe
            if self.ctx.ui_bus is not None
            else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_event)
        theme = self.ctx.theme if getattr(self.ctx, "theme", None) else None
        if theme is not None:
            theme.theme_changed.connect(self._on_theme_changed)

    def shutdown(self) -> None:
        with contextlib.suppress(Exception):
            self._unsub()

    # ---------------------------------------------------------------- events
    def _on_theme_changed(self, theme: Any) -> None:
        self._banner.set_tokens(theme.tokens)

    def on_event(self, topic: str, payload: Any) -> None:
        if topic == "modules_loaded" and isinstance(payload, dict):
            plugins = payload.get("plugins", [])
            modules = "\n".join(f"  {p.get('icon', '')} {p.get('name', '')}" for p in plugins)
            self._modules_caption.setText("<b>Loaded modules</b>")
            self._modules_list.setText(modules or "  (none)")
        elif topic == "binary_dropped" and isinstance(payload, dict):
            path = payload.get("path", "?")
            icon = payload.get("icon", "")
            self._modules_caption.setText(
                f"<b>{_escape(icon + ' ' + str(path))}</b> — loading in Binary Overview…"
            )

    # ---------------------------------------------------------------- helpers
    def _tokens(self) -> dict[str, str]:
        from eightypwner.ui.theme import render_theme

        theme = getattr(self.ctx, "theme", None)
        if theme is not None:
            resolved = theme.theme()
            return dict(resolved.tokens)
        return dict(render_theme("dark").tokens)


def _escape(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;")
