# 80PWNER — by Anas Mahfouz (The80)
#
"""Central theme manager (spec §5): Dark / Light / Follow-system.

Loads QSS templates from ``assets/themes/*.qss``, substitutes color tokens
(`${accent}` …) plus the configured monospace font, applies them via
``QApplication.setStyleSheet`` and notifies listeners through ``theme_changed``.
The choice is persisted in :class:`~eightypwner.core.settings.Settings` and
restored on the next launch.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib import resources
from typing import Literal

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

from eightypwner.core.settings import Settings
from eightypwner.ui.fonts import resolve_monospace

log = logging.getLogger(__name__)

ThemeMode = Literal["dark", "light", "system"]
ThemeModes = ("dark", "light", "system")

# Token palettes (spec §2 accents: #00FF9C dark / #007A5A light).
DARK_TOKENS = {
    "mode": "dark",
    "accent": "#00FF9C",
    "accent_dim": "#1E7A5C",
    "on_accent": "#06100C",
    "bg": "#0F1418",
    "panel": "#161B20",
    "panel_alt": "#1C2429",
    "fg": "#E8F0EC",
    "dim": "#9AA8A2",
    "border": "#2A333A",
    "warn": "#FFB454",
    "danger": "#FF5C57",
    "ok": "#00E17F",
}

LIGHT_TOKENS = {
    "mode": "light",
    "accent": "#007A5A",
    "accent_dim": "#009473",
    "on_accent": "#FFFFFF",
    "bg": "#F4F7F6",
    "panel": "#FFFFFF",
    "panel_alt": "#E9EFEC",
    "fg": "#17211C",
    "dim": "#5E6E67",
    "border": "#C9D4CF",
    "warn": "#B26A00",
    "danger": "#C62828",
    "ok": "#007A5A",
}


@dataclass(frozen=True)
class ResolvedTheme:
    """A fully resolved theme: mode, tokens and rendered QSS."""

    mode: ThemeMode
    tokens: dict[str, str]
    qss: str


def load_qss_template(mode: ThemeMode) -> str:
    file = "dark.qss" if mode == "dark" else "light.qss"
    return resources.files("eightypwner.assets.themes").joinpath(file).read_text(encoding="utf-8")


def system_prefers_dark() -> bool:
    """Best-effort system detection; defaults to dark (the hacker aesthetic)."""
    try:
        app = QApplication.instance()
        if app is not None:
            hints = app.styleHints()
            scheme = getattr(hints, "colorScheme", None)
            if callable(scheme):
                from PySide6.QtGui import Qt

                return scheme() != Qt.ColorScheme.Light
    except Exception:
        log.debug("colorScheme detection failed; assuming dark", exc_info=True)
    return True


def render_theme(mode: ThemeMode, mono_font: str = "") -> ResolvedTheme:
    tokens = dict(DARK_TOKENS if mode == "dark" else LIGHT_TOKENS)
    qss = load_qss_template(mode)
    # $MONO stays literal; ${tokens} are substituted.
    qss = qss.replace("$MONO", mono_font or "Monospace")
    for key, value in tokens.items():
        qss = qss.replace("${" + key + "}", value)
    return ResolvedTheme(mode=mode, tokens=tokens, qss=qss)


class ThemeManager(QObject):
    """Owns the current theme mode, applies QSS and emits ``theme_changed``."""

    theme_changed = Signal(object)  # ResolvedTheme

    def __init__(self, settings: Settings, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._settings = settings
        self._mode: ThemeMode = settings.get("theme.mode") or "dark"
        if self._mode not in ThemeModes:
            self._mode = "dark"
        self.apply()

    @property
    def mode(self) -> ThemeMode:
        return self._mode

    def apply(self) -> None:
        mode = self._mode
        if mode == "system":
            mode = "dark" if system_prefers_dark() else "light"
        theme = render_theme(mode, mono_font=self._mono_font())
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.qss)
        self.theme_changed.emit(theme)
        log.info("Theme applied: %s", mode)

    def set_mode(self, mode: ThemeMode, persist: bool = True) -> None:
        if mode not in ThemeModes:
            log.warning("Unknown theme mode %r ignored", mode)
            return
        self._mode = mode
        if persist:
            self._settings.set("theme.mode", mode)
        self.apply()

    def set_mode_persist(self, mode: ThemeMode) -> None:
        self.set_mode(mode, persist=True)

    def toggle(self) -> None:
        """Toolbar shortcut (Ctrl+Shift+T): dark <-> light."""
        self.set_mode_persist("light" if self.resolved_mode() == "dark" else "dark")

    def resolved_mode(self) -> ThemeMode:
        if self._mode == "system":
            return "dark" if system_prefers_dark() else "light"
        return self._mode

    def theme(self) -> ResolvedTheme:
        return render_theme(
            self.resolved_mode(),
            mono_font=self._mono_font(),
        )

    def _mono_font(self) -> str:
        return resolve_monospace(self._settings.get("font.mono_family") or "")
