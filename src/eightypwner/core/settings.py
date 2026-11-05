# 80PWNER — by Anas Mahfouz (The80)

"""Application settings, persisted as JSON under ``~/.80pwner/settings.json``.

Keys are dotted strings; unknown keys keep their defaults. Pure Python (no Qt)
so it is trivially testable and usable from worker threads.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

THEME_MODES = ("dark", "light", "system")

DEFAULTS: dict[str, Any] = {
    "theme.mode": "dark",            # dark | light | system
    "font.mono_family": "",          # "" → auto-pick (JetBrains Mono → system mono)
    "font.mono_size": 12,
    "window.geometry": "",           # base64 QByteArray on save/restore
    "window.dock_state": "",
}


def config_dir() -> Path:
    return Path(os.environ.get("EIGHTYPWNER_HOME", str(Path.home() / ".80pwner")))


def settings_path() -> Path:
    return config_dir() / "settings.json"


def log_dir() -> Path:
    return config_dir() / "logs"


class Settings:
    """Load/save/observe dotted settings with defaults."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = dict(DEFAULTS)
        self._watchers: list[tuple[str, Any]] = []
        self.load()

    # -- basic access ------------------------------------------------------
    def get(self, key: str, fallback: Any = None) -> Any:
        if key in self._data:
            return self._data[key]
        return DEFAULTS.get(key, fallback)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        for watched, callback in self._watchers:
            if watched == key or watched == "*":
                try:
                    callback(key, value)
                except Exception:
                    log.exception("Settings watcher failed for %s", key)
        self.save()  # settings are tiny; persist immediately so choices survive crashes

    def reset(self, key: str) -> None:
        self._data.pop(key, None)

    # -- persistence -------------------------------------------------------
    def load(self) -> None:
        path = settings_path()
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                self._data = {**DEFAULTS, **stored}
        except FileNotFoundError:
            pass
        except Exception:
            log.warning("Could not read settings at %s; using defaults", path)

    def save(self) -> None:
        try:
            settings_path().parent.mkdir(parents=True, exist_ok=True)
            settings_path().write_text(
                json.dumps(self._data, indent=2, sort_keys=True), encoding="utf-8"
            )
        except Exception:
            log.exception("Could not save settings")

    # -- watchers ----------------------------------------------------------
    def watch(self, key: str, callback: Callable[[str, Any], None]) -> Callable[[], None]:
        """Call *callback*(key, value) whenever *key* (or "*") is set."""
        self._watchers.append((key, callback))
        return lambda: self._watchers.remove((key, callback))
