# 80PWNER — by Anas Mahfouz (The 80)

"""Config/log/session locations on Windows, macOS and Linux.

- settings → user_config_dir("80pwner")
- sessions/notes (SQLite, Step 10) → user_data_dir("80pwner")/sessions
- logs → user_log_dir("80pwner")

``EIGHTYPWNER_HOME`` overrides the location in full (used by tests and
portable installations). An existing legacy ``~/.80pwner`` installation is
migrated automatically once, on first run.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

log = logging.getLogger(__name__)

try:
    from platformdirs import PlatformDirs

    _dirs = PlatformDirs(appname="80pwner", appauthor="The 80")
except ImportError:  # pragma: no cover — platformdirs is a hard dependency
    log.warning("platformdirs missing; falling back to ~/.80pwner")
    _dirs = None

ENV_HOME = "EIGHTYPWNER_HOME"
LEGACY_DIR_NAME = ".80pwner"


def _env_home() -> Path | None:
    value = os.environ.get(ENV_HOME, "").strip()
    return Path(value) if value else None


def config_dir() -> Path:
    """Directory holding settings.json (and other small user config)."""
    override = _env_home()
    if override is not None:
        return override
    return (
        Path(_dirs.user_config_dir)
        if _dirs is not None
        else Path.home() / LEGACY_DIR_NAME
    )


def session_dir() -> Path:
    """Directory for per-challenge workspaces (SQLite sessions, Step 10)."""
    override = _env_home()
    if override is not None:
        return override / "sessions"
    return (
        Path(_dirs.user_data_dir) / "sessions"
        if _dirs is not None
        else Path.home() / LEGACY_DIR_NAME / "sessions"
    )


def log_dir() -> Path:
    override = _env_home()
    if override is not None:
        return override / "logs"
    return (
        Path(_dirs.user_log_dir)
        if _dirs is not None
        else Path.home() / LEGACY_DIR_NAME / "logs"
    )


def legacy_config_dir() -> Path | None:
    """The old hardcoded ~/.80pwner (Step-1 default), if it exists."""
    home_override = _env_home()
    home = Path(home_override) if home_override else Path.home()
    candidate = home / LEGACY_DIR_NAME
    return candidate if candidate.exists() else None


def migrate_legacy_config() -> Path | None:
    """Move the legacy ~/.80pwner into its new location (platformdirs or EIGHTYPWNER_HOME).

    Only runs when the target does not exist yet and the legacy dir does.
    Returns the new location on migration, else None.
    """
    legacy = legacy_config_dir()
    if legacy is None:
        return None
    if config_dir().exists() or session_dir().exists() or log_dir().exists():
        return None  # already initialised — never clobber new data
    target = config_dir()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(legacy), str(target))
        log.info("Migrated legacy config %s → %s", legacy, target)
        return target
    except OSError:
        log.exception("Could not migrate legacy config from %s; starting fresh", legacy)
        return None
