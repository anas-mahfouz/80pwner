# 80PWNER — by Anas Mahfouz (The 80)

"""Platform services in one place (config/log/session locations, debugger
detection, install hints). Everything here falls back gracefully — the app
must never crash because a tool or OS feature is missing."""

from eightypwner.platform.paths import (
    config_dir,
    legacy_config_dir,
    log_dir,
    migrate_legacy_config,
    session_dir,
)

__all__ = [
    "config_dir",
    "legacy_config_dir",
    "log_dir",
    "migrate_legacy_config",
    "session_dir",
]
