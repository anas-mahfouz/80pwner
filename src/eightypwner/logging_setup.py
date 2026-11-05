# 80PWNER — by Anas Mahfouz (The80)

"""Logging to ~/.80pwner/logs (spec §8) with console mirror."""

from __future__ import annotations

import logging
import logging.handlers

from eightypwner.core.settings import log_dir


def setup_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger("eightypwner")
    root.setLevel(level)
    if root.handlers:
        return

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        log_dir().mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir() / "80pwner.log",
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError:  # unwritable HOME — console logging still works
        pass
