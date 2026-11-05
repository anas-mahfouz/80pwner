# 80PWNER — by Anas Mahfouz (The80)

"""Splash screen showing the brand while the app boots (spec §2).

QSplashScreen has no "minimum duration" API (that belongs to QProgressDialog),
so we keep the splash visible for a short fixed time and let the caller
``finish()`` it over the main window once that time has elapsed.
"""

from __future__ import annotations

import time

from PySide6.QtCore import QEventLoop, Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication, QSplashScreen, QWidget

from eightypwner.constants import APP_AUTHOR, APP_NAME
from eightypwner.ui.logo import app_logo_pixmap

SPLASH_MIN_MS = 700

_shown_at: list[float] = []


def show_splash() -> QSplashScreen:
    """Show the splash and record when it appeared."""
    splash = QSplashScreen(app_logo_pixmap(320))
    splash.showMessage(
        f"{APP_NAME} — by {APP_AUTHOR}",
        int(Qt.AlignmentFlag.AlignBottom),
        QColor("#FF2D3D"),  # brand accent; the splash tile is always dark
    )
    splash.show()
    app = QApplication.instance()
    if app is not None:
        # Pump events so the splash paints before slow imports/UI construction.
        app.processEvents()
    _shown_at.append(time.monotonic())
    return splash


def finish_splash(splash: QSplashScreen, window: QWidget) -> None:
    """Keep the splash up for its minimum display time, then finish over *window*."""
    app = QApplication.instance()
    shown = _shown_at[-1] if _shown_at else None
    wait = SPLASH_MIN_MS - (time.monotonic() - shown) * 1000 if shown is not None else SPLASH_MIN_MS
    if app is not None and wait > 0:
        loop = QEventLoop()
        QTimer.singleShot(int(wait), loop.quit)
        loop.exec()  # blocks; stays responsive (processes paint/input events)
    splash.finish(window)
