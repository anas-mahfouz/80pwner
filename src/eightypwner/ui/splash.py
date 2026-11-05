# 80PWNER — by Anas Mahfouz (The80)

"""Splash screen showing the brand while the app boots (spec §2)."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QSplashScreen

from eightypwner.constants import APP_AUTHOR, APP_NAME
from eightypwner.ui.logo import app_logo_pixmap


def show_splash() -> QSplashScreen:
    splash = QSplashScreen(app_logo_pixmap(320))
    splash.showMessage(
        f"{APP_NAME} — by {APP_AUTHOR}", int(Qt.AlignmentFlag.AlignBottom), Qt.GlobalColor.white
    )
    app = QApplication.instance()
    if app is not None:
        app.processEvents()
    splash.show()
    return splash
