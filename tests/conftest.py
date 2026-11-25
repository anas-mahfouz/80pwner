# 80PWNER — by Anas Mahfouz (The 80)

import os
import sys
from pathlib import Path

# Keep Qt headless regardless of the developer's environment.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Tests get an isolated config dir so real user settings are never touched.
os.environ.setdefault("EIGHTYPWNER_HOME", "/tmp/80pwner-tests")

# Pin the Qt locale: LC_NUMERIC may point at a digit-localized region
# (e.g. ar_EG) and then every QSpinBox renders '١٢٠' instead of '120'
# even though QLineEdit stays ASCII. Mirrors cli.py's startup pin.
if os.environ.get("LC_NUMERIC", "").startswith("ar"):
    from PySide6.QtCore import QLocale

    QLocale.setDefault(QLocale.c())


# --------------------------------------------------------------------------
# Qt lifecycle
#
# One QApplication for the whole session, created here instead of inside
# individual tests. Keeping a strong reference (and tearing widgets down
# deterministically while the app is still alive) avoids the intermittent
# "pure virtual method called" abort that PySide6 can raise when Python
# finalisation destroys QObject subclasses after their C++ vtable is gone.
# --------------------------------------------------------------------------
_QT_APP = None


def pytest_configure(config):
    global _QT_APP
    from PySide6.QtWidgets import QApplication

    _QT_APP = QApplication.instance() or QApplication([])


def pytest_sessionfinish(session, exitstatus):
    """Delete every top-level widget before the interpreter shuts down."""
    import gc

    from PySide6.QtCore import QEvent
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        return
    for widget in app.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    app.processEvents()
    app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
    # Drop remaining Python-side references (plugins, relays, models) while
    # QApplication still exists so their C++ destructors run in a safe order.
    gc.collect()
