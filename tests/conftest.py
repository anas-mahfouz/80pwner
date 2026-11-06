# 80PWNER — by Anas Mahfouz (The80)

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
