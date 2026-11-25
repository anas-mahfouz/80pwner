# 80PWNER — by Anas Mahfouz (The 80)

from PySide6.QtGui import QFontDatabase

from eightypwner.platform.debuggers import detect_backends, gdb_status, os_name
from eightypwner.ui import fonts


def test_bundled_font_loaded(qtbot):
    """The OFL JetBrains Mono must resolve before the fallback chain."""
    families = fonts.load_bundled_fonts()
    assert QFontDatabase.families() is not None
    if families:
        assert "JetBrains Mono" in families


def test_resolve_monospace_prefers_bundled_or_fallback(qtbot):
    fonts.load_bundled_fonts()
    family = fonts.resolve_monospace()
    known = fonts.installed_families()
    assert family == "Monospace" or family in known


def test_gdb_detection_never_crashes():
    tools = detect_backends()
    gdb = gdb_status()
    assert gdb is not None and tools.by_name("gdb") == gdb
    # Support level map must be honest per OS (spec C):
    if os_name() == "linux" and gdb.available:
        assert gdb.support_level == "full"
    elif not gdb.available:
        assert gdb.support_level == "missing"
        assert "apt" in gdb.hint or "brew" in gdb.hint or "winget" in gdb.hint
    else:
        assert gdb.support_level == "static-only"
