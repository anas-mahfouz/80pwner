# 80PWNER — by Anas Mahfouz (The80)

from eightypwner.constants import ACCENT_DARK, ACCENT_LIGHT, APP_AUTHOR
from eightypwner.core.settings import Settings
from eightypwner.ui.theme import ThemeManager, render_theme, system_prefers_dark


def test_render_dark_tokens():
    t = render_theme("dark")
    assert t.tokens["accent"] == ACCENT_DARK == "#00FF9C"
    assert ACCENT_DARK in t.qss


def test_render_light_tokens():
    t = render_theme("light")
    assert t.tokens["accent"] == ACCENT_LIGHT == "#007A5A"
    assert ACCENT_LIGHT in t.qss


def test_mono_font_substituted():
    t = render_theme("dark", mono_font="DejaVu Sans Mono")
    assert "$MONO" not in t.qss
    assert "DejaVu Sans Mono" in t.qss


def test_no_unresolved_tokens():
    import re

    for mode in ("dark", "light"):
        qss = render_theme(mode, mono_font="X").qss
        assert not re.search(r"\$\{[a-z_]+\}", qss), f"{mode} theme has unresolved tokens"


def test_toggle_and_persistence(qtbot, tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    settings = Settings()
    tm = ThemeManager(settings)
    dark = tm.resolved_mode()
    with qtbot.waitSignal(tm.theme_changed):
        tm.toggle()
    assert tm.resolved_mode() != dark
    # New instance restores the persisted choice.
    assert ThemeManager(Settings()).resolved_mode() == tm.resolved_mode()


def test_system_mode_resolves(qtbot, tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    tm = ThemeManager(Settings())

    tm.set_mode_persist("system")
    expected = "dark" if system_prefers_dark() else "light"
    assert tm.resolved_mode() == expected
    assert tm.resolved_mode() in ("dark", "light")


def test_branding_in_spans():

    assert APP_AUTHOR == "Anas Mahfouz (The80)"
