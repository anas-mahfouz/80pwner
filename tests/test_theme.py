# 80PWNER — by Anas Mahfouz (The 80)

from eightypwner.constants import ACCENT_DARK, ACCENT_LIGHT, APP_AUTHOR
from eightypwner.core.settings import Settings
from eightypwner.ui.theme import (
    DARK_TOKENS,
    LIGHT_TOKENS,
    ThemeManager,
    render_theme,
    system_prefers_dark,
)


def test_render_dark_tokens():
    t = render_theme("dark")
    assert t.tokens["accent"] == ACCENT_DARK == "#FF2D3D"
    assert ACCENT_DARK in t.qss
    assert t.tokens["accent_hover"] == "#FF5560"
    assert t.tokens["accent_pressed"] == "#C81E2C"


def test_render_light_tokens():
    t = render_theme("light")
    assert t.tokens["accent"] == ACCENT_LIGHT == "#C8102E"
    assert ACCENT_LIGHT in t.qss
    assert t.tokens["accent_hover"] == "#E02A45"
    assert t.tokens["accent_pressed"] == "#9E0C24"


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
    assert APP_AUTHOR == "Anas Mahfouz (The 80)"


# --- WCAG contrast verification ------------------------------------------------
def _lin(c: int) -> float:
    c /= 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def _rgb(hex_color: str) -> tuple[float, float, float]:
    h = hex_color.lstrip("#")
    return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]


def _luminance(hex_color: str) -> float:
    r, g, b = _rgb(hex_color)
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def _contrast(a: str, b: str) -> float:
    la, lb = _luminance(a), _luminance(b)
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def test_body_text_contrast_both_themes():
    for tokens in (DARK_TOKENS, LIGHT_TOKENS):
        assert _contrast(tokens["fg"], tokens["bg"]) >= 4.5
        assert _contrast(tokens["fg"], tokens["panel"]) >= 4.5
        assert _contrast(tokens["fg"], tokens["panel_alt"]) >= 4.5


def test_accent_and_semantics_contrast_both_themes():
    for tokens in (DARK_TOKENS, LIGHT_TOKENS):
        # brand text on page backgrounds
        assert _contrast(tokens["accent"], tokens["bg"]) >= 3.0
        # button/selection text on accent (bold UI text)
        assert _contrast(tokens["on_accent"], tokens["accent"]) >= 3.0
        # badges: enabled=green, disabled=red-error, both distinguishable
        assert _contrast(tokens["ok"], tokens["ok_bg"]) >= 3.0
        assert _contrast(tokens["on_error"], tokens["error"]) >= 4.5
        # error must differ from the accent so errors stay readable
        assert tokens["error"] != tokens["accent"]
