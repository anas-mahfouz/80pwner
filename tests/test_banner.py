# 80PWNER — by Anas Mahfouz (The80)
#
"""Banner tests: figlet asset legible, two-tone rendering, no clipping offscreen."""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from PySide6.QtGui import QColor, QImage

from eightypwner.constants import load_banner_art
from eightypwner.ui.banner import AsciiBannerWidget, ascii_banner_pixmap, fit_px

ASSET = Path(__file__).resolve().parents[1] / "src" / "eightypwner" / "assets" / "banner.txt"
DOCS = Path(__file__).resolve().parents[1] / "docs"


def _art_lines() -> list[str]:
    art, _ = load_banner_art()
    return art.splitlines()


def _count_colors(image: QImage) -> int:
    return len({
        QColor(image.pixel(x, y)).name()
        for x in range(0, image.width(), 5)
        for y in range(0, image.height(), 3)
    })


def test_asset_exists_and_wellformed():
    assert ASSET.is_file(), "assets/banner.txt must exist"
    _art, split = load_banner_art()
    lines = _art_lines()
    assert lines, "banner asset non-empty"
    assert split >= 1, "two-tone split column present"
    # equal column count on all rows (figlet output is a rectangle)
    widths = {len(line) for line in lines}
    assert len(widths) == 1
    # include only printable banner glyphs — squares/hyphens, no replacement chars
    assert all("�" not in line for line in lines)


@pytest.mark.skipif(not ASSET.is_file(), reason="banner asset missing")
def test_asset_matches_pyfiglet_regeneration():
    pytest.importorskip("pyfiglet", reason="dev-only regeneration check")
    import pyfiglet

    art = pyfiglet.figlet_format("THE80-PWNER", font="ansi_shadow", width=512)
    regenerated = art.rstrip()
    asset_lines = [
        line
        for line in ASSET.read_text(encoding="utf-8").splitlines()
        if not line.startswith("#")
    ]
    assert "\n".join(asset_lines) == regenerated, (
        "banner asset drifted from the pyfiglet source — run tools/gen_banner.py"
    )


def test_cli_version_art_is_the_asset():
    from eightypwner.constants import ASCII_ART, VERSION_BANNER

    assert ASCII_ART in VERSION_BANNER
    assert ASCII_ART.splitlines()[0] == _art_lines()[0]


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_banner_pixmap_renders_two_tone(qtbot, tmp_path, monkeypatch, mode):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    tokens = DARK_TOKENS if mode == "dark" else LIGHT_TOKENS

    pixmap = ascii_banner_pixmap(760, tokens)
    image = pixmap.toImage()
    assert not image.isNull()
    assert image.width() >= 300, "sane art width at 760px viewport"
    assert _count_colors(image) > 2, f"{mode}: art painted over background"


def _make_widget(qtbot, mode, width=760):
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    tokens = DARK_TOKENS if mode == "dark" else LIGHT_TOKENS
    widget = AsciiBannerWidget(tokens)
    widget.resize(width, 200)
    qtbot.addWidget(widget)
    return widget


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_banner_widget_autofit_and_no_clip(qtbot, tmp_path, monkeypatch, mode):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    lines = _art_lines()
    cols = len(lines[0])

    widget = _make_widget(qtbot, mode, width=760)
    widget._px = fit_px(760, cols)
    natural = widget.natural_size(widget._px)
    assert natural.width() <= 760, "full art fits the viewport width (auto-scale)"

    image = widget.grab().toImage()
    assert not image.isNull()
    assert _count_colors(image) > 2

    # no clipping: every figlet row paints visible glyph pixels inside the
    # art's own span (the widget is wider than the art and centers it).
    natural = widget.natural_size(widget._px)
    natural_w, natural_h = natural.width(), natural.height()
    x0 = max((widget.width() - natural_w) // 2, 0)
    row_h = natural_h // len(lines)
    top = max((widget.height() - natural_h) // 2, 0)
    for row in range(len(lines)):
        y = min(int(top + row * row_h + row_h / 2), image.height() - 1)
        colors = {
            QColor(image.pixel(x, y)).name()
            for x in range(x0, min(x0 + natural_w, image.width() - 1), 2)
        }
        assert len(colors) > 1, f"{mode}: figlet row {row} painted (no clip)"


def test_narrow_falls_back_to_scroll_geometry(qtbot, tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    # the widget has an explicit minimum art width (scroll fallback): at a
    # 120px-wide viewport the art cannot fit ≥ MIN_PX, so it stays wide.
    widget = _make_widget(qtbot, "dark", width=120)
    assert widget.render_target() > 120, "art wider than the viewport → scrollable"


def test_banner_screenshot_saved_to_docs(qtbot, tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    from eightypwner.ui.theme import DARK_TOKENS

    pixmap = ascii_banner_pixmap(760, DARK_TOKENS)
    DOCS.mkdir(exist_ok=True)
    ok = pixmap.toImage().save(str(DOCS / "banner.png"))
    assert ok and (DOCS / "banner.png").exists()


def test_theme_tokens_two_tone_colors_differ():
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    for tokens in (DARK_TOKENS, LIGHT_TOKENS):
        assert tokens["accent"] != tokens["accent_pressed"]
        assert _relative_lum(tokens["accent"]) > 0


def _relative_lum(hex_color: str) -> float:
    """WCAG luminance of a #RRGGBB color."""
    value = hex_color.lstrip("#")
    rgb = [int(value[i : i + 2], 16) / 255.0 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def test_contrast_of_banner_shades_on_both_backgrounds():
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    def ratio(a: str, b: str) -> float:
        la, lb = _relative_lum(a), _relative_lum(b)
        lighter, darker = max(la, lb), min(la, lb)
        return (lighter + 0.05) / (darker + 0.05)

    # large/text art: WCAG ≥ 3:1 against the panel background in both themes
    for tokens in (DARK_TOKENS, LIGHT_TOKENS):
        assert ratio(tokens["accent"], tokens["bg"]) >= 3.0, "left shade contrast"
        assert ratio(tokens["accent_pressed"], tokens["bg"]) >= 3.0, "right shade contrast"
        assert (ratio(tokens["accent"], tokens["accent_pressed"]) >= 1.15 or math.isclose(
            ratio(tokens["accent"], tokens["accent_pressed"]), 1.15, rel_tol=0.4
        )), "two shades visually distinct from each other"
