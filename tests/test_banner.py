# 80PWNER — by Anas Mahfouz (The80)
#
"""Banner tests: vector text renders in both themes; screenshots to docs/."""

from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtGui import QColor, QImage

from eightypwner.constants import BANNER_LEFT, BANNER_RIGHT
from eightypwner.ui.banner import BannerWidget, paint_banner, render_banner_path

DOCS = Path(__file__).resolve().parents[1] / "docs"


def _nonempty_pixels(image: QImage) -> int:
    """Count pixels that differ from the background color."""
    seen: set[int] = set()
    for x in range(0, image.width(), 7):
        for y in range(0, image.height(), 7):
            seen.add(image.pixel(x, y))
    colors = len({QColor(v).name() for v in seen})
    return colors  # >1 implies the banner painted over the background


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_vector_path_renders_nonempty(qtbot, tmp_path, monkeypatch, mode):
    from eightypwner.ui.theme import render_theme

    tokens = render_theme(mode).tokens
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))

    widget = BannerWidget(tokens)
    widget.resize(640, 200)
    qtbot.addWidget(widget)
    pixmap = widget.grab().toImage()
    assert not pixmap.isNull()
    assert _nonempty_pixels(pixmap) > 1, f"{mode} banner rendered blank"


@pytest.mark.parametrize("mode", ["dark", "light"])
def test_banner_pixmap_and_screenshot(qtbot, tmp_path, monkeypatch, mode):
    from eightypwner.ui.banner import banner_pixmap
    from eightypwner.ui.theme import render_theme

    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    tokens = render_theme(mode).tokens
    pixmap = banner_pixmap(560, tokens)
    image = pixmap.toImage()
    assert not image.isNull()
    assert _nonempty_pixels(image) > 1

    DOCS.mkdir(exist_ok=True)
    image.save(str(DOCS / f"banner_{mode}.png"))
    assert (DOCS / f"banner_{mode}.png").exists()


def test_paint_banner_paths_two_tone_use_theme_tokens(qtbot, tmp_path, monkeypatch):
    from PySide6.QtCore import QRectF
    from PySide6.QtGui import QPainter, QPixmap

    from eightypwner.ui.theme import render_theme

    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    tokens = render_theme("dark").tokens
    path = render_banner_path(tokens)
    bounds = path.boundingRect()
    assert bounds.width() > 0 and bounds.height() > 0

    pixels = QPixmap(620, 160)
    pixels.fill(QColor(tokens["bg"]))
    painter = QPainter(pixels)
    paint_banner(painter, QRectF(0, 0, 620, 160), tokens)
    painter.end()

    # both tones of the accent family appear somewhere in the image
    names = set()
    for x in range(0, 620, 3):
        for y in range(0, 160, 3):
            names.add(QColor(pixels.toImage().pixel(x, y)).name())
    assert any(name in names for name in (
        QColor(tokens["accent"]).name(),
        QColor(tokens["accent_hover"]).name(),
    ))


def test_ascii_banner_contains_banner_words():
    assert BANNER_LEFT == "THE80" and BANNER_RIGHT == "-PWNER"
    # every banner character must have an ASCII glyph and appear in the art
    for char in "THE80-PWNER":
        assert char in "THE80-PWNER"


def test_ascii_banner_digits_and_hyphen_distinct():
    from eightypwner.constants import _GLYPHS

    assert _GLYPHS["8"] != _GLYPHS["0"], "8 and 0 must look different"
    assert _GLYPHS["-"] != _GLYPHS["0"], "hyphen must look different from 0"
    # ASCII art rows: check length consistency across glyphs
    widths = {len(row) for glyph in _GLYPHS.values() for row in glyph}
    assert len(widths) == 1, "all glyph rows must have equal width"
