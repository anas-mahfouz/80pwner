# 80PWNER — by Anas Mahfouz (The80)

"""Banner tests — bitmap block font (banner_font.py), asset, CLI fallback.

The banner is a hand-designed 5x7 cell bitmap font rendered by QPainter; the
text asset (assets/banner.txt) and the CLI --version output must match it
exactly. The glyph grid is printed to the test console for visual review.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

from eightypwner.constants import (
    APP_BANNER,
    BANNER_LEFT,
    VERSION_BANNER,
    load_banner_art,
    terminal_banner,
)
from eightypwner.ui import banner_font as bf

ASSET = Path(__file__).resolve().parents[1] / "src" / "eightypwner" / "assets" / "banner.txt"

EXPECTED_COLS = bf.glyph_cols(len(APP_BANNER))  # 11 glyphs → 65 columns


def _asset_lines() -> list[str]:
    return [
        line
        for line in ASSET.read_text(encoding="utf-8").splitlines()
        if not line.startswith("#")
    ]


# ------------------------------------------------------------------ glyphs
def test_glyphs_are_wellformed():
    for char, rows in bf.GLYPHS.items():
        assert len(rows) == bf.GLYPH_H, f"{char!r}: {len(rows)} rows"
        assert all(len(row) == bf.GLYPH_W for row in rows), f"{char!r}: width"
        assert all(set(row) <= {"#", " "} for row in rows), f"{char!r}: cells"


def test_glyph_bitmaps_all_unique():
    """No two glyphs share a bitmap (checked visually in the printed dump)."""
    bitmaps = {char: bf.glyph_bitmap(char) for char in bf.GLYPHS}
    for a_char, b_char in itertools.combinations(bitmaps, 2):
        assert bitmaps[a_char] != bitmaps[b_char], (
            f"{a_char!r} and {b_char!r} have identical bitmaps"
        )


def test_glyph_expected_width_and_dump(capsys):
    """The full banner text has the expected width; dump the art for review."""
    art = bf.render_text(APP_BANNER, fill="#")
    lines = art.splitlines()
    print()
    print(art)
    captured = capsys.readouterr()
    assert "#####" in captured.out, "art dumped to the test console for review"

    assert len(lines) == bf.GLYPH_H
    assert all(len(line) == EXPECTED_COLS for line in lines), "each row spans 65 cols"
    assert EXPECTED_COLS == 65
    # two-tone split: left half is exactly the 'THE80' span
    assert bf.left_cols(BANNER_LEFT) == len(BANNER_LEFT) * (bf.GLYPH_W + bf.GLYPH_GAP)


def test_8_and_0_visually_distinct():
    """8 = two closed loops + middle bar; 0 = slashed oval, no middle bar."""
    eight = bf.GLYPHS["8"]
    zero = bf.GLYPHS["0"]
    # closed side walls on the loop body rows (8's row 3 is its middle bar)
    for row in (eight[1], eight[2], eight[4], eight[5], zero[3]):
        assert row[0] == "#" and row[-1] == "#", "loops closed left/right"
    # zero's own loop rows are closed too (1, 2, 4, 5 — row 3 checked above)
    for row in (zero[1], zero[2], zero[4], zero[5]):
        assert row[0] == "#" and row[-1] == "#", "0 loops closed"
    # 8's middle bar is a full interior run; 0 never has one
    assert eight[3].strip() == "###", "8 middle bar"
    assert zero[3].strip() != "###", "0 has no middle bar"
    # 0 carries the interior slash (lit cells strictly inside the walls)
    assert zero[2][3] == "#" and zero[3][2] == "#" and zero[4][1] == "#", (
        "0 slash inside the oval"
    )
    assert eight[2][3] == " " and eight[4][1] == " ", "8 has no slash"
    assert zero[0].strip() == "###" and zero[6].strip() == "###", "0 closed oval top/bottom"


def test_hyphen_and_space_blanks():
    hyphen = bf.glyph_bitmap("-")
    blank = bf.glyph_bitmap(" ")
    assert not any(any(row) for row in blank), "space is empty"
    lit_rows = [i for i, row in enumerate(hyphen) if any(row)]
    assert lit_rows == [3], "hyphen is a single middle bar"


def test_unknown_char_rejected():
    with pytest.raises(KeyError):
        bf.glyph_bitmap("%")


# ------------------------------------------------------------------- asset
def test_asset_matches_bitmap_font():
    assert ASSET.is_file(), "assets/banner.txt must exist"
    assert "\n".join(_asset_lines()) == bf.render_text(APP_BANNER, fill="█"), (
        "banner asset drifted from banner_font.py — run tools/gen_banner.py"
    )


def test_asset_recorded_split_matches_font():
    art, split = load_banner_art()
    assert art == bf.render_text(APP_BANNER, fill="█")
    assert split == bf.left_cols(BANNER_LEFT), "split column must match the font"


def test_load_banner_art_fallback_without_asset(monkeypatch):
    import eightypwner.constants as c

    monkeypatch.setattr(
        c.resources, "files", lambda *_a, **_k: (_ for _ in ()).throw(OSError("gone"))
    )
    art, split = c.load_banner_art()
    assert art == bf.render_text(APP_BANNER, fill="#"), "fallback uses bitmap font"
    assert split == bf.left_cols(BANNER_LEFT)


# --------------------------------------------------------------------- CLI
def test_version_banner_embeds_art():
    assert "=" not in VERSION_BANNER
    assert "█████" in VERSION_BANNER, "CLI art uses the display font"
    assert APP_BANNER in VERSION_BANNER
    assert "Anas Mahfouz (The80)" in VERSION_BANNER


def test_terminal_banner_ascii_fallback(monkeypatch):
    class _AsciiStdout:
        encoding = "ascii"

    monkeypatch.setattr(sys, "stdout", _AsciiStdout())
    safe = terminal_banner(VERSION_BANNER)
    assert "█" not in safe and "#" in safe, "█ mapped to # for ascii stdout"
    assert "—" not in safe and "- An Integrated" in safe, "em-dash also degraded"

    class _Utf8Stdout:
        encoding = "utf-8"

    monkeypatch.setattr(sys, "stdout", _Utf8Stdout())
    assert terminal_banner(VERSION_BANNER) is VERSION_BANNER, "utf-8 keeps the art"


def test_cli_version_output_matches_asset():
    """`--version`'s art line shape = asset rows (same renderer)."""
    art_lines = _asset_lines()
    version_lines = VERSION_BANNER.splitlines()
    assert version_lines[: len(art_lines)] == art_lines


# -------------------------------------------------------------- Qt rendering
DOCS = Path(__file__).resolve().parents[1] / "docs"
TEST_WIDTHS = (240, 760, 1400)  # narrow / normal / wide


def _ink_shades(tokens: dict[str, str]) -> set[str]:
    """The two banner shades (accent / accent_pressed), lowercased."""
    return {
        tokens["accent"].lower(),
        tokens.get("accent_pressed", tokens["accent"]).lower(),
    }


def _ink_pixels(image, shades: set[str]) -> list[tuple[int, int]]:
    """(x, y) of pixels painted in a banner accent shade."""
    from PySide6.QtGui import QColor

    hits = []
    for y in range(image.height()):
        for x in range(image.width()):
            if QColor(image.pixel(x, y)).name().lower() in shades:
                hits.append((x, y))
    return hits


def _border_palette(image) -> set[str]:
    """Colors of the image's 1px edge ring."""
    from PySide6.QtGui import QColor

    w, h = image.width(), image.height()
    names: set[str] = set()
    for x in range(w):
        names.add(QColor(image.pixel(x, 0)).name().lower())
        names.add(QColor(image.pixel(x, h - 1)).name().lower())
    for y in range(h):
        names.add(QColor(image.pixel(0, y)).name().lower())
        names.add(QColor(image.pixel(w - 1, y)).name().lower())
    return names


def _pixel_palette(image) -> set[str]:
    from PySide6.QtGui import QColor

    return {
        QColor(image.pixel(x, y)).name().lower()
        for y in range(image.height())
        for x in range(image.width())
    }


def test_widget_renders_not_clipped_all_widths(qtbot, capsys):
    """Offscreen render at 3 widths x both themes: the art's ink never leaves
    the art box (nothing clipped), both tones painted, ASCII dump for review."""
    from eightypwner.ui.banner import BannerWidget
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    print()
    print(bf.dump_text(APP_BANNER))
    captured = capsys.readouterr()
    assert "#####" in captured.out, "banner glyph grid dumped for review"

    for mode, tokens in (("dark", DARK_TOKENS), ("light", LIGHT_TOKENS)):
        shades = _ink_shades(tokens)
        widget = BannerWidget(tokens)
        qtbot.addWidget(widget)
        for width in TEST_WIDTHS:
            widget.resize(width, widget.heightForWidth(width))
            widget.show()
            image = widget.grab().toImage()

            x0, y0, art_w, art_h = widget.art_geometry()
            assert x0 >= -0.51 and y0 >= -0.51, f"{mode}@{width}: art centered"
            assert art_h <= widget.height() + 0.01, (
                f"{mode}@{width}: art {art_h:.0f}px inside widget {widget.height()}px"
            )

            inks = _ink_pixels(image, shades)
            assert inks, f"{mode}@{width}: banner painted accent ink"
            for x, y in inks:
                assert x0 - 1.5 <= x <= x0 + art_w + 0.5, (
                    f"{mode}@{width}: ink column {x} escapes the art box"
                )
                assert y0 - 1.5 <= y <= y0 + art_h + 0.5, (
                    f"{mode}@{width}: ink row {y} escapes the art box"
                )
            names = {
                __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(
                    image.pixel(x, y)
                ).name().lower()
                for x, y in inks
            }
            assert len(names & shades) == 2, f"{mode}@{width}: two-tone ink present"


def test_widget_aspect_ratio_preserved(qtbot):
    """Art box keeps the 65:7 grid aspect at every width (uniform scale)."""
    from eightypwner.ui.banner import BannerWidget, grid_cols, grid_rows
    from eightypwner.ui.theme import DARK_TOKENS

    widget = BannerWidget(DARK_TOKENS)
    qtbot.addWidget(widget)
    expected = grid_cols() / grid_rows()
    for width in TEST_WIDTHS:
        widget.resize(width, widget.heightForWidth(width))
        widget.show()
        _x0, _y0, art_w, art_h = widget.art_geometry()
        assert art_w / art_h == pytest.approx(expected, rel=0.02), (
            f"@{width}: aspect {art_w:.0f}/{art_h:.0f} vs {expected:.2f}"
        )
        # integer cell sizing whenever it fits: cell = floor(width / cols)
        cell = int(width / grid_cols())
        if cell >= 1:
            assert art_w == cell * grid_cols(), f"@{width}: integer cell used"
            assert art_h == cell * grid_rows()


def test_widget_minimum_height_never_below_grid(qtbot):
    from eightypwner.ui.banner import MIN_CELL, BannerWidget
    from eightypwner.ui.theme import DARK_TOKENS

    widget = BannerWidget(DARK_TOKENS)
    qtbot.addWidget(widget)
    assert widget.minimumSizeHint().height() == MIN_CELL * 7 == 21
    for width in (80, 120, 240, 760, 1400):
        widget.resize(width, 10)  # preposterously short request
        assert widget.minimumHeight() >= 21, (
            f"@{width}: banner never shrinks below the 7-row grid"
        )


def test_widget_repaints_on_theme_change(qtbot):
    from eightypwner.ui.banner import BannerWidget
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    widget = BannerWidget(DARK_TOKENS)
    qtbot.addWidget(widget)
    widget.resize(600, widget.heightForWidth(600))
    widget.show()
    before = widget.grab().toImage()
    widget.set_tokens(LIGHT_TOKENS)
    after = widget.grab().toImage()

    diff = sum(
        1
        for y in range(0, before.height(), 2)
        for x in range(0, before.width(), 2)
        if before.pixelColor(x, y) != after.pixelColor(x, y)
    )
    assert diff > 0, "theme change visibly recolors the banner"


def test_pixmap_renders_no_edge_touch_all_widths():
    """Rasterized banner (splash/About/thumb): ink stays off the 1px border
    ring in both themes at narrow/normal/wide sizes; both tones present."""
    from eightypwner.ui.banner import ascii_banner_pixmap
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    for mode, tokens in (("dark", DARK_TOKENS), ("light", LIGHT_TOKENS)):
        shades = _ink_shades(tokens)
        for width in TEST_WIDTHS:
            image = ascii_banner_pixmap(width, tokens).toImage()
            assert not (_border_palette(image) & shades), (
                f"{mode}@{width}: banner ink touches the pixmap edge"
            )
            assert shades & _pixel_palette(image), (
                f"{mode}@{width}: banner painted both shades"
            )


def test_pixmap_screenshots_saved_to_docs():
    from eightypwner.ui.banner import ascii_banner_pixmap
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    DOCS.mkdir(exist_ok=True)
    dark = ascii_banner_pixmap(1200, DARK_TOKENS)
    light = ascii_banner_pixmap(1200, LIGHT_TOKENS)
    assert dark.save(str(DOCS / "banner-dark.png"))
    assert light.save(str(DOCS / "banner-light.png"))
    assert (DOCS / "banner-dark.png").exists() and (DOCS / "banner-light.png").exists()
    assert dark.save(str(DOCS / "banner.png"))


# ------------------------------------------------------------------- theme
def _relative_lum(hex_color: str) -> float:
    """WCAG luminance of a #RRGGBB color."""
    value = hex_color.lstrip("#")
    rgb = [int(value[i : i + 2], 16) / 255.0 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def test_theme_tokens_two_tone_colors_differ():
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    for tokens in (DARK_TOKENS, LIGHT_TOKENS):
        assert tokens["accent"] != tokens["accent_pressed"]
        assert _relative_lum(tokens["accent"]) > 0


def test_contrast_of_banner_shades_on_both_backgrounds():
    from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

    def ratio(a: str, b: str) -> float:
        la, lb = _relative_lum(a), _relative_lum(b)
        lighter, darker = max(la, lb), min(la, lb)
        return (lighter + 0.05) / (darker + 0.05)

    # banner text art: WCAG >= 3:1 against the panel background in both themes
    for tokens in (DARK_TOKENS, LIGHT_TOKENS):
        assert ratio(tokens["accent"], tokens["bg"]) >= 3.0, "left shade contrast"
        assert ratio(tokens["accent_pressed"], tokens["bg"]) >= 3.0, "right shade contrast"
        assert ratio(tokens["accent"], tokens["accent_pressed"]) >= 1.1, (
            "two shades visually distinct from each other"
        )

