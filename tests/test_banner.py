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
