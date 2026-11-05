# 80PWNER — by Anas Mahfouz (The80)

"""Dock title-bar tests: text never clips at the bottom of its title bar.

Renders the real MainWindow (all builtin plugins) offscreen and, for every
dock, pixel-scans the rendered title bar: the accent border row marks the
title bar bottom, and the title's foreground-colored ink must stay inside
the title band with a visible margin — i.e. no glyph may touch or cross the
border (the "Disassembler / Welcome cut off" bug). Verified with both the
standard UI font and the bundled JetBrains Mono at font sizes approximating
100% / 150% / 200% UI scaling, in the dark theme (the QSS block is shared,
and the light theme's QSS block is asserted textually to stay in contract).

Font pt sizes are the deterministic proxy for DPI scaling on the offscreen
platform: px sizes grow ~proportionally, and the QSS padding is identical.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics
from PySide6.QtWidgets import QApplication

MONO_FAMILY = "JetBrains Mono"
HORIZONTAL_PADDING_PX = 10  # from QDockWidget::title QSS

# (label, point size, family) — None family = platform default UI font
FONT_CASES = [
    ("100%", 9, None),
    ("150%", 13, None),
    ("200%", 18, None),
    ("200% mono", 18, MONO_FAMILY),
]

# QSS contract: vertical padding and border must keep room for tall glyphs
MIN_QSS_VERTICAL_PADDING = 6  # px — 5px was the clipping value before the fix
DOCKS_QSS = {
    "dark": Path(__file__).resolve().parents[1]
    / "src/eightypwner/assets/themes/dark.qss",
    "light": Path(__file__).resolve().parents[1]
    / "src/eightypwner/assets/themes/light.qss",
}


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    """Real MainWindow with every builtin plugin (mirrors test_main_window)."""
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    from eightypwner.core.event_bus import EventBus
    from eightypwner.core.session import SessionState
    from eightypwner.core.settings import Settings
    from eightypwner.modules.interface import PluginContext
    from eightypwner.modules.registry import PluginRegistry
    from eightypwner.ui.theme import ThemeManager

    settings, bus = Settings(), EventBus()
    theme = ThemeManager(settings)
    ctx = PluginContext(bus=bus, settings=settings, app_version="test")
    registry = PluginRegistry(ctx)
    registry.load_builtins()

    from eightypwner.ui.main_window import MainWindow

    window = MainWindow(bus, theme, registry, SessionState(), settings)
    yield window, theme
    window.close()


# ------------------------------------------------------------------ helpers
def _near(color: str, target: str, tol: int) -> bool:
    a, b = QColor(color), QColor(target)
    return (
        abs(a.red() - b.red()) <= tol
        and abs(a.green() - b.green()) <= tol
        and abs(a.blue() - b.blue()) <= tol
    )


def _title_border_y(img, accent_dim: str) -> int:
    """Y of the title bar's bottom border (first mostly-accent-dim row)."""
    width = img.width()
    step = max(width // 8, 1)
    for y in range(img.height() // 3):
        hits = sum(
            1
            for x in range(0, width, step)
            if _near(QColor(img.pixel(x, y)).name(), accent_dim, 40)
        )
        if hits > (width // step) * 0.6:
            return y
    return -1


def _ink_rows(img, fg: str, bottom_inclusive: int):
    """(min_y, max_y) of foreground-colored text rows, or None."""
    width = img.width()
    step = max(width // 400, 1)  # dense scan: glyph stems are 1-2px wide
    rows = [
        y
        for y in range(min(bottom_inclusive, img.height()))
        if sum(
            1
            for x in range(0, width, step)
            if _near(QColor(img.pixel(x, y)).name(), fg, 30)
        )
        >= 2
    ]
    return (min(rows), max(rows)) if rows else None


def _ink_xs(img, fg: str, rows: range) -> list[int]:
    """X positions of foreground ink in the given rows."""
    return [
        x
        for y in rows
        for x in range(img.width())
        if _near(QColor(img.pixel(x, y)).name(), fg, 30)
    ]


def _apply_font(window, point_size: int, family: str | None) -> QFontMetrics:
    """Apply a scaled font to every dock (widget-level: an app-wide setFont
    is ignored for these widgets while the stylesheet is active, and Qt's
    font-propagation quirks differ per platform — explicit per-dock fonts
    make the scaled render deterministic)."""
    font = QFont(family or "Sans Serif")
    font.setPointSize(point_size)
    for dock in window._dock_by_name.values():
        dock.setFont(font)
    window.show()  # re-layout at the new font
    QApplication.instance().processEvents()
    return QFontMetrics(font)


def _mode_of(theme) -> str:
    mode = theme.mode
    return mode if mode in ("dark", "light") else "dark"


def _tokens_of(theme) -> dict[str, str]:
    from eightypwner.ui.theme import render_theme

    return render_theme(_mode_of(theme)).tokens


# ----------------------------------------------------------------- the QSS
def test_qss_pads_dock_titles_enough():
    """Both themes must keep the anti-clip padding (>= 6px vertical)."""
    for mode, qss_path in DOCKS_QSS.items():
        text = qss_path.read_text(encoding="utf-8")
        block = re.search(r"QDockWidget::title\s*\{(.*?)\n\}", text, re.S)
        assert block, f"{mode}.qss: QDockWidget::title block missing"
        padding = re.search(r"padding:\s*(\d+)px(?:\s+(\d+)px)?", block.group(1))
        assert padding, f"{mode}.qss: title padding missing"
        vertical = int(padding.group(1))
        horizontal = int(padding.group(2))
        assert vertical >= MIN_QSS_VERTICAL_PADDING, (
            f"{mode}.qss: vertical title padding {vertical}px < "
            f"{MIN_QSS_VERTICAL_PADDING}px (the clipping value)"
        )
        assert horizontal >= HORIZONTAL_PADDING_PX, (
            f"{mode}.qss: horizontal title padding too small"
        )
        assert "border-bottom" in block.group(1), f"{mode}.qss: title border gone"


# ------------------------------------------------------- rendered geometry
def test_dock_titles_never_clip(qtbot, app_ctx, capsys):
    """Rendered title bars: text ink inside the band with a visible margin.

    At every font case, no dock glyph may come within 2px of the accent
    border (bottom clipping) — the row dump doubles as a review aid.
    """
    window, theme = app_ctx
    window.resize(1200, 800)
    window.show()

    tokens = _tokens_of(theme)
    fg, accent_dim = tokens["fg"].lower(), tokens["accent_dim"].lower()

    assert len(window._dock_by_name) >= 4, "the window must have its docks"
    problems: list[str] = []
    for label, point_size, family in FONT_CASES:
        fm = _apply_font(window, point_size, family)
        print(f"-- {label}: font {family or 'UI'} fm.h={fm.height()}")
        for name, dock in window._dock_by_name.items():
            img = dock.grab().toImage()
            border_y = _title_border_y(img, accent_dim)
            if border_y < 0:
                problems.append(f"{label} {name}: title bar border not found")
                continue
            span = _ink_rows(img, fg, border_y)
            if span is None:
                problems.append(f"{label} {name}: no title text rendered")
                continue
            top, bottom = span
            title = dock.windowTitle()
            print(
                f"   {name!r} {title!r}: bar={border_y}px ink {top}..{bottom} "
                f"margin_bottom={border_y - 1 - bottom}"
            )
            if border_y - 1 - bottom < 2:
                problems.append(
                    f"{label} {name}: ink ends at row {bottom}, border at "
                    f"{border_y} — bottom margin {border_y - 1 - bottom}px (<2px, clips)"
                )
            if top > fm.height() + 4:
                problems.append(
                    f"{label} {name}: text starts at row {top} — vertically "
                    "mis-centered for its font height"
                )
            # width: the title must fit (elided) within its own title bar
            content_w = max(60, dock.width() - 2 * HORIZONTAL_PADDING_PX)
            elided = fm.elidedText(title, Qt.TextElideMode.ElideRight, content_w)
            assert fm.horizontalAdvance(elided) <= content_w, (
                f"{label} {name}: elided title still overflows the title bar"
            )

    assert not problems, "\n".join(problems)


def test_dock_titles_elide_when_narrow(qtbot, app_ctx):
    """A squeezed dock renders elided text — never overflowing its bar."""
    window, theme = app_ctx
    window.resize(640, 600)
    window.show()
    QApplication.instance().processEvents()

    tokens = _tokens_of(theme)
    fg, accent_dim = tokens["fg"].lower(), tokens["accent_dim"].lower()

    dock = window._dock_by_name["Disassembler"]
    dock.setFloating(False)
    dock.resize(160, 60)
    QApplication.instance().processEvents()
    img = dock.grab().toImage()

    border_y = _title_border_y(img, accent_dim)
    assert border_y > 0, "title bar border must be visible at small sizes"
    span = _ink_rows(img, fg, border_y)
    assert span is not None, "elided title text must still render"
    top, bottom = span
    xs = _ink_xs(img, fg, range(top, bottom + 1))
    assert xs, "no horizontal ink found in the title bar"
    assert max(xs) <= img.width() - 3, (
        "title text overflows the title bar's right edge (no eliding)"
    )
