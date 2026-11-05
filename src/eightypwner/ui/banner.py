# 80PWNER — by Anas Mahfouz (The80)

"""ASCII-art brand banner — "THE80-PWNER" (FIGlet ansi_shadow asset).

The art is a static asset loaded by :mod:`eightypwner.constants`; this module
renders it with the bundled JetBrains Mono at a size auto-scaled to the
available width (never stretched — the monospace cell aspect is preserved),
with horizontal scrolling as the fallback for very narrow windows. The two
halves (THE80 / -PWNER) use two accent shades from the theme tokens.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QFontMetricsF, QPainter, QPixmap
from PySide6.QtWidgets import QSizePolicy, QWidget

from eightypwner.constants import load_banner_art
from eightypwner.ui.fonts import resolve_monospace

log = logging.getLogger(__name__)

# smallest readable pixel size before switching to horizontal scroll
MIN_PX = 5


def _banner_font(px: int) -> QFont:
    font = QFont(resolve_monospace())
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPixelSize(max(int(px), 1))
    return font


def banner_cell(font: QFont) -> tuple[float, float]:
    """Monospace cell width / row height for *font* (keeps the cell aspect)."""
    metrics = QFontMetricsF(font)
    return metrics.horizontalAdvance("█"), metrics.height()


def fit_px(width: int, cols: int) -> int:
    """Largest font px whose full column span fits *width* (floor: MIN_PX)."""
    if cols <= 0:
        return MIN_PX
    px = max(int(width / cols), MIN_PX)
    font = _banner_font(px)
    cell_w, _ = banner_cell(font)
    while px > MIN_PX and cell_w * cols > width:
        px -= 1
        font = _banner_font(px)
        cell_w, _ = banner_cell(font)
    return px


def _paint_ascii_banner(
    painter: QPainter,
    rect: QRectF,
    tokens: dict[str, str],
    lines: list[str],
    split: int,
    px: int,
) -> None:
    """Draw the art inside *rect* at *px*, two-tone, centered horizontally."""
    if not lines or px <= 0:
        return
    font = _banner_font(px)
    cell_w, row_h = banner_cell(font)
    cols = max(len(line) for line in lines)
    art_w = cell_w * cols
    art_h = row_h * len(lines)

    x0 = rect.left() + max((rect.width() - art_w) / 2.0, 0.0)
    y0 = rect.top() + max((rect.height() - art_h) / 2.0, 0.0)

    # two-tone: THE80 = accent (brighter), -PWNER = accent_pressed (deeper)
    right_color = QColor(tokens.get("accent_pressed") or tokens["accent"])
    left_color = QColor(tokens["accent"])
    split_x = x0 + cell_w * max(split, 1)

    painter.setFont(font)

    def draw(color: QColor, clip: QRectF | None = None) -> None:
        if clip is not None:
            painter.save()
            painter.setClipRect(clip)
        painter.setPen(color)
        for row, line in enumerate(lines):
            painter.drawText(
                QRectF(x0, y0 + row * row_h, art_w + cell_w, row_h),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                line,
            )
        if clip is not None:
            painter.restore()

    # paint everything in the deeper shade, then re-paint the left region in
    # the brighter shade — crisp two-tone without pixel-level chopping.
    draw(right_color)
    draw(left_color, clip=QRectF(0, 0, split_x, rect.height()))


class AsciiBannerWidget(QWidget):
    """Auto-fitting two-tone ASCII banner (used on the Welcome screen)."""

    def __init__(self, tokens: dict[str, str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tokens = tokens
        self._art, self._split = load_banner_art()
        self._lines = self._art.splitlines()
        self._rows = len(self._lines)
        self._cols = max(len(line) for line in self._lines)
        self._px = MIN_PX
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(1)

    def set_tokens(self, tokens: dict[str, str]) -> None:
        self._tokens = tokens
        self.update()

    # ------------------------------------------------------------- geometry
    def _current_px(self) -> int:
        """Fit-to-width font size, recomputed on demand (cheap font metrics)."""
        return self.fit_px(max(self.width(), self.render_target()))

    def natural_size(self, px: int) -> QSize:
        """Pixel size the art needs at font size *px* (cell aspect preserved)."""
        cell_w, row_h = banner_cell(_banner_font(px))
        return QSize(round(self._cols * cell_w), round(self._rows * row_h))

    def fit_px(self, width: int) -> int:
        return fit_px(width, self._cols)

    def resizeEvent(self, event: Any) -> None:  # noqa: N802 (Qt override)
        self._px = self._current_px()
        self.setMinimumHeight(self.natural_size(self._px).height())
        super().resizeEvent(event)
        self.update()

    def heightForWidth(self, width: int) -> int:  # noqa: N802 (Qt override)
        return self.natural_size(self.fit_px(width)).height()

    def render_target(self) -> int:
        """Minimum width the art must have (drives the scroll fallback)."""
        return self.natural_size(MIN_PX).width()

    # ---------------------------------------------------------------- paint
    def paintEvent(self, event: Any) -> None:  # noqa: N802 (Qt override)
        painter = QPainter(self)
        try:
            px = self._current_px()
            self._px = px
            _paint_ascii_banner(
                painter, QRectF(self.rect()), self._tokens, self._lines,
                self._split, px,
            )
        except Exception:
            log.exception("Banner paint failed")
        finally:
            painter.end()


def ascii_banner_pixmap(width: int, tokens: dict[str, str]) -> QPixmap:
    """Rasterize the ASCII banner fitted to *width* (for splash/About)."""
    art, split = load_banner_art()
    lines = art.splitlines()
    cols = max(len(line) for line in lines)
    rows = len(lines)
    px = fit_px(width, cols)
    cell_w, row_h = banner_cell(_banner_font(px))
    art_w = round(cell_w * cols)
    art_h = round(row_h * rows)
    height = max(art_h + 8, 24)

    pixmap = QPixmap(art_w, height)
    pixmap.fill(QColor(tokens["bg"]))
    painter = QPainter(pixmap)
    try:
        _paint_ascii_banner(painter, QRectF(pixmap.rect()), tokens, lines, split, px)
    finally:
        painter.end()
    return pixmap


def ascii_banner_size(width: int) -> QSize:
    """Natural pixmap size the widget/scrollbar logic can use."""
    art, _ = load_banner_art()
    lines = art.splitlines()
    cols = max(len(line) for line in lines)
    cell_w, row_h = banner_cell(_banner_font(fit_px(width, cols)))
    return QSize(
        round(cell_w * cols), round(row_h * len(lines))
    )
