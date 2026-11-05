# 80PWNER — by Anas Mahfouz (The80)

"""Brand banner widget — "THE80-PWNER" rendered as filled rectangles.

The art comes straight from the bitmap block font
(:mod:`eightypwner.ui.banner_font`): one lit cell → one filled rect with a
small gap between cells. QPainter owns the geometry, so sizing is exact —
aspect-etraying uniform scale from the available width, integer cell sizes
whenever they fit, and size hints derived from the grid so the widget is
never clipped vertically. The two halves (THE80 / -PWNER) use two accent
shades from the theme tokens; theme changes simply repaint.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter, QPixmap
from PySide6.QtWidgets import QSizePolicy, QWidget

from eightypwner.constants import APP_BANNER, load_banner_art
from eightypwner.ui import banner_font as bf

log = logging.getLogger(__name__)

# below this cell size the uniform scale becomes fractional (fit beats integer)
MIN_CELL = 3
# gap between neighbouring lit cells as a fraction of the cell (0 = touching)
CELL_GAP_FRACTION = 0.18


def _gap_for(cell: float) -> float:
    """Lit-cell gap in device px for *cell* (scaled down at tiny sizes)."""
    if cell < 4:
        return 0.0
    return max(1.0, cell * CELL_GAP_FRACTION)


def paint_banner_grid(
    painter: QPainter,
    rect: Any,  # QRectF
    tokens: dict[str, str],
    grid: tuple[tuple[tuple[bool, ...], ...], int],
    split: int,
) -> None:
    """Paint the banner grid inside *rect*: two-tone, uniform scale, centered.
    """
    rows, cols = grid
    if not rows or cols <= 0:
        return
    grid_h = len(rows)
    if rect.width() <= 0 or rect.height() <= 0:
        return

    # uniform scale: the tightest of width-fit / height-fit, never below 1
    cell = min(rect.width() / cols, rect.height() / grid_h)
    scale_to_fit_width = rect.width() / cols
    if scale_to_fit_width >= 1:
        cell = min(float(int(scale_to_fit_width)), rect.height() / grid_h)
        cell = max(cell, 1.0)
    if cell <= 0:  # pragma: no cover — guarded above
        return

    art_w = cols * cell
    art_h = grid_h * cell
    x0 = rect.left() + max((rect.width() - art_w) / 2.0, 0.0)
    y0 = rect.top() + max((rect.height() - art_h) / 2.0, 0.0)
    split_x = x0 + split * cell  # right half begins at this x

    # two-tone: THE80 = accent (brighter), -PWNER = accent_pressed (deeper)
    left_color = QColor(tokens["accent"])
    right_color = QColor(tokens.get("accent_pressed") or tokens["accent"])

    gap = _gap_for(cell)
    lit = cell - gap
    if lit <= 0:  # pragma: no cover — cell ≥ 1 keeps this unreachable
        lit = cell

    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
    painter.setPen(Qt.PenStyle.NoPen)
    for row_idx, row in enumerate(rows):
        y = y0 + row_idx * cell  # top-anchored rows (grid already tight)
        for col_idx, lit_cell in enumerate(row):
            if not lit_cell:
                continue
            x = x0 + col_idx * cell
            painter.setBrush(left_color if x < split_x else right_color)
            painter.drawRect(x, y, lit, lit)
    painter.restore()


class BannerWidget(QWidget):
    """The welcome-screen banner: bitmap letters, zero font dependencies.

    Geometry guarantees (by construction — every dimension derives from the
    grid): ``minimumSizeHint`` holds the art at :data:`MIN_CELL` per cell and
    ``heightForWidth`` returns the exact uniform-scale height, so no layout
    can vertically clip the seven grid rows.
    """

    def __init__(self, tokens: dict[str, str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tokens = tokens
        self._grid, self._cols = bf.banner_grid(APP_BANNER)
        self._split = load_banner_art()[1]
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(self.minimum_grid_height())

    # ------------------------------------------------------------- geometry
    def minimum_grid_height(self) -> int:
        return grid_rows() * MIN_CELL

    def minimumSizeHint(self) -> QSize:  # noqa: N802 (Qt override)
        return QSize(grid_cols() * MIN_CELL, self.minimum_grid_height())

    def sizeHint(self) -> QSize:  # noqa: N802 (Qt override)
        cell = 9  # comfortable default the layout can shrink freely
        return QSize(grid_cols() * cell, grid_rows() * cell)

    def current_cell(self) -> float:
        """The cell size used for painting at the widget's current width."""
        return cell_for_width(self.width(), self.height())

    def resizeEvent(self, event: Any) -> None:  # noqa: N802 (Qt override)
        # Guard the height: layouts may hand us less room than the uniform
        # scale needs, so raise the minimum to the exact width-fit art height
        # (the old-clip bug: widget height shorter than the art). The paint
        # itself down-scales gracefully if the extra height is still missing
        # for a frame — never clipped, at worst temporarily smaller.
        desired = art_cell(self.width())
        needed = round(grid_rows() * desired)
        self.setMinimumHeight(max(self.minimum_grid_height(), needed))
        super().resizeEvent(event)
        self.update()

    def heightForWidth(self, width: int) -> int:  # noqa: N802 (Qt override)
        """Exact art height for *width* (uniform scale, aspect preserved)."""
        cell = art_cell(width)
        return max(round(grid_rows() * cell), self.minimum_grid_height())

    # ---------------------------------------------------------------- paint
    def set_tokens(self, tokens: dict[str, str]) -> None:
        """Theme change hook — repaint in the new accent shades."""
        self._tokens = tokens
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802 (Qt override)
        painter = QPainter(self)
        try:
            paint_banner_grid(
                painter,
                QRectF(self.rect()),
                self._tokens,
                (self._grid, self._cols),
                self._split,
            )
        except Exception:
            log.exception("Banner paint failed")
        finally:
            painter.end()

    def art_geometry(self) -> tuple[float, float, float, float]:
        """(x0, y0, art_w, art_h) of the centered art in the current widget.

        Computes the cell on demand (never from cached state): a resize that
        happens before the widget is shown may not be delivered as an event
        yet, but the geometry math is pure — width/height in, rect out.
        """
        w, h = self.width(), self.height()
        cell = cell_for_width(w, h)
        art_w = grid_cols() * cell
        art_h = grid_rows() * cell
        x0 = max((w - art_w) / 2.0, 0.0)
        y0 = max((h - art_h) / 2.0, 0.0)
        return x0, y0, art_w, art_h


def art_cell(width: int) -> float:
    """Cell size for a banner fitted into *width* px.

    Integer cells whenever ≤ MIN_CELL-wide pixels exist to spare; fractional
    (still uniform, never stretched) when the space is too narrow.
    """
    cols = grid_cols()
    if cols <= 0:  # pragma: no cover — static grid
        return float(MIN_CELL)
    scale = width / cols
    if scale >= 1:
        return max(float(int(scale)), 1.0)
    return max(scale, 1.0 / cols)  # too narrow: fit exactly, aspect intact


def cell_for_width(width: int, height: int) -> float:
    """Cell size honoring both width and height (the widget may be taller)."""
    rows = grid_rows()
    available_rows = max(height // rows, 1)
    fit_w = art_cell(width)
    cell = fit_w
    if cell > available_rows:  # height-constrained (rare: wide art, tall box)
        cell = float(available_rows)
    return max(cell, 1.0)


def grid_cols() -> int:
    """Banner grid width in cells (65 for THE80-PWNER)."""
    return bf.glyph_cols(len(APP_BANNER))


def grid_rows() -> int:
    """Banner grid height in cells (7)."""
    return bf.GLYPH_H


def ascii_banner_pixmap(width: int, tokens: dict[str, str]) -> QPixmap:
    """Rasterize the banner fitted to *width* (splash, About, screenshots).

    Carries a background margin ≥ half a cell so the art never touches the
    pixmap edges (verifiable no-clip guarantee for tests/thumbnails).
    """
    grid = bf.banner_grid(APP_BANNER)
    split = load_banner_art()[1]
    cell = max(art_cell(width), 2.0)  # pixmap render keeps ≥ 2px cells
    art_w = int(grid_cols() * cell)
    art_h = int(grid_rows() * cell)
    pad = max(2.0, round(cell / 2))
    pixmap = QPixmap(round(art_w + 2 * pad), round(art_h + 2 * pad))
    pixmap.fill(QColor(tokens["bg"]))
    painter = QPainter(pixmap)
    try:
        paint_banner_grid(
            painter, QRectF(pad, pad, art_w, art_h), tokens, grid, split
        )
    finally:
        painter.end()
    return pixmap


# back-compat name used by older imports/tests
AsciiBannerWidget = BannerWidget
