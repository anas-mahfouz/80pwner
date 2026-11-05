# 80PWNER — by Anas Mahfouz (The80)

"""Vector brand banner — "THE80-PWNER".

Rendered as real vector text (QPainterPath.addText) so every glyph is crisp at
any size / DPI — no pixel-art fonts. Colors come from theme tokens: "THE80"
uses the accent, "-PWNER" the accent_hover shade, giving a designed two-tone
look in both dark and light themes.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import QWidget

from eightypwner.constants import BANNER_LEFT, BANNER_RIGHT
from eightypwner.ui.fonts import resolve_monospace

log = logging.getLogger(__name__)

_UNIT_SIZE = 100  # font pixel size used for the unit-geometry path


def _banner_font(family: str = "") -> QFont:
    font = QFont(family or resolve_monospace())
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setWeight(QFont.Weight.Black)
    font.setPixelSize(_UNIT_SIZE)
    return font


def _two_tone_paths(font: QFont) -> tuple[QPainterPath, QPainterPath]:
    """Vector outlines for (THE80, -PWNER), laid out back to back at origin."""
    left_path = QPainterPath()
    left_path.addText(QPointF(0, 0), font, BANNER_LEFT)
    advance = QPainterPath()
    advance.addText(QPointF(0, 0), font, BANNER_LEFT + " ")
    left_width = advance.boundingRect().width()
    right_path = QPainterPath()
    right_path.addText(QPointF(left_width, 0), font, BANNER_RIGHT)
    return left_path, right_path


def render_banner_path(tokens: dict[str, str]) -> QPainterPath:
    """Unit-geometry two-tone path (100px font) — exposes the vector outlines."""
    left_path, right_path = _two_tone_paths(_banner_font())
    return left_path.united(right_path)


def paint_banner(
    painter: QPainter,
    rect: QRectF,
    tokens: dict[str, str],
    font_family: str = "",
) -> None:
    """Fill *rect*, centered, with the two-tone vector banner."""
    font = _banner_font(font_family)
    left_path, right_path = _two_tone_paths(font)
    bounds = left_path.united(right_path).boundingRect()
    if bounds.width() <= 0 or bounds.height() <= 0:
        return

    scale = min(rect.width() / bounds.width(), rect.height() / bounds.height()) * 0.92

    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    center = rect.center() - QPointF(
        bounds.width() * scale / 2, bounds.height() * scale * 0.40
    )
    painter.translate(center)
    painter.scale(scale, scale)
    painter.fillPath(left_path, QColor(tokens["accent"]))         # THE80
    painter.fillPath(right_path, QColor(tokens["accent_hover"]))  # -PWNER
    painter.restore()


def banner_pixmap(width: int, tokens: dict[str, str]) -> QPixmap:
    """Rasterize the vector banner for the splash/About dialog (2x for HiDPI)."""
    font = _banner_font()
    left_path, right_path = _two_tone_paths(font)
    bounds = left_path.united(right_path).boundingRect()
    aspect = bounds.width() / max(bounds.height(), 1.0)
    height = max(int(width / aspect) + 12, 40)

    ratio = 2.0
    pixmap = QPixmap(int(width * ratio), int(height * ratio))
    pixmap.fill(QColor(tokens["bg"]))
    painter = QPainter(pixmap)
    try:
        paint_banner(
            painter,
            QRectF(0, 0, width * ratio, height * ratio),
            tokens,
        )
    finally:
        painter.end()
    return pixmap.scaled(width, height, Qt.AspectRatioMode.KeepAspectRatio)


class BannerWidget(QWidget):
    """Welcome-screen banner; repaints as vectors whenever tokens change."""

    def __init__(self, tokens: dict[str, str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tokens = tokens
        self.setMinimumHeight(90)

    def set_tokens(self, tokens: dict[str, str]) -> None:
        self._tokens = tokens
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802 (Qt override)
        painter = QPainter(self)
        try:
            paint_banner(painter, QRectF(self.rect()), self._tokens)
        except Exception:
            log.exception("Banner paint failed")
        finally:
            painter.end()
