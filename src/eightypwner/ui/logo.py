# 80PWNER — by Anas Mahfouz (The80)

"""App icon/logo, generated in code (spec §2): stylized "80" in a rounded dark
tile with a terminal caret — minimal hacker aesthetic, no skull."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap

from eightypwner.constants import ACCENT_DARK

_TILE_BG_TOP = "#001410"
_TILE_BG_BOTTOM = "#05070A"
_CARET_DIM = "#1E7A5C"


def app_logo_pixmap(size: int = 256) -> QPixmap:
    """Draw the 80PWNER logo as a square pixmap."""
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Rounded tile with a subtle top-lit gradient.
    inset = size * 0.06
    radius = size * 0.18
    grad = QLinearGradient(QPointF(0, inset), QPointF(0, size - inset))
    grad.setColorAt(0.0, _TILE_BG_TOP)
    grad.setColorAt(1.0, _TILE_BG_BOTTOM)
    p.setBrush(QBrush(grad))
    p.setPen(Qt.PenStyle.NoPen)
    path = QPainterPath()
    path.addRoundedRect(QRectF(inset, inset, size - 2 * inset, size - 2 * inset), radius, radius)
    p.drawPath(path)

    # Terminal caret ">" — dim, top-left.
    p.setPen(QPen(_CARET_DIM))
    caret_font = QFont("DejaVu Sans Mono")
    caret_font.setPixelSize(int(size * 0.22))
    caret_font.setBold(True)
    p.setFont(caret_font)
    p.drawText(
        QRectF(inset, inset, size - 2 * inset, size * 0.30),
        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
        ">",
    )

    # "80" — the brand mark, neon green.
    p.setPen(QPen(ACCENT_DARK))
    main_font = QFont("JetBrains Mono")
    main_font.setPixelSize(int(size * 0.42))
    main_font.setBold(True)
    p.setFont(main_font)
    p.drawText(QRectF(inset, size * 0.38, size - 2 * inset, size * 0.48), Qt.AlignmentFlag.AlignCenter, "80")

    # Blinking-cursor underscore, bottom-right.
    p.drawText(
        QRectF(inset, size * 0.80, size - 2 * inset, size * 0.12),
        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        "_",
    )
    p.end()
    return px
