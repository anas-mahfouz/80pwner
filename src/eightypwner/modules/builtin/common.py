# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Small shared helpers for builtin docks (Qt-side only)."""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterable
from typing import Any

from PySide6.QtCore import QObject, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from eightypwner.ui.fonts import resolve_monospace


class Relay(QObject):
    """Re-dispatch a worker payload onto the thread this object lives on."""

    route = Signal(object)


def copy_text(text: str) -> bool:
    """Best-effort clipboard write (headless tests have no clipboard)."""
    app = QApplication.instance()
    if app is None:
        return False
    with contextlib.suppress(Exception):
        app.clipboard().setText(text)
        return True
    return False


def parse_int(text: Any, default: int | None = None) -> int | None:
    """Accept ``0x…``, decimal, ``0b…`` and bare hex-ish strings."""
    if isinstance(text, int):
        return int(text)
    if not text:
        return default
    value = str(text).strip().replace("_", "").replace(",", "")
    if not value:
        return default
    try:
        return int(value, 0)
    except ValueError:
        pass
    try:
        return int(value, 16)
    except ValueError:
        return default


def mono_font(settings: Any = None, point_size: int | None = None) -> QFont:
    preferred = ""
    if settings is not None:
        with contextlib.suppress(Exception):
            preferred = str(settings.get("font.mono_family") or "")
    font = QFont(resolve_monospace(preferred))
    with contextlib.suppress(Exception):
        family = preferred or resolve_monospace("")
        if family:
            font.setFamily(family)
    if point_size:
        font.setPointSize(point_size)
    font.setStyleHint(QFont.StyleHint.Monospace)
    return font


def make_table(headers: Iterable[str], *, mono: bool = True, settings: Any = None) -> QTableWidget:
    headers = list(headers)
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    if mono:
        table.setFont(mono_font(settings))
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    header.setStretchLastSection(True)
    return table


def set_row(table: QTableWidget, row: int, values: Iterable[Any], addr: int | None = None) -> None:
    values = list(values)
    for column, value in enumerate(values):
        item = QTableWidgetItem(str(value))
        if addr is not None and column == 0:
            item.setData(0x0100, addr)  # Qt.ItemDataRole.UserRole
        table.setItem(row, column, item)


def elide(text: str, limit: int = 64) -> str:
    text = re.sub(r"\s+", " ", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def scroll_to_top(table: QWidget) -> None:
    with contextlib.suppress(Exception):
        table.scrollToTop()  # type: ignore[attr-defined]
