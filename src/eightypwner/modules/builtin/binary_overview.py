# 80PWNER — by Anas Mahfouz (The80)

"""Binary Overview module (spec §6.1): target metadata, checksec panel with
colored badges, sections/segments/symbols/imports/exports/strings tables, and
dangerous-function highlighting. Heavy parsing runs in a worker thread; all
widget updates arrive via the UiBus bridge on the UI thread."""

from __future__ import annotations

import contextlib
import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import (
    BINARY_CLOSED,
    BINARY_DROPPED,
    BINARY_LOAD_FAILED,
    BINARY_LOADED,
    OPEN_BINARY_REQUESTED,
)
from eightypwner.engines.binary_parser import ParseError, parse_binary
from eightypwner.modules.interface import Plugin
from eightypwner.ui.fonts import resolve_monospace

if TYPE_CHECKING:
    from eightypwner.engines.binary_parser import BinaryModel

log = logging.getLogger(__name__)

# checksec/badge status → QSS role (semantic colors; NOT the red accent:
# enabled = green, disabled = red-error, unknown = neutral)
_STATUS_ROLES = {
    "enabled": "badge-ok",
    "disabled": "badge-error",
    "unknown": "badge-na",
}
_SEVERITY_ROLES = {
    "critical": "badge-error",
    "high": "badge-warn",
    "medium": "badge-na",
}

INFO_FIELDS = [
    ("File", "name"),
    ("Format", "fmt"),
    ("Architecture", "arch"),
    ("Bits", "bits"),
    ("Endianness", "endianness"),
    ("Entry point", "entry"),
]


class BinaryOverviewPlugin(Plugin):
    name = "Binary Overview"  # wins the sort → dock built first
    description = "Loaded target: metadata, checksec, sections, symbols, strings."
    icon = "🧬"

    _model: BinaryModel | None

    # ---------------------------------------------------------------- widget
    def widget(self) -> QWidget:
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)

        # toolbar row
        bar = QHBoxLayout()
        open_btn = QPushButton("Open Binary…")
        open_btn.clicked.connect(self._open_dialog)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(lambda: self.ctx.bus.publish(BINARY_CLOSED))
        self._path_label = QLabel("No binary loaded")
        self._path_label.setEnabled(False)
        bar.addWidget(open_btn)
        bar.addWidget(close_btn)
        bar.addStretch(1)
        bar.addWidget(self._path_label)
        outer.addLayout(bar)

        self._tabs = QTabWidget(panel)
        outer.addWidget(self._tabs, 1)

        self._build_overview_tab()
        self._sections_table = self._make_table(["Name", "Size", "Virtual addr", "Type"])
        self._tabs.addTab(self._sections_table, "Sections")

        self._segments_table = self._make_table(["Type", "Virtual addr", "Size", "Flags"])
        self._tabs.addTab(self._segments_table, "Segments")

        self._symbols_table = self._make_table(["Name", "Size", "Address"])
        self._tabs.addTab(self._symbols_table, "Symbols")

        self._imports_table = self._make_table(["Imported function"])
        self._tabs.addTab(self._imports_table, "Imports")

        self._exports_table = self._make_table(["Exported symbol"])
        self._tabs.addTab(self._exports_table, "Exports")

        self._strings_table = self._make_table(["Offset", "String"])
        self._tabs.addTab(self._strings_table, "Strings")

        self._danger_table = self._make_table(["Function", "Origin", "Severity", "Risk"])
        self._tabs.addTab(self._danger_table, "Dangerous")

        self._status_label = QLabel("")
        outer.addWidget(self._status_label)
        self._model = None
        return panel

    def _build_overview_tab(self) -> None:
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)

        # target info grid
        grid = QGridLayout()
        self._info_values: dict[str, QLabel] = {}
        for row, (caption, key) in enumerate(INFO_FIELDS):
            caption_label = QLabel(f"{caption}:")
            value_label = QLabel("")
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._info_values[key] = value_label
            grid.addWidget(caption_label, row, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(value_label, row, 1, Qt.AlignmentFlag.AlignTop)
        grid.setColumnStretch(2, 1)
        tab_layout.addLayout(grid)

        # checksec badges
        checksec_caption = QLabel("<b>Security mitigations (checksec)</b>")
        tab_layout.addWidget(checksec_caption)
        self._checksec_grid = QGridLayout()
        checksec_note = QLabel(
            'green = enabled, red = disabled, grey = unknown — '
            'the accent color of the app is separate from these.'
        )
        checksec_note.setEnabled(False)
        tab_layout.addLayout(self._checksec_grid)
        tab_layout.addWidget(checksec_note)
        tab_layout.addStretch(1)
        self._tabs.addTab(tab, "Overview")

    def _make_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setFont(QFont(resolve_monospace(self.ctx.settings.get("font.mono_family") or "")))
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        return table

    # ------------------------------------------------------------- lifecycle
    def initialize(self, parent: Any = None) -> None:
        subscribe = (
            self.ctx.ui_bus.subscribe
            if self.ctx.ui_bus is not None
            else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_event)

    def shutdown(self) -> None:
        with contextlib.suppress(Exception):
            self._unsub()

    # --------------------------------------------------------------- actions
    def _open_dialog(self) -> None:
        start = str(self._model.path.parent) if self._model is not None else str(Path.home())
        chosen, _filter = QFileDialog.getOpenFileName(
            self._panel, "Open binary (ELF / PE / Mach-O)", start
        )
        if chosen:
            self.load_path(Path(chosen))

    def load_path(self, path: Path) -> None:
        """Spawn a worker thread; UI stays functional during parsing."""
        self._status_label.setText(f"Parsing {path.name}…")
        worker = threading.Thread(target=self._load, args=(path,), daemon=True)
        worker.start()

    def _load(self, path: Path) -> None:
        try:
            model = parse_binary(path)
        except ParseError as exc:
            self.ctx.bus.publish(BINARY_LOAD_FAILED, {"path": str(path), "error": str(exc)})
            return
        except Exception:
            log.exception("Unexpected parser failure on %s", path)
            self.ctx.bus.publish(
                BINARY_LOAD_FAILED,
                {"path": str(path), "error": f"Internal parser error on {path.name}."},
            )
            return
        self.ctx.bus.publish(BINARY_LOADED, {"model": model})

    # ---------------------------------------------------------------- events
    def on_event(self, topic: str, payload: Any) -> None:
        if topic == BINARY_LOAD_FAILED:
            self._status_label.setText(f"⚠ {payload.get('error', 'Load failed')}")
            return
        if topic == BINARY_CLOSED:
            self._model = None
            self._clear_all()
            self._status_label.setText("")
            self._path_label.setText("No binary loaded")
            self._path_label.setEnabled(False)
            return
        if topic == OPEN_BINARY_REQUESTED:
            self._open_dialog()
            return
        if topic == BINARY_DROPPED and isinstance(payload, dict):
            path = payload.get("path", "")
            if path:
                self.load_path(Path(path))
            return
        if topic == BINARY_LOADED:
            self._populate(payload.get("model"))

    # --------------------------------------------------------------- populate
    def _clear_all(self) -> None:
        for table in (
            self._sections_table,
            self._segments_table,
            self._symbols_table,
            self._imports_table,
            self._exports_table,
            self._strings_table,
            self._danger_table,
        ):
            table.setRowCount(0)
        for label in self._info_values.values():
            label.setText("")
        while self._checksec_grid.count():
            self._checksec_grid.takeAt(0)
            widget = self._checksec_grid.itemAt(0)
            if widget is not None:
                widget.widget().deleteLater()

    def _populate(self, model: Any) -> None:
        if model is None:
            return
        self._model = model
        self._path_label.setText(str(model.path))
        self._path_label.setEnabled(True)

        data = {
            "name": model.name,
            "fmt": model.fmt,
            "arch": model.arch,
            "bits": str(model.bits),
            "endianness": model.endianness,
            "entry": hex(model.entry_point) if model.entry_point else "(none)",
        }
        for _caption, key in INFO_FIELDS:
            self._info_values[key].setText(data.get(key, ""))

        self._fill_checksec(model)
        self._fill_tables(model)
        self._status_label.setText(
            f"{model.fmt} {model.arch} {model.bits}-bit · {len(model.sections)} sections · "
            f"{len(model.symbols)} symbols · {len(model.imports)} imports · backend: {model.parser_backend}"
        )

    def _fill_checksec(self, model: Any) -> None:
        self._clear_grid(self._checksec_grid)
        for index, item in enumerate(model.checksec):
            badge = self._badge(item.name, item.status)
            self._checksec_grid.addWidget(badge, index, 0)
            row = QLabel(item.explanation)
            row.setEnabled(False)
            row.setWordWrap(True)
            self._checksec_grid.addWidget(row, index, 1)
        self._checksec_grid.setColumnStretch(1, 1)

    def _clear_grid(self, grid: QGridLayout) -> None:
        while grid.count():
            item = grid.takeAt(0)
            if item is not None and item.widget() is not None:
                item.widget().deleteLater()

    def _badge(self, name: str, status: str) -> QLabel:
        role = _STATUS_ROLES.get(status, "badge-na")
        badge = QLabel(f"{name}: {status.upper()}")
        badge.setProperty("role", role)
        badge.setToolTip(
            {
                "enabled": "Mitigation active",
                "disabled": "Mitigation missing — this is the weak spot",
                "unknown": "Cannot be determined for this file",
            }.get(status, "")
        )
        return badge

    # ----------------------------------------------------------------- tables
    def _fill_tables(self, model: Any) -> None:
        fill = _TableFiller
        fill.sections(self._sections_table, model.sections)
        fill.segments(self._segments_table, model.segments)
        fill.symbols(self._symbols_table, model.symbols)
        fill.names(self._imports_table, model.imports)
        fill.names(self._exports_table, model.exports)
        fill.strings(self._strings_table, model.strings)
        fill.dangerous(self._danger_table, model.dangerous)


class _TableFiller:
    # static utility so the plugin class stays readable
    @staticmethod
    def sections(table: QTableWidget, rows: Any) -> None:
        rows = list(rows)
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = [row.name, _human_size(row.size), hex(row.vaddr), row.type]
            _put_row(table, index, values)

    @staticmethod
    def segments(table: QTableWidget, rows: Any) -> None:
        rows = list(rows)
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = [row.type_name, hex(row.vaddr), _human_size(row.size), row.flags]
            _put_row(table, index, values)

    @staticmethod
    def symbols(table: QTableWidget, rows: Any) -> None:
        rows = list(rows)
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = [row.name, str(row.size) if row.size else "", hex(row.value)]
            _put_row(table, index, values)

    @staticmethod
    def names(table: QTableWidget, names: list[str]) -> None:
        table.setRowCount(len(names))
        for index, name in enumerate(sorted(names)):
            _put_row(table, index, [name])

    @staticmethod
    def strings(table: QTableWidget, rows: list[tuple[int, str]]) -> None:
        table.setRowCount(len(rows))
        for index, (offset, text) in enumerate(rows):
            _put_row(table, index, [hex(offset), text])

    @staticmethod
    def dangerous(table: QTableWidget, rows: Any) -> None:
        rows = list(rows)
        table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            _put_row(
                table,
                index,
                [row.name, row.origin, row.severity.upper(), row.why],
            )


def _put_row(table: QTableWidget, index: int, values: list[str]) -> None:
    for col, value in enumerate(values):
        item = QTableWidgetItem(str(value))
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        table.setItem(index, col, item)


def _human_size(value: int) -> str:
    return f"{value} B" if value < 10240 else f"{value / 1024:.1f} KB"
