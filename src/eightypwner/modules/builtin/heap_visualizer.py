# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Heap Visualizer dock (Step 8) — glibc chunk chain + tcache bins.

The debugger reads the live ``[heap]`` in 4 KiB MI chunks; this dock parses it
with :mod:`eightypwner.engines.heap` and shows the chunk table, tcache state
and corruption red flags (size/align violations, double-listed chunks,
non-main arenas). Click a chunk to send the address to the memory view.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import Any

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import ADDRESS_SELECTED
from eightypwner.engines.gdb_mi import T_HEAP_REQUEST, T_HEAP_SNAPSHOT
from eightypwner.engines.heap import HeapResult, analyze_heap, chunk_rows
from eightypwner.modules.builtin.common import (
    copy_text,
    make_table,
    mono_font,
    parse_int,
    set_row,
)
from eightypwner.modules.interface import Plugin

log = logging.getLogger(__name__)

MAX_SNAPSHOT = 4 * 1024 * 1024
DEFAULT_SNAPSHOT = 512 * 1024


class HeapPlugin(Plugin):
    name = "Heap"
    description = (
        "Snapshot the live glibc heap: chunk chain, tcache bins, sizes, flags "
        "and corruption hints."
    )
    icon = "🧱"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._panel: QWidget | None = None
        self._result: HeapResult | None = None
        self._waiting = False

    # ------------------------------------------------------------------ widget
    def widget(self) -> QWidget:
        if self._panel is not None:
            return self._panel
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(4)

        controls = QHBoxLayout()
        self._snapshot_button = QPushButton("Snapshot heap")
        self._snapshot_button.setToolTip(
            "Requires a stopped debuggee. Reads up to the size below."
        )
        self._snapshot_button.clicked.connect(self.request_snapshot)
        controls.addWidget(self._snapshot_button)
        controls.addWidget(QLabel("bytes:"))
        self._size_spin = QSpinBox()
        self._size_spin.setRange(0x1000, MAX_SNAPSHOT)
        self._size_spin.setSingleStep(0x10000)
        self._size_spin.setValue(DEFAULT_SNAPSHOT)
        self._size_spin.setDisplayIntegerBase(16)
        self._size_spin.setPrefix("0x")
        controls.addWidget(self._size_spin)
        controls.addWidget(QLabel("base:"))
        self._base_edit = QLineEdit()
        self._base_edit.setPlaceholderText("auto ([heap])")
        self._base_edit.setMaximumWidth(140)
        controls.addWidget(self._base_edit)
        self._copy_button = QPushButton("Copy chunks")
        self._copy_button.clicked.connect(self._copy)
        controls.addWidget(self._copy_button)
        outer.addLayout(controls)

        self._stats = QLabel(
            "Run the target to a breakpoint after malloc(), then snapshot. "
            "The heap base is resolved from [heap] automatically."
        )
        self._stats.setWordWrap(True)
        outer.addWidget(self._stats)

        self._tabs = QTabWidget()
        self._chunks = make_table(
            ["Address", "Size", "Flags", "State", "Notes"], settings=self.ctx.settings
        )
        self._chunks.itemDoubleClicked.connect(self._row_clicked)
        self._tabs.addTab(self._chunks, "Chunks")

        self._bins = make_table(
            ["Idx", "Chunk size", "Count", "Entries"], settings=self.ctx.settings
        )
        self._bins.itemDoubleClicked.connect(self._bin_clicked)
        self._tabs.addTab(self._bins, "tcache")

        self._raw = QLineEdit()
        self._raw.setReadOnly(True)
        self._raw.setFont(mono_font(self.ctx.settings))
        self._raw.setPlaceholderText("tcache_perthread_struct summary")
        wrap = QWidget()
        raw_layout = QVBoxLayout(wrap)
        raw_layout.setContentsMargins(0, 0, 0, 0)
        raw_layout.addWidget(self._raw)
        raw_layout.addStretch(1)
        self._tabs.addTab(wrap, "Struct")

        outer.addWidget(self._tabs, 1)

        hints = QLabel(
            "Red flags: tcache count > 7 (double free), chunk size not 0x10-aligned, "
            "PREV_INUSE gaps (possible overflow), duplicate tcache entries."
        )
        hints.setWordWrap(True)
        hints.setFont(mono_font(self.ctx.settings))
        outer.addWidget(hints)
        return panel

    # --------------------------------------------------------------- lifecycle
    def initialize(self, parent: Any = None) -> None:
        subscribe = (
            self.ctx.ui_bus.subscribe if self.ctx.ui_bus is not None else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_event)

    def shutdown(self) -> None:
        with suppress(Exception):
            self._unsub()

    # ------------------------------------------------------------------ events
    def on_event(self, topic: str, payload: Any) -> None:
        if topic != T_HEAP_SNAPSHOT or not isinstance(payload, dict):
            return
        self._waiting = False
        self._snapshot_button.setEnabled(True)
        if payload.get("error"):
            self._stats.setText(f"⚠ {payload['error']}")
            if not payload.get("data"):
                return
        data = payload.get("data")
        base = int(payload.get("base", 0) or 0)
        if not isinstance(data, (bytes, bytearray)) or not data:
            self._stats.setText("⚠ Empty heap snapshot.")
            return
        bits = int(payload.get("bits", 64) or 64)
        try:
            result = analyze_heap(
                bytes(data), base=base, bits=bits, max_chunks=8192
            )
        except Exception as exc:  # pragma: no cover — defensive
            log.exception("heap parse failed")
            self._stats.setText(f"⚠ Heap parse failed: {exc}")
            return
        # The engine's readers report a bounded window; flag it in the UI.
        if payload.get("truncated") and result.note:
            result.note = result.note
        self._result = result
        self._render(result, payload)
        with suppress(Exception):
            self.ctx.bus.publish(
                "heap_analyzed",
                {
                    "base": result.base,
                    "chunks": result.total_chunks,
                    "tcache_total": result.tcache_total,
                },
            )

    # ----------------------------------------------------------------- request
    def request_snapshot(self) -> None:
        if self._waiting:
            return
        base = parse_int(self._base_edit.text())
        self._waiting = True
        self._snapshot_button.setEnabled(False)
        self._stats.setText("Reading heap from the debugger…")
        with suppress(Exception):
            self.ctx.bus.publish(
                T_HEAP_REQUEST,
                {"max_bytes": int(self._size_spin.value()), "base": base},
            )

    # ------------------------------------------------------------------ render
    def _render(self, result: HeapResult, payload: dict[str, Any]) -> None:
        chunks = self._chunks
        rows = chunk_rows(result)
        chunks.setRowCount(len(rows))
        for row, values in enumerate(rows):
            address = parse_int(values[0]) or 0
            set_row(chunks, row, values, addr=address)
        chunks.resizeColumnToContents(0)

        bins = self._bins
        bins.setRowCount(len(result.tcache))
        for row, bin_ in enumerate(result.tcache):
            entries = "  ".join(f"{entry:#x}" for entry in bin_.entries) or "—"
            set_row(
                bins,
                row,
                [str(bin_.index), f"{bin_.chunk_size:#x}", str(bin_.count), entries],
                addr=bin_.entries[0] if bin_.entries else None,
            )

        struct = (
            f"tcache_perthread_struct @ {result.tcache_struct:#x} "
            f"({result.tcache_layout or 'unknown layout'})"
            if result.tcache_struct
            else "tcache_perthread_struct not found"
        )
        self._raw.setText(struct)

        flags: list[str] = []
        for bin_ in result.tcache:
            if bin_.count > 7:
                flags.append(f"tcache[{bin_.index}] count={bin_.count} (> 7 → double free?)")
            if len(set(bin_.entries)) != len(bin_.entries):
                flags.append(f"tcache[{bin_.index}] duplicate entries")
        for chunk in result.chunks:
            if chunk.size % 0x10:
                flags.append(f"chunk {chunk.addr:#x} size {chunk.size:#x} unaligned")
        total = result.tcache_total
        self._stats.setText(
            f"heap {result.base:#x}-{result.end:#x} ({result.end - result.base:#x} bytes)  ·  "
            f"{result.total_chunks} chunks ({result.in_use} in use, "
            f"{len(result.free_chunks)} free)  ·  tcache {total} entries"
            + (f"  ·  {result.note}" if result.note else "")
            + (f"\n⚠ {'; '.join(flags[:4])}" if flags else "")
        )

    # ----------------------------------------------------------------- actions
    def _copy(self) -> None:
        if self._result is None:
            self._stats.setText("Snapshot the heap first.")
            return
        lines = [
            f"{address}\t{size}\t{flags}\t{state}\t{note}"
            for address, size, flags, state, note in chunk_rows(self._result)
        ]
        copy_text("\n".join(lines))
        self._stats.setText("Chunk table copied as TSV.")

    def _row_clicked(self, item: Any, _column: int = 0) -> None:
        table = self._chunks
        address_item = table.item(item.row(), 0)
        address = parse_int(address_item.text() if address_item else "")
        if address:
            with suppress(Exception):
                self.ctx.bus.publish(ADDRESS_SELECTED, {"address": address})
            with suppress(Exception):
                self.ctx.bus.publish(
                    "memory_goto_request", {"address": address, "size": 0x100}
                )

    def _bin_clicked(self, item: Any, _column: int = 0) -> None:
        table = self._bins
        entries = table.item(item.row(), 3)
        text = entries.text() if entries else ""
        first = text.split()[0] if text.strip() not in ("", "—") else ""
        address = parse_int(first)
        if address:
            copy_text(first)
            with suppress(Exception):
                self.ctx.bus.publish(ADDRESS_SELECTED, {"address": address})
