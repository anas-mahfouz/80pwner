# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Libc Helper dock (Step 7 B).

Load the target's libc once and get everything ret2libc needs: fingerprint,
symbol offsets, ``/bin/sh``, one-gadget candidates, runtime addresses from a
leak (or a known base), and a ready-made chain. The loaded file is announced
on the bus so the Script Generator can embed it.
"""

from __future__ import annotations

import logging
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from eightypwner.engines.gadgets import Gadget
from eightypwner.engines.libc import (
    WANTED_SYMBOLS,
    LibcError,
    LibcInfo,
    load_libc,
)
from eightypwner.engines.ropchain import chain_from_addresses, find_exact, find_pop_ret
from eightypwner.modules.builtin.common import (
    Relay,
    copy_text,
    elide,
    make_table,
    mono_font,
    parse_int,
    set_row,
)
from eightypwner.modules.builtin.gadget_finder import GADGET_SCAN_RESULT
from eightypwner.modules.interface import Plugin

log = logging.getLogger(__name__)

LIBC_LOADED = "libc_loaded"  # {"path": str, "info": LibcInfo}
LIBC_BASE_COMPUTED = "libc_base_computed"  # {"base": int, "symbol": str, "leak": int}


class LibcHelperPlugin(Plugin):
    name = "Libc Helper"
    description = (
        "Fingerprint a libc, resolve symbol offsets, compute the base from a leak, "
        "list one-gadgets and build a ret2libc chain."
    )
    icon = "📚"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._panel: QWidget | None = None
        self._info: LibcInfo | None = None
        self._base: int | None = None
        self._gadgets: list[Gadget] = []
        self._loading = False

    # ------------------------------------------------------------------ widget
    def widget(self) -> QWidget:
        if self._panel is not None:
            return self._panel
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(4)

        top = QHBoxLayout()
        load = QPushButton("Load libc…")
        load.setToolTip("Open the exact libc.so.6 the target uses")
        load.clicked.connect(self._load_dialog)
        top.addWidget(load)
        self._path_label = QLabel("No libc loaded")
        self._path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        top.addWidget(self._path_label, 1)
        outer.addLayout(top)

        self._info_label = QLabel("Fingerprint, offsets and one-gadgets appear here.")
        self._info_label.setWordWrap(True)
        outer.addWidget(self._info_label)

        base_row = QHBoxLayout()
        base_row.addWidget(QLabel("Base:"))
        self._base_edit = QLineEdit()
        self._base_edit.setPlaceholderText("libc base 0x…")
        self._base_edit.textChanged.connect(self._base_changed)
        base_row.addWidget(self._base_edit, 1)
        base_row.addWidget(QLabel("from leak:"))
        self._leak_symbol = QComboBox()
        self._leak_symbol.setEditable(True)
        self._leak_symbol.setMinimumWidth(120)
        self._leak_symbol.addItems(["puts", "printf", "read", "write", "malloc", "free", "system", "__libc_start_main"])
        base_row.addWidget(self._leak_symbol)
        self._leak_value = QLineEdit()
        self._leak_value.setPlaceholderText("leaked 0x…")
        self._leak_value.setMaximumWidth(170)
        self._leak_value.returnPressed.connect(self._compute_base)
        base_row.addWidget(self._leak_value)
        compute = QPushButton("Compute base")
        compute.clicked.connect(self._compute_base)
        base_row.addWidget(compute)
        outer.addLayout(base_row)

        self._tabs = QTabWidget()
        outer.addWidget(self._tabs, 1)
        self._build_symbols_tab()
        self._build_gadgets_tab()
        self._build_chain_tab()

        self._status = QLabel("Offsets are file-relative; runtime addresses need a base (leak or input).")
        self._status.setWordWrap(True)
        outer.addWidget(self._status)
        return panel

    def _build_symbols_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        self._sym_filter = QLineEdit()
        self._sym_filter.setPlaceholderText("Filter symbols…")
        self._sym_filter.textChanged.connect(lambda _t: self._refresh_symbols())
        layout.addWidget(self._sym_filter)
        self._sym_table = make_table(
            ["Symbol", "Offset", "Runtime"], settings=self.ctx.settings
        )
        self._sym_table.itemDoubleClicked.connect(self._copy_symbol_row)
        layout.addWidget(self._sym_table, 1)
        layout.addWidget(
            QLabel("Double-click a row to copy the address (runtime when a base is set).")
        )
        self._tabs.addTab(wrap, "Symbols")

    def _build_gadgets_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        self._one_table = make_table(
            ["Offset", "Verified", "RDI constraint / sequence"], settings=self.ctx.settings
        )
        self._one_table.itemDoubleClicked.connect(self._copy_one_gadget)
        layout.addWidget(self._one_table, 1)
        row = QHBoxLayout()
        self._one_note = QLabel(
            "Heuristic scan: verified gadgets provably load /bin/sh into RDI; "
            "others list the constraint you must satisfy."
        )
        self._one_note.setWordWrap(True)
        row.addWidget(self._one_note, 1)
        copy_offset = QPushButton("Copy offset")
        copy_offset.clicked.connect(lambda: self._copy_one_gadget(self._current_one_row(), 0))
        row.addWidget(copy_offset)
        copy_runtime = QPushButton("Copy runtime")
        copy_runtime.clicked.connect(lambda: self._copy_one_gadget(self._current_one_row(), 0))
        row.addWidget(copy_runtime)
        layout.addLayout(row)
        self._tabs.addTab(wrap, "One-gadgets")

    def _build_chain_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(QLabel("pop rdi ; ret:"))
        self._pop_rdi_edit = QLineEdit()
        self._pop_rdi_edit.setPlaceholderText("0x… (auto-filled from a gadget scan)")
        row.addWidget(self._pop_rdi_edit, 1)
        row.addWidget(QLabel("ret (align):"))
        self._ret_edit = QLineEdit()
        self._ret_edit.setPlaceholderText("optional")
        self._ret_edit.setMaximumWidth(130)
        row.addWidget(self._ret_edit)
        self._align_check = QCheckBox("align")
        self._align_check.setChecked(True)
        row.addWidget(self._align_check)
        layout.addLayout(row)

        actions = QHBoxLayout()
        build = QPushButton("Build ret2libc chain")
        build.clicked.connect(self._build_chain)
        actions.addWidget(build)
        copy = QPushButton("Copy chain")
        copy.clicked.connect(self._copy_chain)
        actions.addWidget(copy)
        actions.addStretch(1)
        layout.addLayout(actions)

        self._chain_out = QPlainTextEdit()
        self._chain_out.setReadOnly(True)
        self._chain_out.setFont(mono_font(self.ctx.settings))
        self._chain_out.setPlaceholderText(
            "Chain output: p64 lines ready to paste into your exploit."
        )
        layout.addWidget(self._chain_out, 1)
        self._tabs.addTab(wrap, "Chain")

    # --------------------------------------------------------------- lifecycle
    def initialize(self, parent: Any = None) -> None:
        self._relay = Relay()
        self._relay.route.connect(self._on_loaded)
        subscribe = (
            self.ctx.ui_bus.subscribe if self.ctx.ui_bus is not None else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_event)

    def shutdown(self) -> None:
        with suppress(Exception):
            self._unsub()

    def on_event(self, topic: str, payload: Any) -> None:
        if topic == GADGET_SCAN_RESULT and isinstance(payload, dict):
            if payload.get("state") == "done":
                gadgets = [g for g in payload.get("gadgets") or () if isinstance(g, Gadget)]
                if gadgets:
                    self._gadgets = gadgets
                    pop_rdi = find_pop_ret(gadgets, "rdi")
                    if pop_rdi is not None and not self._pop_rdi_edit.text().strip():
                        self._pop_rdi_edit.setText(hex(int(pop_rdi.address)))
                    ret = find_exact(gadgets, "ret")
                    if ret is not None and not self._ret_edit.text().strip():
                        self._ret_edit.setText(hex(int(ret.address)))
            return

    # ------------------------------------------------------------------- load
    def _load_dialog(self) -> None:
        start = str(self._info.path.parent) if self._info is not None else str(Path("/lib"))
        path, _filter = QFileDialog.getOpenFileName(
            self._panel, "Load libc", start, "ELF libraries (libc.so* *.so*);;All files (*)"
        )
        if path:
            self.load_path(path)

    def load_path(self, path: str) -> None:
        if self._loading:
            return
        self._loading = True
        self._status.setText(f"Parsing {Path(path).name} (symbol table + one-gadget scan)…")

        def work() -> None:
            try:
                info = load_libc(path)
                payload: dict[str, Any] = {"path": str(path), "info": info}
            except LibcError as exc:
                payload = {"path": str(path), "error": str(exc)}
            except Exception as exc:
                log.exception("libc load failed")
                payload = {"path": str(path), "error": f"Could not parse libc: {exc}"}
            with suppress(Exception):
                self._relay.route.emit(payload)

        threading.Thread(target=work, name="80pwner-libc", daemon=True).start()

    def _on_loaded(self, payload: Any) -> None:
        self._loading = False
        if not isinstance(payload, dict):
            return
        if payload.get("error"):
            self._status.setText(f"⚠ {payload['error']}")
            return
        info = payload.get("info")
        if not isinstance(info, LibcInfo):
            return
        self._info = info
        self._base = None
        self._base_edit.blockSignals(True)
        self._base_edit.clear()
        self._base_edit.blockSignals(False)
        path = str(info.path)
        self._path_label.setText(elide(path, 70))
        self._path_label.setToolTip(path)
        details = [info.fingerprint(), f"{info.arch}/{info.bits}-bit"]
        if info.binsh is not None:
            details.append(f"/bin/sh @ {info.binsh:#x}")
        if info.system is not None:
            details.append(f"system @ {info.system:#x}")
        if info.symbols:
            details.append(f"{len(info.symbols)} symbols")
        details.append(f"{len(info.one_gadgets)} one-gadget candidates")
        self._info_label.setText("  ·  ".join(details) + (f"\n{info.note}" if info.note else ""))
        self._refresh_symbols()
        self._refresh_one_gadgets()
        self._status.setText(
            f"Loaded {elide(info.soname or info.path.name, 40)}"
            + (f" — {info.note}" if info.note else "")
        )
        with suppress(Exception):
            self.ctx.bus.publish(LIBC_LOADED, {"path": path, "info": info})

    # ------------------------------------------------------------------ tables
    def _refresh_symbols(self) -> None:
        table = getattr(self, "_sym_table", None)
        if table is None:
            return
        info = self._info
        needle = self._sym_filter.text().strip().lower()
        table.setSortingEnabled(False)
        table.clearContents()
        table.setRowCount(0)
        if info is None:
            return
        names: list[str] = []
        seen: set[str] = set()
        for name in WANTED_SYMBOLS:
            if name in info.symbols and name not in seen:
                names.append(name)
                seen.add(name)
        for name in sorted(info.symbols):
            if name not in seen:
                names.append(name)
                seen.add(name)
        if needle:
            names = [
                name
                for name in names
                if needle in name.lower() or needle in hex(info.symbols[name]).lower()
            ]
        rows = names[:5000]
        base = self._active_base()
        table.setRowCount(len(rows))
        for row, name in enumerate(rows):
            offset = info.symbols[name]
            runtime = f"{base + offset:#x}" if base is not None else ""
            set_row(table, row, [name, f"{offset:#x}", runtime])
        table.resizeColumnToContents(2)

    def _refresh_one_gadgets(self) -> None:
        table = getattr(self, "_one_table", None)
        if table is None:
            return
        info = self._info
        table.setRowCount(0)
        if info is None:
            return
        table.setRowCount(len(info.one_gadgets))
        base = self._active_base()
        for row, gadget in enumerate(info.one_gadgets):
            runtime = f"{base + gadget.offset:#x}" if base is not None else f"{gadget.offset:#x}"
            verified = "✅" if gadget.verified else "constraint"
            set_row(table, row, [runtime, verified, gadget.constraint], addr=gadget.offset)

    def _current_one_row(self) -> int:
        table = getattr(self, "_one_table", None)
        if table is None:
            return -1
        selected = table.selectedItems()
        return selected[0].row() if selected else -1

    def _copy_one_gadget(self, row: int, _column: int = 0) -> None:
        table = getattr(self, "_one_table", None)
        if table is None or row < 0 or row >= table.rowCount():
            return
        text = table.item(row, 0).text() if table.item(row, 0) else ""
        copy_text(text)
        self._status.setText(f"Copied one-gadget address {text}.")

    def _copy_symbol_row(self, item: Any, _column: int = 0) -> None:
        table = self._sym_table
        row = item.row()
        column = 2 if table.item(row, 2) and table.item(row, 2).text() else 1
        cell = table.item(row, column)
        if cell is None:
            return
        copy_text(cell.text())
        self._status.setText(f"Copied {table.item(row, 0).text()} = {cell.text()}")

    # -------------------------------------------------------------------- base
    def _active_base(self) -> int | None:
        return self._base

    def _base_changed(self, text: str) -> None:
        self._base = parse_int(text)
        self._refresh_symbols()
        self._refresh_one_gadgets()

    def _compute_base(self) -> None:
        info = self._info
        if info is None:
            self._status.setText("Load a libc first.")
            return
        symbol = self._leak_symbol.currentText().strip()
        leak = parse_int(self._leak_value.text())
        if not symbol or leak is None:
            self._status.setText("Choose the leaked symbol and paste its runtime value.")
            return
        offset = info.symbols.get(symbol) or info.offset(symbol, "__" + symbol)
        if not offset:
            self._status.setText(f"No offset for {symbol!r} in this libc.")
            return
        base = leak - offset
        if base < 0:
            self._status.setText(
                f"Leak {leak:#x} is smaller than {symbol}'s offset {offset:#x} — wrong libc?"
            )
            return
        self._base_edit.setText(hex(base))
        self._status.setText(f"libc base = {leak:#x} - {offset:#x} ({symbol}) = {base:#x}")
        with suppress(Exception):
            self.ctx.bus.publish(
                LIBC_BASE_COMPUTED, {"base": base, "symbol": symbol, "leak": leak}
            )

    # ------------------------------------------------------------------- chain
    def _build_chain(self) -> None:
        info = self._info
        base = self._active_base()
        if info is None or base is None:
            self._status.setText("Load a libc and set/compute the base first.")
            return
        system = info.system
        binsh = info.binsh
        if not system or binsh is None:
            self._status.setText("This libc is missing system or /bin/sh.")
            return
        pop_rdi = parse_int(self._pop_rdi_edit.text())
        ret = parse_int(self._ret_edit.text())
        if not pop_rdi:
            gadget = find_pop_ret(self._gadgets, "rdi")
            pop_rdi = int(gadget.address) if gadget is not None else None
        if not pop_rdi:
            self._status.setText(
                "No 'pop rdi ; ret' gadget — scan the binary/libc in Gadget Finder "
                "or paste its address."
            )
            return
        items = []
        labels = []
        if self._align_check.isChecked() and ret:
            items.append(ret)
            labels.append("ret (align)")
        items += [pop_rdi, base + binsh, base + system]
        labels += ["pop rdi ; ret", "/bin/sh", "system"]
        chain = chain_from_addresses(items, labels, bits=info.bits)
        self._chain_out.setPlainText(
            f"# ret2libc — libc base {base:#x} ({info.version or '?'})\n"
            f"# system={base + system:#x}  binsh={base + binsh:#x}  pop_rdi={pop_rdi:#x}\n"
            + chain.p64_lines()
            + f"\n# raw: {chain.raw.hex()}\n"
        )
        self._status.setText("Chain built. Stack alignment is handled with the leading ret.")

    def _copy_chain(self) -> None:
        text = self._chain_out.toPlainText().strip()
        if not text:
            self._status.setText("Build a chain first.")
            return
        copy_text(text)
        self._status.setText("Chain copied.")
