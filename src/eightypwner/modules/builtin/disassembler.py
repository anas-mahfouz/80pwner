# 80PWNER — by Anas Mahfouz (The80)

"""Disassembler module (Step 3): function list + disassembly view + xrefs.

Heavy work (capstone decode, function discovery) always runs in worker
threads; every widget update arrives through the UiBus bridge on the UI
thread. Decoding is lazy — per function or a bounded range around a jumped-to
address — so huge binaries never get disassembled wholesale.

Per-session annotations: comments on addresses and renamed symbols live in
the ``SessionState`` model (persisted as JSON in the platform session dir).
"""

from __future__ import annotations

import contextlib
import logging
import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import (
    ADDRESS_SELECTED,
    BINARY_CLOSED,
    BINARY_DROPPED,
    BINARY_LOAD_FAILED,
    BINARY_LOADED,
    DISASSEMBLY_READY,
    FUNCTION_SELECTED,
    FUNCTIONS_DISCOVERED,
    OPEN_BINARY_REQUESTED,
)
from eightypwner.engines.disassembler import Disassembler, ReadError
from eightypwner.engines.functions import FunctionFinder, filter_functions
from eightypwner.engines.gdb_mi import (
    T_BP_TOGGLE_REQUEST,
    T_BP_UPDATED,
    T_STOPPED,
)
from eightypwner.modules.interface import Plugin
from eightypwner.ui.fonts import resolve_monospace

if TYPE_CHECKING:
    from eightypwner.engines.binary_parser import BinaryModel
    from eightypwner.engines.disassembler import Instruction
    from eightypwner.engines.functions import FunctionIndex

log = logging.getLogger(__name__)

VIEW_RANGE_BYTES = 0x400  # window for non-function jumps (bss, data, wild addr)
IMM_RE = re.compile(r"0x[0-9a-fA-F]+")


class DisassemblerPlugin(Plugin):
    name = "Disassembler"
    description = "Capstone disassembly: functions, xrefs, comments, renames."
    icon = "🖥"

    # ---------------------------------------------------------------- state
    _model: BinaryModel | None
    _disasm: Disassembler | None
    _index: FunctionIndex | None

    # ---------------------------------------------------------------- widget
    def widget(self) -> QWidget:
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)

        # ------------------------------------------------- toolbar row
        bar = QHBoxLayout()
        open_btn = QPushButton("Open Binary…")
        open_btn.clicked.connect(self._open_dialog)
        back_btn = QPushButton("◀")
        back_btn.setToolTip("Back in navigation history")
        back_btn.setEnabled(False)
        fwd_btn = QPushButton("▶")
        fwd_btn.setToolTip("Forward in navigation history")
        fwd_btn.setEnabled(False)
        back_btn.clicked.connect(self._go_back)
        fwd_btn.clicked.connect(self._go_forward)
        self._nav_buttons = (back_btn, fwd_btn)

        self._jump_edit = QLineEdit()
        self._jump_edit.setPlaceholderText("Go to address (hex) — Ctrl+G")
        self._jump_edit.setMaximumWidth(240)
        self._jump_edit.returnPressed.connect(self._jump_entered)
        self._gshortcut = QShortcut(QKeySequence("Ctrl+G"), self._jump_edit)
        # F9 toggles a breakpoint at the row under the disassembly cursor
        self._f9shortcut = QShortcut(QKeySequence("F9"), self._panel)
        self._f9shortcut.activated.connect(self._f9_toggle)

        self._att_check = QCheckBox("AT&T")
        self._att_check.setToolTip("AT&T syntax (x86 only) — reload current view")
        self._att_check.toggled.connect(self._reload_view)

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter functions…")
        self._filter_edit.setMaximumWidth(200)
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.textChanged.connect(self._refill_functions)

        bar.addWidget(open_btn)
        bar.addWidget(back_btn)
        bar.addWidget(fwd_btn)
        bar.addWidget(self._jump_edit, 0, Qt.AlignmentFlag.AlignLeft)
        bar.addWidget(self._att_check)
        bar.addStretch(1)
        bar.addWidget(QLabel("Functions:"))
        bar.addWidget(self._filter_edit)
        outer.addLayout(bar)

        # ------------------------------------------------- main splitter
        split = QSplitter(Qt.Orientation.Horizontal)
        outer.addWidget(split, 1)

        # -- function list (left)
        self._func_table = QTableWidget(0, 4)
        self._func_table.setHorizontalHeaderLabels(["Function", "Address", "Size", "Origin"])
        mono = QFont(resolve_monospace(self.ctx.settings.get("font.mono_family") or ""))
        self._func_table.setFont(mono)
        self._func_table.verticalHeader().setVisible(False)
        self._func_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._func_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._func_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._func_table.setAlternatingRowColors(True)
        header = self._func_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        self._func_table.itemSelectionChanged.connect(self._function_selected)
        split.addWidget(self._func_table)

        # -- right half: disassembly above, xrefs below
        right = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(right)

        self._disasm_table = QTableWidget(0, 5)
        self._disasm_table.setHorizontalHeaderLabels(["Address", "Bytes", "Instruction", "Comment", "Addr"])
        # last (hidden) column carries the numeric address for double-click nav
        dis_header = self._disasm_table.horizontalHeader()
        dis_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        dis_header.setStretchLastSection(True)
        self._disasm_table.setFont(mono)
        self._disasm_table.verticalHeader().setVisible(False)
        self._disasm_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._disasm_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._disasm_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._disasm_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._disasm_table.customContextMenuRequested.connect(self._context_menu)
        self._disasm_table.itemSelectionChanged.connect(self._instruction_selected)
        self._disasm_table.cellDoubleClicked.connect(self._instruction_dblclicked)
        self._disasm_table.setColumnHidden(4, True)
        right.addWidget(self._disasm_table)

        self._xref_table = QTableWidget(0, 3)
        self._xref_table.setHorizontalHeaderLabels(["Kind", "From", "To"])
        self._xref_table.setFont(mono)
        self._xref_table.verticalHeader().setVisible(False)
        self._xref_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._xref_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._xref_table.cellDoubleClicked.connect(self._xref_dblclicked)
        xref_header = self._xref_table.horizontalHeader()
        xref_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        xref_header.setStretchLastSection(True)
        right.addWidget(self._xref_table)
        right.setSizes([460, 180])

        split.setSizes([300, 700])

        self._status_label = QLabel("No binary loaded")
        self._status_label.setEnabled(False)
        outer.addWidget(self._status_label)

        # internal state
        self._model = None
        self._disasm = None
        self._index = None
        self._all_functions: list[Any] = []
        self._view_name = ""
        self._view_start = 0
        self._view_instructions: list[Instruction] = []
        self._current_function: int | None = None
        self._history: list[int] = []
        self._history_pos = -1
        self._pending_view = 0  # request id: ignore stale worker results
        self._lock = threading.Lock()
        # live-debugger sync (Step 4): PC marker + breakpoint marks
        self._pc_address: int | None = None
        self._breakpoint_addrs: set[int] = set()
        return panel

    def _tokens(self) -> dict[str, str]:
        theme = getattr(self.ctx, "theme", None)
        if theme is not None:
            return dict(theme.theme().tokens)
        from eightypwner.ui.theme import DARK_TOKENS

        return dict(DARK_TOKENS)

    # ------------------------------------------------------------- lifecycle
    def initialize(self, parent: Any = None) -> None:
        subscribe = (
            self.ctx.ui_bus.subscribe
            if self.ctx.ui_bus is not None
            else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_event)
        theme = getattr(self.ctx, "theme", None)
        if theme is not None:
            theme.theme_changed.connect(self._on_theme_changed)

    def shutdown(self) -> None:
        with contextlib.suppress(Exception):
            self._unsub()

    def _on_theme_changed(self, theme: Any) -> None:
        self._reload_view()

    # --------------------------------------------------------------- events
    def on_event(self, topic: str, payload: Any) -> None:
        if topic == BINARY_LOADED:
            model = payload.get("model") if isinstance(payload, dict) else None
            if model is not None:
                self._on_model_loaded(model)
        elif topic == BINARY_LOAD_FAILED:
            self._status_label.setText(f"⚠ {payload.get('error', 'Load failed')}")
        elif topic == BINARY_DROPPED and isinstance(payload, dict):
            # stand-alone robustness: if no other module parses the drop,
            # we take it (parse in a worker; publish binary_loaded for sync)
            path = payload.get("path", "")
            if path and getattr(self._model, "path", None) != Path(path):
                self._status_label.setText(f"Parsing {Path(path).name}…")
                threading.Thread(target=self._parse_drop, args=(Path(path),), daemon=True).start()
        elif topic == BINARY_CLOSED:
            self._reset()
        elif topic == OPEN_BINARY_REQUESTED:
            self._open_dialog()
        elif topic == FUNCTIONS_DISCOVERED and isinstance(payload, dict):
            self._on_index_ready(payload)
        elif topic == DISASSEMBLY_READY and isinstance(payload, dict):
            self._on_disassembly(payload)
        elif topic == T_STOPPED and isinstance(payload, dict):
            self._on_debugger_pc(payload.get("pc"))
        elif topic == T_BP_UPDATED and isinstance(payload, dict):
            self._on_breakpoints(payload)

    # -------------------------------------------------------- debugger sync
    def _on_debugger_pc(self, pc: Any) -> None:
        """UI thread: mark the current instruction (and navigate to it)."""
        with contextlib.suppress(TypeError, ValueError):
            self._pc_address = int(str(pc), 16) if pc else None
        if self._pc_address is None:
            self._refresh_marks()
            return
        visible = any(ins.address == self._pc_address for ins in self._view_instructions)
        if visible:
            self._refresh_marks()
        elif self._model is not None:
            self.navigate(self._pc_address, record=False)

    def _on_breakpoints(self, payload: dict[str, Any]) -> None:
        rows = payload.get("breakpoints") if isinstance(payload, dict) else None
        self._breakpoint_addrs = {
            int(str(row["address"]), 16)
            for row in (rows or [])
            if row.get("address") and str(row.get("enabled", "yes")) == "yes"
        }
        self._refresh_marks()

    def _refresh_marks(self) -> None:
        """Re-apply address-column backgrounds (PC row + breakpoint rows)."""
        tokens = self._tokens()
        pc_color = QColor(tokens["accent"])
        bp_color = QColor(tokens.get("warn", "#FFB454"))
        for row in range(self._disasm_table.rowCount()):
            address_item = self._disasm_table.item(row, 4)
            if address_item is None:
                continue
            address = address_item.data(Qt.ItemDataRole.UserRole)
            if address is None:
                continue
            if address == self._pc_address:
                address_item.setToolTip("▶ current instruction (PC)")
                self._disasm_table.item(row, 0).setForeground(pc_color)
                first = self._disasm_table.item(row, 2)
                if first is not None:
                    first.setForeground(pc_color)
            elif address in self._breakpoint_addrs:
                address_item.setToolTip("● breakpoint — F9 or the menu toggles it")
                self._disasm_table.item(row, 0).setForeground(bp_color)

    def _request_bp_toggle(self, address: int) -> None:
        """Publish the toggle request; the Debugger module owns the engine."""
        self.ctx.bus.publish(T_BP_TOGGLE_REQUEST, {"address": int(address)})

    def _f9_toggle(self) -> None:
        row = self._disasm_table.currentRow()
        if row < 0 or row >= len(self._view_instructions):
            self._status_label.setText("⚠ F9 toggles breakpoints on an instruction")
            return
        self._request_bp_toggle(self._view_instructions[row].address)

    # ------------------------------------------------------- binary loading
    def _open_dialog(self) -> None:
        start = str(self._model.path.parent) if self._model is not None else ""
        chosen, _filter = QFileDialog.getOpenFileName(
            self._panel, "Open binary (ELF / PE / Mach-O)", start
        )
        if chosen:
            from eightypwner.core.event_bus import BINARY_DROPPED

            self.ctx.bus.publish(BINARY_DROPPED, {"path": chosen})

    def _parse_drop(self, path: Path) -> None:
        """Worker thread: parse a dropped binary (kept for stand-alone flow)."""
        from eightypwner.engines.binary_parser import ParseError, parse_binary

        try:
            model = parse_binary(path)
        except ParseError as exc:
            self.ctx.bus.publish(
                BINARY_LOAD_FAILED, {"path": str(path), "error": str(exc)}
            )
            return
        except Exception:
            log.exception("Unexpected parser failure on %s", path)
            self.ctx.bus.publish(
                BINARY_LOAD_FAILED,
                {"path": str(path), "error": f"Internal parser error on {path.name}."},
            )
            return
        self.ctx.bus.publish(BINARY_LOADED, {"model": model})

    def _on_model_loaded(self, model: BinaryModel) -> None:
        """New binary: load its annotations into the session, discover functions."""
        self._model = model
        session = getattr(self.ctx, "session", None)
        if session is not None:
            session.binary_path = model.path
            session.load_annotations()
        self._status_label.setText(f"Discovering functions in {model.name}…")
        worker = threading.Thread(
            target=self._build_index, args=(model, self._pending_view + 1), daemon=True
        )
        self._pending_view += 1
        worker.start()

    def _build_index(self, model: BinaryModel, request_id: int) -> None:
        """Worker thread: capstone discovery — never touches widgets."""
        try:
            finder = FunctionFinder(model)
            index = finder.discover()
            disasm = Disassembler(model)
        except RuntimeError as exc:  # capstone missing / unsupported arch
            self.ctx.bus.publish(
                FUNCTIONS_DISCOVERED, {"model": model, "request": request_id, "error": str(exc)}
            )
            return
        except Exception:
            log.exception("Function discovery failed on %s", model.name)
            self.ctx.bus.publish(
                FUNCTIONS_DISCOVERED,
                {"model": model, "request": request_id, "error": "Discovery failed."},
            )
            return
        self.ctx.bus.publish(
            FUNCTIONS_DISCOVERED,
            {"model": model, "request": request_id, "index": index, "disasm": disasm},
        )

    def _on_index_ready(self, payload: dict[str, Any]) -> None:
        """UI thread: index + Disassembler ready."""
        if payload.get("request") != self._pending_view:
            return  # stale worker result
        model = payload.get("model")
        if model is not self._model:
            return
        if payload.get("error"):
            self._status_label.setText(f"⚠ {payload['error']}")
            return
        self._disasm = payload["disasm"]
        self._index = payload["index"]
        self._all_functions = list(self._index.functions)
        self._refill_functions()
        self._att_check.setEnabled(bool(getattr(self._disasm, "is_x86", False)))
        truncated = " (truncated scan)" if self._index.truncated else ""
        self._status_label.setText(
            f"{len(self._all_functions)} functions · {len(self._index.xrefs)} xrefs{truncated}"
        )
        # auto-jump so the panel is never empty: prefer ``main``, else entry
        target = self._model.entry_point if self._model is not None else 0
        main_like = [f for f in self._all_functions if f.name == "main"]
        if main_like:
            target = main_like[0].address
        elif target == 0 and self._all_functions:
            target = self._all_functions[0].address
        if target:
            self.navigate(target)

    # ------------------------------------------------------- function list
    def _display_name(self, address: int, original: str) -> str:
        session = getattr(self.ctx, "session", None)
        if session is not None:
            return session.display_name(address, original)
        return original

    def _refill_functions(self) -> None:
        self._func_table.setRowCount(0)
        if not self._all_functions:
            return
        needle = self._filter_edit.text()
        rows = filter_functions(self._all_functions, needle)
        self._func_table.setRowCount(len(rows))
        for row, func in enumerate(rows):
            name = self._display_name(func.address, func.name)
            if name != func.name:
                name += "  (renamed)"
            values = [name, hex(func.address), str(func.size) if func.size else "", func.origin]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 1:
                    item.setData(Qt.ItemDataRole.UserRole, func.address)
                self._func_table.setItem(row, col, item)

    def _function_selected(self) -> None:
        items = self._func_table.selectedItems()
        if not items:
            return
        address = self._func_table.item(items[0].row(), 1).data(Qt.ItemDataRole.UserRole)
        self._current_function = int(address)
        self.ctx.bus.publish(
            FUNCTION_SELECTED, {"address": self._current_function}
        )
        self.navigate(int(address))

    # -------------------------------------------------------- disassembly UI
    def navigate(self, address: int, record: bool = True) -> None:
        """Jump the disassembly view to *address*: function view or range view."""
        if self._disasm is None:
            self._status_label.setText("No binary — nothing to disassemble")
            return
        att = self._att_check.isChecked()
        self._pending_view += 1
        self._status_label.setText(f"Disassembling {hex(address)}…")
        if record:
            self._push_history(address)
        threading.Thread(
            target=self._decode_request,
            args=(address, att, self._pending_view),
            daemon=True,
        ).start()

    def _decode_request(self, address: int, att: bool, request_id: int) -> None:
        """Worker thread: decode one view and publish the result."""
        disasm = self._disasm
        if disasm is None:
            return
        index = self._index
        match = (
            [f for f in index.functions if f.address == address] if index is not None else []
        )
        try:
            if match:
                # known function start → lazy cached per-function decode
                instructions = disasm.decode_function(address, att)
                func = match[0]
                self.ctx.bus.publish(
                    DISASSEMBLY_READY,
                    {
                        "request": request_id,
                        "address": address,
                        "start": func.address,
                        "name": func.name,
                        "instructions": instructions,
                        "att": att,
                        "truncated": len(instructions) >= 4096,
                    },
                )
                return
            # unknown address: bounded range decode (never the whole binary)
            instructions = list(disasm.decode(address, VIEW_RANGE_BYTES, att))
        except ReadError as exc:
            self.ctx.bus.publish(
                DISASSEMBLY_READY,
                {"request": request_id, "address": address, "error": str(exc)},
            )
            return
        except Exception:
            log.exception("Decode failed at %s", hex(address))
            self.ctx.bus.publish(
                DISASSEMBLY_READY,
                {"request": request_id, "address": address, "error": "Decode failed."},
            )
            return
        self.ctx.bus.publish(
            DISASSEMBLY_READY,
            {
                "request": request_id,
                "address": address,
                "start": address,
                "name": f"@ {hex(address)}",
                "instructions": instructions,
                "att": att,
                "truncated": True,
            },
        )

    def _on_disassembly(self, payload: dict[str, Any]) -> None:
        """UI thread: fill the disassembly table from a worker result."""
        if payload.get("request") != self._pending_view:
            return
        if payload.get("error"):
            self._status_label.setText(f"⚠ {payload['error']}")
            return
        self._view_name = str(payload.get("name", ""))
        self._view_start = int(payload.get("start", 0))
        self._view_instructions = list(payload.get("instructions", []))
        self._fill_view()
        self._fill_xrefs()
        self._update_nav_buttons()
        self._refresh_marks()
        count = len(self._view_instructions)
        self._status_label.setText(
            f"{self._view_name or hex(payload['address'])} — {count} instructions"
            + (" (truncated)" if payload.get("truncated") else "")
        )

    def _fill_view(self) -> None:
        tokens = self._tokens()
        session = getattr(self.ctx, "session", None)
        rows = self._view_instructions
        self._disasm_table.setRowCount(len(rows))
        for row, ins in enumerate(rows):
            ins_bytes = " ".join(ins.bytes_hex.split(" ")[:8])
            if len(ins.bytes_hex.split(" ")) > 8:
                ins_bytes += " …"
            values = [hex(ins.address), ins_bytes, ins.text(), "", hex(ins.address)]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if col == 4:
                    item.setData(Qt.ItemDataRole.UserRole, ins.address)
                    self._disasm_table.setItem(row, col, item)
                    continue
                # token-based syntax colors (semantic, not the bare accent)
                color = _color_for(ins.mnemonic, tokens)
                if color:
                    item.setForeground(QColor(color))
                if col == 3 and session is not None:
                    comment = session.comment_at(ins.address)
                    if comment:
                        item.setText(comment.splitlines()[0])
                        item.setToolTip(comment)
                self._disasm_table.setItem(row, col, item)

    # ---------------------------------------------------------------- xrefs
    def _fill_xrefs(self) -> None:
        """xrefs to/from the current view (uses the discovery index)."""
        self._xref_table.setRowCount(0)
        if self._index is None:
            return
        field_start = self._view_start
        field_end = self._view_start
        if self._view_instructions:
            last = self._view_instructions[-1]
            field_end = last.address + max(last.size, 1)
        relevant = [
            x
            for x in self._index.xrefs
            if (field_start <= x.to_address < field_end) or (field_start <= x.from_address < field_end)
        ]
        self._xref_table.setRowCount(len(relevant))
        for row, xref in enumerate(relevant):
            values = [xref.kind, hex(xref.from_address), hex(xref.to_address)]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self._xref_table.setItem(row, col, item)

    def _xref_dblclicked(self, row: int, _col: int) -> None:
        from_item = self._xref_table.item(row, 1)
        if from_item is not None:
            self.navigate(int(str(from_item.text()), 16))

    # ------------------------------------------------------------ selection
    def _instruction_selected(self) -> None:
        item = self._disasm_table.item(self._disasm_table.currentRow(), 4)
        if item is not None:
            self.ctx.bus.publish(ADDRESS_SELECTED, {"address": item.data(Qt.ItemDataRole.UserRole)})

    def _instruction_dblclicked(self, row: int, _col: int) -> None:
        """Double-click a call/jmp operand → follow that target."""
        text = ""
        for col in (2,):
            item = self._disasm_table.item(row, col)
            text = item.text() if item is not None else ""
        match = IMM_RE.findall(text)
        for candidate in match:
            address = int(candidate, 16)
            if self._maybe_function(address):
                self.navigate(address)
                return
        # no operand target (e.g. j replaced by branch-table) — xrefs panel wins
        if self._view_instructions and row < len(self._view_instructions):
            targets = self._disasm.xrefs_from(self._view_instructions[row].address) if self._disasm else []
            if targets:
                self.navigate(targets[0].address)

    def _maybe_function(self, address: int) -> bool:
        """Only treat an immediate as a jump target when it can be mapped."""
        if self._disasm is None:
            return False
        return self._disasm.addrmap.to_offset(address) is not None

    # ------------------------------------------------------------ navigation
    def _push_history(self, address: int) -> None:
        if self._history and self._history_pos >= 0 and self._history[self._history_pos] == address:
            return
        self._history = self._history[: self._history_pos + 1]
        self._history.append(address)
        self._history_pos = len(self._history) - 1
        self._update_nav_buttons()

    def _update_nav_buttons(self) -> None:
        back, fwd = self._nav_buttons
        back.setEnabled(self._history_pos > 0)
        fwd.setEnabled(self._history_pos < len(self._history) - 1)

    def _go_back(self) -> None:
        if self._history_pos > 0:
            self._history_pos -= 1
            self.navigate(self._history[self._history_pos], record=False)

    def _go_forward(self) -> None:
        if self._history_pos < len(self._history) - 1:
            self._history_pos += 1
            self.navigate(self._history[self._history_pos], record=False)

    def _jump_entered(self) -> None:
        text = self._jump_edit.text().strip()
        try:
            address = int(text, 16)
        except ValueError:
            self._status_label.setText(f"⚠ '{text}' is not a hex address")
            return
        self._jump_edit.clear()
        self.navigate(address)

    def _reload_view(self) -> None:
        if self._view_instructions:
            anchor = self._view_start
            self.navigate(anchor, record=False)

    # ---------------------------------------------------------- context menu
    def _context_menu(self, pos: Any) -> None:
        row = self._disasm_table.rowAt(pos.y())
        if row < 0 or row >= len(self._view_instructions):
            return
        ins = self._view_instructions[row]
        menu = QMenu(self._panel)
        menu.addAction("Copy address", lambda: _copy(hex(ins.address)))
        menu.addAction("Copy bytes", lambda: _copy(ins.bytes_hex))
        menu.addAction("Copy instruction", lambda: _copy(ins.text()))
        menu.addSeparator()
        menu.addAction("Comment…", lambda: self._comment_dialog(ins.address))
        menu.addAction("Rename symbol…", lambda: self._rename_dialog(ins.address))
        menu.addSeparator()
        bp_here = ins.address in self._breakpoint_addrs
        menu.addAction(
            ("Remove breakpoint" if bp_here else "Toggle breakpoint here"),
            lambda: self._request_bp_toggle(ins.address),
        )
        menu.exec(self._disasm_table.viewport().mapToGlobal(pos))

    def _comment_dialog(self, address: int) -> None:
        session = getattr(self.ctx, "session", None)
        if session is None:
            self._status_label.setText("⚠ No session — cannot comment")
            return
        existing = session.comment_at(address) or ""
        text, ok = QInputDialog.getMultiLineText(
            self._panel, "Comment", f"Comment at {hex(address)}:", existing
        )
        if not ok:
            return
        session.set_comment(address, text)
        session.save_annotations()
        self._fill_view()

    def _rename_dialog(self, address: int) -> None:
        session = getattr(self.ctx, "session", None)
        if session is None:
            self._status_label.setText("⚠ No session — cannot rename")
            return
        # renaming applies to the containing function (or the raw address)
        target = address
        original = self._display_name(address, f"sub_{address:x}")
        if self._index is not None:
            for func in self._index.functions:
                if func.address <= address < func.address + max(func.size, 1):
                    target = func.address
                    original = self._display_name(func.address, func.name)
                    break
        name, ok = QInputDialog.getText(
            self._panel, "Rename symbol", f"New name for { hex(target) } ({original}):", text=original
        )
        if not ok:
            return
        session.rename_symbol(target, name)
        session.save_annotations()
        self._refill_functions()
        self._fill_view()

    # ----------------------------------------------------------------- reset
    def _reset(self) -> None:
        self._model = None
        self._disasm = None
        self._index = None
        self._all_functions = []
        self._view_instructions = []
        self._view_name = ""
        self._view_start = 0
        self._current_function = None
        self._history = []
        self._history_pos = -1
        self._pending_view += 1  # invalidate in-flight workers
        self._pc_address = None
        self._breakpoint_addrs.clear()
        self._func_table.setRowCount(0)
        self._disasm_table.setRowCount(0)
        self._xref_table.setRowCount(0)
        self._att_check.setEnabled(False)
        self._att_check.blockSignals(True)
        self._att_check.setChecked(False)
        self._att_check.blockSignals(False)
        self._status_label.setText("No binary loaded")
        self._update_nav_buttons()


def _copy(text: str) -> None:
    """Clipboard helper that works without a focused widget."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is not None:
        clipboard = app.clipboard()
        if clipboard is not None:
            clipboard.setText(text)


def _color_for(mnemonic: str, tokens: dict[str, str]) -> str | None:
    """Token color per instruction class (semantic — NOT the accent badge)."""
    if mnemonic == "call":
        return tokens.get("warn")
    if mnemonic.startswith("j"):
        return tokens.get("accent")
    if mnemonic in ("ret", "hlt", "iret", "leave", "ud2"):
        return tokens.get("error")
    if mnemonic in ("nop", "endbr64", "endbr32"):
        return tokens.get("dim")
    return None  # default foreground
