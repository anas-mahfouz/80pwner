# 80PWNER — by Anas Mahfouz (The80)

"""Debugger module (Step 4): docked GDB/MI panels over the :mod:`gdb_mi` engine.

Toolbar actions (Run/Continue/Step Into/Step Over/Finish/Stop/Restart) push
non-blocking commands; every engine event (worker thread) comes back through
the raw bus and UiBus delivers it here on the UI thread. When gdb is missing
(non-Linux or not installed) the panels are disabled with a clear message and
all static modules keep working.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import (
    ADDRESS_SELECTED,
    BINARY_CLOSED,
    BINARY_LOADED,
)
from eightypwner.engines.gdb_mi import (
    T_BP_ADDED,
    T_BP_REMOVED,
    T_BP_TOGGLE_REQUEST,
    T_BP_UPDATED,
    T_DIED,
    T_ERROR,
    T_EXITED,
    T_MEMORY_READ,
    T_OUTPUT,
    T_PROGRAM_OUTPUT,
    T_REGISTERS,
    T_STACK_WORDS,
    T_STARTED,
    T_STATE,
    T_STOPPED,
)
from eightypwner.modules.interface import Plugin
from eightypwner.platform.debuggers import gdb_status
from eightypwner.ui.fonts import resolve_monospace

if TYPE_CHECKING:
    from eightypwner.engines.gdb_mi import GdbEngine

log = logging.getLogger(__name__)

DBG_UNAVAILABLE = "debugger_unavailable"
MAX_LOG_LINES = 8000
MEM_BYTES_PER_ROW = 16
STACK_BYTES = 192  # auto window requested on every stop (matches the engine)


class DebuggerPlugin(Plugin):
    """Docked live-debugging panel (gdb/MI on Linux; degraded elsewhere)."""

    name = "Debugger"
    description = "Live GDB/MI debugging: registers, stack, memory, breakpoints."
    icon = "🐞"

    # ---------------------------------------------------------------- widget
    def widget(self) -> QWidget:
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)
        self._mono = QFont(resolve_monospace(self.ctx.settings.get("font.mono_family") or ""))
        self._engine: GdbEngine | None = None
        self._engine_unavailable = ""
        self._state = "idle"  # idle|running|stopped|exited
        self._target_path: str | None = None
        self._selected_address: int | None = None  # ADDRESS_SELECTED sync w/ disasm
        self._populating = False  # ignore re-entrant table signals while filling
        self._breakpoints: dict[str, dict[str, Any]] = {}
        self._last_sp = ""

        outer.addLayout(self._build_toolbar())

        self._status = QLabel("No debugging session")
        self._status.setEnabled(False)
        outer.addWidget(self._status)

        self._tabs = QTabWidget()
        outer.addWidget(self._tabs, 1)
        self._build_registers_tab()
        self._build_stack_tab()
        self._build_memory_tab()
        self._build_breakpoints_tab()
        self._build_console_tab()
        self._build_stdio_tab()

        self._make_shortcuts()
        self._set_panel_enabled(False)
        return panel

    # ------------------------------------------------------------- toolbar
    def _build_toolbar(self) -> QHBoxLayout:
        bar = QHBoxLayout()

        def button(text: str, handler: Any, tip: str = "") -> QPushButton:
            btn = QPushButton(text)
            if tip:
                btn.setToolTip(tip)
            btn.clicked.connect(handler)
            bar.addWidget(btn)
            self._buttons[text] = btn
            return btn

        self._buttons: dict[str, Any] = {}
        button("Run…", self._run_dialog, "Start a debugging session (F5)")
        button("Attach…", self._attach_dialog, "Attach to a running program")
        button("Continue", self._continue, "F5 (while stopped) / Ctrl+F5 (start last config)")
        button("Step ⟶", self._step_into, "Step into (F11)")
        button("Next", self._step_over, "Step over (F10)")
        button("Finish", self._step_finish, "Step out of the current frame (Shift+F11)")
        button("Stop", self._stop, "Kill the debuggee")
        button("Restart", self._restart, "Kill + relaunch the same configuration")
        bar.addStretch(1)
        return bar

    # -------------------------------------------------------------- panels
    def _build_registers_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        first_row = QHBoxLayout()
        self._reg_filter = QLineEdit()
        self._reg_filter.setPlaceholderText("Filter registers…")
        self._reg_filter.setMaximumWidth(220)
        self._reg_filter.textChanged.connect(self._refill_registers)
        first_row.addWidget(QLabel("Registers (editable — Enter applies)"))
        first_row.addStretch(1)
        first_row.addWidget(self._reg_filter)
        layout.addLayout(first_row)

        self._reg_table = self._table(["Register", "Value"], final_stretch=1)
        self._reg_table.itemChanged.connect(self._register_edited)
        layout.addWidget(self._reg_table)
        self._tabs.addTab(wrap, "Registers")

    def _build_stack_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self._stack_size = QSpinBox()
        self._stack_size.setRange(8, 512)
        self._stack_size.setValue(96)
        self._stack_size.setPrefix("bytes around $sp: ")
        self._stack_size.valueChanged.connect(self._stack_window_changed)
        head.addWidget(self._stack_size)
        head.addStretch(1)
        layout.addLayout(head)
        self._stack_table = self._table(["Address", "Value", "Annotated"], final_stretch=2)
        layout.addWidget(self._stack_table)
        self._tabs.addTab(wrap, "Stack")

    def _build_memory_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self._mem_goto = QLineEdit()
        self._mem_goto.setPlaceholderText("Go to: 0x… / $sp / $rip+16 — Enter")
        self._mem_goto.returnPressed.connect(self._memory_goto)
        head.addWidget(self._mem_goto, 1)
        self._mem_len = QComboBox()
        self._mem_len.addItems(["64", "128", "256", "512"])
        self._mem_len.setCurrentIndex(1)
        self._mem_len.currentTextChanged.connect(lambda _t: self._memory_refresh())
        head.addWidget(self._mem_len)
        layout.addLayout(head)

        cols = 2 + MEM_BYTES_PER_ROW + 1  # Address, bytes…, ASCII
        self._mem_table = QTableWidget(0, cols)
        self._mem_table.setFont(self._mono)
        self._mem_table.verticalHeader().setVisible(False)
        labels = ["Address", *[f"+{i:01x}" for i in range(MEM_BYTES_PER_ROW)], "ASCII"]
        self._mem_table.setHorizontalHeaderLabels(labels)
        self._mem_table.itemChanged.connect(self._memory_byte_edited)
        header = self._mem_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        layout.addWidget(self._mem_table)
        self._tabs.addTab(wrap, "Memory")

    def _build_breakpoints_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self._bp_addr = QLineEdit()
        self._bp_addr.setPlaceholderText("New bp: 0x…, fn-name, main — Enter")
        self._bp_addr.returnPressed.connect(self._bp_add_clicked)
        head.addWidget(self._bp_addr, 1)
        layout.addLayout(head)
        self._bp_table = self._table(["#", "Address", "Function", "Enabled"], final_stretch=2)
        self._bp_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._bp_table)
        btn_row = QHBoxLayout()
        for label, handler in (
            ("Enable", lambda: self._bp_enable(True)),
            ("Disable", lambda: self._bp_enable(False)),
            ("Delete", self._bp_delete),
            ("Clear all", self._bp_clear_all),
        ):
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            btn_row.addWidget(btn)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)
        self._tabs.addTab(wrap, "Breakpoints")

    def _build_console_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setFont(self._mono)
        self._console.setMaximumBlockCount(MAX_LOG_LINES)
        layout.addWidget(self._console, 1)
        input_row = QHBoxLayout()
        self._console_input = QLineEdit()
        self._console_input.setPlaceholderText(
            "GDB command — MI (-break-list) or plain c / info locals → Enter"
        )
        self._console_input.returnPressed.connect(self._console_send)
        self._console_btn = QPushButton("Send")
        self._console_btn.clicked.connect(self._console_send)
        input_row.addWidget(self._console_input, 1)
        input_row.addWidget(self._console_btn)
        layout.addLayout(input_row)
        self._tabs.addTab(wrap, "GDB")

    def _build_stdio_tab(self) -> None:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        self._stdio = QPlainTextEdit()
        self._stdio.setReadOnly(True)
        self._stdio.setFont(self._mono)
        self._stdio.setMaximumBlockCount(MAX_LOG_LINES)
        layout.addWidget(self._stdio, 1)
        input_row = QHBoxLayout()
        self._stdio_input = QLineEdit()
        self._stdio_input.setPlaceholderText("Send text to the debuggee's stdin → Enter")
        self._stdio_input.returnPressed.connect(self._stdio_send)
        self._stdio_btn = QPushButton("Send")
        self._stdio_btn.clicked.connect(self._stdio_send)
        input_row.addWidget(self._stdio_input, 1)
        input_row.addWidget(self._stdio_btn)
        layout.addLayout(input_row)
        self._tabs.addTab(wrap, "Program I/O")

    def _table(self, headers: list[str], final_stretch: int = 1) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setFont(self._mono)
        table.setAlternatingRowColors(True)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(final_stretch > 1)
        return table

    # ------------------------------------------------------------- shortcuts
    def _make_shortcuts(self) -> None:
        panel = self._panel
        for sequence, target in (
            ("F5", self._play_or_continue),
            ("F9", self._toggle_bp_at_selection),
            ("F10", self._step_over),
            ("F11", self._step_into),
            ("Shift+F11", self._step_finish),
        ):
            shortcut = QShortcut(QKeySequence(sequence), panel)
            shortcut.activated.connect(target)

    # -------------------------------------------------------------- engine
    def _ensure_engine(self) -> bool:
        """Create the engine (checking for gdb once); False → message shown."""
        if self._engine is not None:
            return True
        status = gdb_status()
        if not status.available:
            self._engine_unavailable = (
                f"gdb was not found.\n{status.hint}\n"
                "The debugger panel stays disabled; every static module works."
            )
        else:
            with contextlib.suppress(Exception):
                self._mk_engine()
        if self._engine is None:
            self._mark_unavailable()
            return False
        return True

    def _mk_engine(self) -> None:
        from eightypwner.engines.gdb_mi import GdbEngine

        def emit(topic: str, payload: Any) -> None:
            # worker thread → raw bus; subscribers use ui_bus (UI thread)
            self.ctx.bus.publish(topic, payload)

        self._engine = GdbEngine(emit)
        self._state = "idle"
        self._set_panel_enabled(True)

    def _mark_unavailable(self) -> None:
        for button in self._buttons.values():
            button.setEnabled(False)
        self._console_input.setEnabled(False)
        self._console_btn.setEnabled(False)
        self._stdio_input.setEnabled(False)
        self._stdio_btn.setEnabled(False)
        self._status.setText(f"⚠ {self._engine_unavailable or 'gdb unavailable'}")
        self._status.setEnabled(True)
        self.ctx.bus.publish(DBG_UNAVAILABLE, {"reason": self._engine_unavailable})

    def _mark_available(self) -> None:
        for button in self._buttons.values():
            button.setEnabled(True)
        self._console_input.setEnabled(True)
        self._console_btn.setEnabled(True)
        self._stdio_input.setEnabled(True)
        self._stdio_btn.setEnabled(True)

    def _set_panel_enabled(self, enabled: bool) -> None:
        self._console_input.setEnabled(enabled)
        self._console_btn.setEnabled(enabled)
        self._stdio_input.setEnabled(enabled)
        self._stdio_btn.setEnabled(enabled)
        self._mem_goto.setEnabled(enabled)
        self._bp_addr.setEnabled(enabled)
        self._reg_filter.setEnabled(enabled)
        self._update_state_buttons()

    # ------------------------------------------------------------ run dialogs
    def _run_dialog(self) -> None:
        if not self._ensure_engine():
            return
        dialog = RunDialog(self._panel, str(self._target_path or ""))
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        config = dialog.config()
        self.start_session(config)

    def start_session(self, config: dict[str, Any]) -> None:
        """Start (or restart) the engine with a run configuration."""
        target = config.get("target", "")
        if not target:
            self._status.setText("⚠ Choose a binary to debug first (load it in the Binary Overview)")
            return
        if not self._ensure_engine():
            return
        engine = self._engine
        assert engine is not None
        try:
            engine.start_program(
                target,
                args=list(config.get("args") or []),
                stdin_file=config.get("stdin") or None,
                env=dict(config.get("env") or {}),
                cwd=config.get("cwd") or None,
            )
        except Exception as exc:
            self._status.setText(f"⚠ {exc}")
            return
        self._run_config = dict(config)
        if config.get("break_entry", True):
            engine.set_breakpoint("main")
        engine.run()
        self._stdio.clear()
        self._console.clear()

    def _attach_dialog(self) -> None:
        if not self._ensure_engine():
            return
        pid, ok = QInputDialog.getInt(
            self._panel, "Attach to process", "PID:", 0, 1, 0xFFFFFFFF
        )
        if not ok or pid <= 0:
            return
        engine = self._engine
        assert engine is not None
        engine.attach(pid, target_path=self._target_path)
        self._state = "stopped"
        self._update_state_buttons()

    def _restart(self) -> None:
        engine = self._engine
        if engine is None:
            return
        if getattr(self, "_run_config", None):
            self.start_session(dict(self._run_config))
        else:
            engine.restart()

    def _play_or_continue(self) -> None:
        engine = self._engine
        if engine is None:
            self._run_dialog()
            return
        if self._state == "stopped":
            self._continue()
        elif self._state in ("idle", "exited"):
            self._restart()

    def _continue(self) -> None:
        if self._engine is not None:
            self._engine.continue_()

    def _step_into(self) -> None:
        if self._engine is not None:
            self._engine.step_into()

    def _step_over(self) -> None:
        if self._engine is not None:
            if self._state == "stopped":
                self._engine.step_over()
            else:
                self._status.setText("⏳ Start/continue the session first")

    def _step_finish(self) -> None:
        if self._engine is None:
            return
        self._engine.step_finish()

    def _stop(self) -> None:
        engine = self._engine
        if engine is None:
            return
        engine.stop_program()
        engine.shutdown()
        self._engine = None
        self._state = "exited"
        self._status.setText("Session stopped")
        self._update_state_buttons()

    def _toggle_bp_at_selection(self) -> None:
        """F9 — toggle a breakpoint at the disassembly cursor."""
        if self._engine is None:
            return
        if self._selected_address is None:
            self._status.setText("⚠ Select an instruction in the Disassembler first")
            return
        self._engine.toggle_breakpoint(self._selected_address)

    def _bp_add_clicked(self) -> None:
        text = self._bp_addr.text().strip()
        if not text or self._engine is None:
            return
        self._bp_addr.clear()
        try:
            where: int | str = int(text, 16) if text.lower().startswith("0x") else text
        except ValueError:
            where = text
        self._engine.set_breakpoint(where)

    def _stack_window_changed(self, size: int) -> None:
        if self._engine is not None and self._state == "stopped":
            self._engine.read_stack_words(size // 8)

    def _memory_goto(self) -> None:
        self._memory_refresh()

    def _memory_refresh(self) -> None:
        """Go-to box: '0x…', '$sp', '$sp+16', '$rip'; empty → last selection."""
        if self._engine is None:
            return
        text = self._mem_goto.text().strip()
        address: int | None = None
        if text.startswith("$"):
            expr = text[1:]  # e.g. "sp" or "sp+16"
            base_name, _sep, offset_text = expr.partition("+")
            base = self._eval_reg(base_name)
            if base is not None and offset_text.strip():
                with contextlib.suppress(ValueError):
                    base += int(offset_text.strip().lstrip("0x"), 0)
            address = base
        else:
            with contextlib.suppress(ValueError):
                address = int(text, 16) if text else None
        if address is None:
            address = self._selected_address
        if address is None:
            self._status.setText("⚠ Type a hex address, or read a register as $sp")
            return
        size = int(self._mem_len.currentText())
        self._read_memory_view(address, size)

    def _eval_reg(self, expr: str) -> int | None:
        """Resolve things like 'sp+16' via the engine's register snapshot."""
        reg = getattr(self, "_registers", {}) or {}
        name = f"${expr.split('+')[0].strip()}"
        text = reg.get(name, "")
        with contextlib.suppress(ValueError):
            return int(text, 16)
        return None

    def _read_memory_view(self, address: int, size: int) -> None:
        if self._engine is not None:
            self._mem_goto.setText(hex(address))
            self._engine.read_memory(address, size)
            self._pending_mem = (address, size)

    # ------------------------------------------------------------ lifecycle
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
        engine = self._engine
        if engine is not None:
            engine.shutdown()
            self._engine = None

    # ---------------------------------------------------------------- events
    def on_event(self, topic: str, payload: Any) -> None:
        if topic == BINARY_LOADED and isinstance(payload, dict):
            model = payload.get("model")
            if model is not None:
                self._target_path = str(model.path)
            return
        if topic == BINARY_CLOSED:
            self._target_path = None
            return
        if topic == ADDRESS_SELECTED and isinstance(payload, dict):
            with contextlib.suppress(TypeError, ValueError):
                self._selected_address = int(payload.get("address", 0))
            return
        if topic == T_BP_TOGGLE_REQUEST and isinstance(payload, dict):
            if self._engine is not None:
                with contextlib.suppress(TypeError, ValueError):
                    address = int(payload.get("address", 0))
                    self._engine.toggle_breakpoint(address)
            return

        if topic == T_ERROR and isinstance(payload, dict):
            self._status.setText(f"⚠ {payload.get('message', 'debugger error')}")
            return
        if topic == T_DIED:
            self._state = "exited"
            self._update_state_buttons()
            self._status.setText("⚠ gdb died — see the GDB console tab")
            return
        if topic == T_STATE and isinstance(payload, dict):
            self._state = str(payload.get("state", self._state))
            self._update_state_buttons()
            return
        if topic == T_STARTED and isinstance(payload, dict):
            self._status.setText(f"Session on {payload.get('target', '?')}")
            self._clear_dynamic()
            return
        if topic == T_EXITED and isinstance(payload, dict):
            code = payload.get("exit_code")
            self._state = "exited"
            self._update_state_buttons()
            self._status.setText(
                "Debuggee exited normally" if code in (0, None) else f"Debuggee exited ({code})"
            )
            return
        if topic == T_STOPPED and isinstance(payload, dict):
            self._on_stopped(payload)
            return
        if topic == T_REGISTERS and isinstance(payload, dict):
            self._on_registers(payload)
            return
        if topic == T_STACK_WORDS and isinstance(payload, dict):
            self._on_stack_words(payload)
            return
        if topic == T_MEMORY_READ and isinstance(payload, dict):
            self._on_memory_read(payload)
            return
        if topic in (T_BP_UPDATED, T_BP_ADDED, T_BP_REMOVED):
            self._on_breakpoints(topic, payload)
            return
        if topic == T_OUTPUT and isinstance(payload, dict):
            stream = payload.get("stream", "console")
            text = str(payload.get("text", ""))
            self._append_log(self._console, text, color="program" if stream == "program" else None)
            return
        if topic == T_PROGRAM_OUTPUT and isinstance(payload, dict):
            self._append_log(self._stdio, str(payload.get("text", "")), color=None)

    # ------------------------------------------------------------- handlers
    def _on_stopped(self, payload: dict[str, Any]) -> None:
        self._state = "stopped"
        self._update_state_buttons()
        bits = []
        reason = payload.get("reason") or ""
        if reason == "breakpoint-hit":
            bits.append("Breakpoint")
        elif payload.get("signal"):
            bits.append(f"Signal {payload['signal']}")
        else:
            bits.append(reason or "Stopped")
        frame = payload.get("frame") or {}
        if frame.get("func"):
            bits.append(f"in {frame['func']}")
        if frame.get("line"):
            bits.append(f"@{frame['line']}")
        bits.append(f"pc={payload.get('pc', '?')}")
        self._status.setText(" · ".join(str(b) for b in bits))
        # the engine bundles registers with every stop — route them to the table
        if payload.get("regs"):
            self._on_registers(
                {
                    "values": payload.get("regs"),
                    "changed": payload.get("changed") or [],
                    "pc": payload.get("pc", ""),
                    "sp": payload.get("sp", ""),
                }
            )

    def _on_registers(self, payload: dict[str, Any]) -> None:
        values = payload.get("values") or {}
        changed = set(payload.get("changed") or [])
        tokens = self._tokens()
        self._remember_registers(values)
        self._fill_registers(values, changed, tokens)

    def _remember_registers(self, values: dict[str, str]) -> None:
        self._registers = dict(values)

    def _fill_registers(self, values: dict[str, str], changed: set[str], tokens: dict[str, str]) -> None:
        table = self._reg_table
        table.blockSignals(True)
        try:
            rows = [
                (name, value) for name, value in sorted(values.items())
                if self._reg_match(name)
            ]
            table.setRowCount(len(rows))
            highlight = QColor(tokens.get("warn", "#FFB454"))
            pc, sp = "$rip", "$rsp"
            for row, (name, value) in enumerate(rows):
                name_item = QTableWidgetItem(name)
                name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if name in (pc, sp):
                    name_item.setForeground(QColor(tokens["accent"]))
                table.setItem(row, 0, name_item)
                value_item = QTableWidgetItem(str(value))
                if name in changed:
                    value_item.setBackground(highlight)
                    value_item.setToolTip("Changed since the previous stop")
                table.setItem(row, 1, value_item)
        finally:
            table.blockSignals(False)

    def _reg_match(self, name: str) -> bool:
        needle = self._reg_filter.text().strip().lstrip("$")
        return not needle or needle in name.lstrip("$")

    def _refill_registers(self) -> None:
        self._fill_registers(
            getattr(self, "_registers", {}), set(), self._tokens()
        )

    def _register_edited(self, item: QTableWidgetItem) -> None:
        if self._populating or self._engine is None:
            return
        row = item.row() if item is not None else self._reg_table.currentRow()
        if row < 0:
            return
        name_item = self._reg_table.item(row, 0)
        if name_item is None:
            return
        name = str(name_item.text()).lstrip("$")
        self._engine.write_register(name, item.text().strip())
        self._status.setText(f"Set {name} = {item.text().strip()}")

    def _on_stack_words(self, payload: dict[str, Any]) -> None:
        tokens = self._tokens()
        self._last_sp = str(payload.get("sp", ""))
        table = self._stack_table
        table.blockSignals(True)
        try:
            rows = payload.get("words") or []
            table.setRowCount(len(rows))
            accent = QColor(tokens["accent"])
            dim = QColor(tokens.get("dim", "#9AA8A2"))
            ok_color = QColor(tokens.get("ok", "#34D399"))
            for row, info in enumerate(rows):
                address, word = str(info.get("address")), str(info.get("word_hex", ""))
                is_sp = bool(info.get("is_sp"))
                address_item = QTableWidgetItem(address)
                value_item = QTableWidgetItem(word)
                annotate = ""
                if is_sp:
                    annotate = "$sp — stack top"
                elif word.startswith("00007fff") or word.startswith("000000000040"):
                    annotate = "ptr?"
                for item in (address_item, value_item):
                    if is_sp:
                        item.setForeground(accent)
                    elif annotate.startswith("ptr"):
                        item.setForeground(ok_color)
                    else:
                        item.setForeground(dim)
                annotate_item = QTableWidgetItem(annotate)
                if is_sp:
                    annotate_item.setForeground(accent)
                table.setItem(row, 0, address_item)
                table.setItem(row, 1, value_item)
                table.setItem(row, 2, annotate_item)
        finally:
            table.blockSignals(False)

    def _on_memory_read(self, payload: dict[str, Any]) -> None:
        table = self._mem_table
        expected = getattr(self, "_pending_mem", None)
        if expected is not None:
            address, _size = expected
            if int(payload.get("address", "0x0"), 16) != address:
                return  # some other read (stack window) — not the hex view
        try:
            begin = int(str(payload.get("address", "0x0")), 16)
            data = bytes.fromhex(str(payload.get("hex", "")))
        except ValueError:
            return
        if not data:
            return
        rows = (len(data) + MEM_BYTES_PER_ROW - 1) // MEM_BYTES_PER_ROW
        table.blockSignals(True)
        try:
            table.setRowCount(rows)
            for row in range(rows):
                row_addr = begin + row * MEM_BYTES_PER_ROW
                chunk = data[row * MEM_BYTES_PER_ROW : (row + 1) * MEM_BYTES_PER_ROW]
                address_item = QTableWidgetItem(hex(row_addr))
                address_item.setFlags(address_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, 0, address_item)
                for i in range(MEM_BYTES_PER_ROW):
                    cell = QTableWidgetItem()
                    if i < len(chunk):
                        cell.setText(format(chunk[i], "02x"))
                        cell.setToolTip(f"byte {hex(row_addr + i)}")
                    else:
                        cell.setFlags(cell.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    table.setItem(row, 1 + i, cell)
                ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                ascii_item = QTableWidgetItem(ascii_text)
                ascii_item.setFlags(ascii_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, 1 + MEM_BYTES_PER_ROW, ascii_item)
        finally:
            table.blockSignals(False)

    def _memory_byte_edited(self, item: QTableWidgetItem) -> None:
        """A byte cell was rewritten → write one byte at its address."""
        if self._populating:
            return
        row, col = item.row(), item.column()
        if col < 1 or col > MEM_BYTES_PER_ROW:
            return
        address_cell = self._mem_table.item(row, 0)
        if address_cell is None:
            return
        try:
            value = int(item.text().strip(), 16)
            address = int(address_cell.text(), 16) + (col - 1)
        except ValueError:
            return
        if not (0 <= value <= 0xFF) or self._engine is None:
            return
        self._engine.write_memory(address, bytes([value]))
        self._engine.read_memory(address & ~0xF, 16)  # refresh the row
        self._status.setText(f"Wrote {value:02x} at {hex(address)}")

    def _on_breakpoints(self, topic: str, payload: Any) -> None:
        if topic == T_BP_UPDATED and isinstance(payload, dict):
            rows = payload.get("breakpoints") or []
            self._breakpoints = {str(row["number"]): row for row in rows}
        elif topic in (T_BP_ADDED,) and isinstance(payload, dict):
            number = str(payload.get("number"))
            self._breakpoints.setdefault(number, dict(payload))
        elif topic == T_BP_REMOVED and isinstance(payload, dict):
            self._breakpoints.pop(str(payload.get("number")), None)
        self._fill_bp_table()

    def _fill_bp_table(self) -> None:
        table = self._bp_table
        table.setRowCount(len(self._breakpoints))
        for row, info in enumerate(self._breakpoints.values()):
            values = (
                str(info.get("number", "")),
                str(info.get("address", "")),
                str(info.get("func", "")),
                "yes" if info.get("enabled", True) else "no",
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, col, item)

    def _current_bp_number(self) -> str | None:
        items = self._bp_table.selectedItems()
        if not items:
            return None
        number_item = self._bp_table.item(items[0].row(), 0)
        return str(number_item.text()) if number_item is not None else None

    def _bp_enable(self, enabled: bool) -> None:
        if self._engine is None:
            return
        number = self._current_bp_number()
        if number is not None:
            self._engine.enable_breakpoint(number, enabled)

    def _bp_delete(self) -> None:
        if self._engine is None:
            return
        number = self._current_bp_number()
        if number is not None:
            self._engine.remove_breakpoint(number)

    def _bp_clear_all(self) -> None:
        if self._engine is None:
            return
        for number in list(self._breakpoints):
            self._engine.remove_breakpoint(number)

    def _console_send(self) -> None:
        if self._engine is None:
            return
        text = self._console_input.text().strip()
        if text:
            self._console_input.clear()
            self._engine.send_raw(text)

    def _stdio_send(self) -> None:
        if self._engine is None:
            return
        text = self._stdio_input.text()
        if text:
            self._stdio_input.clear()
            self._engine.program_stdin(text + "\n")

    # --------------------------------------------------------------- helpers
    def _update_state_buttons(self) -> None:
        if not hasattr(self, "_buttons"):
            return
        stopped = self._state == "stopped"
        labels = {
            "Continue": stopped,
            "Step ⟶": stopped,
            "Next": stopped,
            "Finish": stopped,
        }
        for label, enabled in labels.items():
            button = self._buttons.get(label)
            if button is not None:
                button.setEnabled(enabled)

    def _clear_dynamic(self) -> None:
        self._breakpoints.clear()
        self._fill_bp_table()
        self._stack_table.setRowCount(0)
        self._mem_table.setRowCount(0)
        self._console.clear()
        self._stdio.clear()

    def _tokens(self) -> dict[str, str]:
        theme = getattr(self.ctx, "theme", None)
        if theme is not None:
            return dict(theme.theme().tokens)
        from eightypwner.ui.theme import DARK_TOKENS

        return dict(DARK_TOKENS)

    def _append_log(self, view: QPlainTextEdit, text: str, color: str | None = None) -> None:
        """Append without a scrollbar dance and with a hard line budget."""
        view.appendPlainText(text.rstrip("\n"))


class RunDialog(QDialog):
    """Program arguments / stdin / environment / working directory picker."""

    def __init__(self, parent: QWidget | None, target: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Run program — 80PWNER debugger")
        self.setMinimumWidth(460)
        grid = QGridLayout(self)

        self._target = QLineEdit(target)
        browse = QPushButton("…")
        browse.clicked.connect(self._browse_target)
        grid.addWidget(QLabel("Binary"), 0, 0)
        grid.addWidget(self._target, 0, 1)
        grid.addWidget(browse, 0, 2)

        self._args = QLineEdit()
        self._args.setPlaceholderText("arguments…")
        grid.addWidget(QLabel("Arguments"), 1, 0)
        grid.addWidget(self._args, 1, 1, 1, 2)

        self._stdin = QLineEdit()
        stdin_browse = QPushButton("…")
        stdin_browse.clicked.connect(self._browse_stdin)
        self._stdin.setPlaceholderText("optional: a file plumbed to the program's stdin")
        grid.addWidget(QLabel("Stdin file"), 2, 0)
        grid.addWidget(self._stdin, 2, 1)
        grid.addWidget(stdin_browse, 2, 2)

        self._env = QPlainTextEdit()
        self._env.setPlaceholderText("environment, KEY=VALUE per line (optional)")
        self._env.setMaximumHeight(84)
        grid.addWidget(QLabel("Environment"), 3, 0)
        grid.addWidget(self._env, 3, 1, 1, 2)

        self._cwd = QLineEdit()
        self._cwd.setPlaceholderText("working directory (optional)")
        grid.addWidget(QLabel("Working dir"), 4, 0)
        grid.addWidget(self._cwd, 4, 1, 1, 2)

        self._break_entry = QCheckBox("Break at main")
        self._break_entry.setChecked(True)
        grid.addWidget(self._break_entry, 5, 1)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        grid.addWidget(buttons, 6, 0, 1, 3)

    def _browse_target(self) -> None:
        chosen, _f = QFileDialog.getOpenFileName(self, "Binary to debug")
        if chosen:
            self._target.setText(chosen)

    def _browse_stdin(self) -> None:
        chosen, _f = QFileDialog.getOpenFileName(self, "Stdin file")
        if chosen:
            self._stdin.setText(chosen)

    def config(self) -> dict[str, Any]:
        """Missing keys are simply absent — the panel treats them as defaults."""
        env: dict[str, str] = {}
        for line in self._env.toPlainText().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
        args = self._args.text().split()
        return {
            "target": self._target.text().strip(),
            "args": args,
            "stdin": self._stdin.text().strip(),
            "env": env,
            "cwd": self._cwd.text().strip(),
            "break_entry": self._break_entry.isChecked(),
        }
