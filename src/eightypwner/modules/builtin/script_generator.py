# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Exploit Script Generator dock (Step 9 A).

Turns the current binary + libc + gadget scan + crash offset into a
ready-to-run pwntools script. Everything is filled in as it becomes available
on the bus, so the flow is: load binary → scan gadgets → pattern lookup →
pick a template → Generate → Copy/Save.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import BINARY_CLOSED, BINARY_LOADED
from eightypwner.engines.script_gen import ExploitContext, generate
from eightypwner.modules.builtin.common import copy_text, mono_font, parse_int
from eightypwner.modules.builtin.gadget_finder import GADGET_SCAN_RESULT
from eightypwner.modules.builtin.libc_helper import LIBC_BASE_COMPUTED, LIBC_LOADED
from eightypwner.modules.builtin.pattern_tool import PATTERN_LOOKUP_RESULT
from eightypwner.modules.interface import Plugin

log = logging.getLogger(__name__)

TEMPLATE_LABELS = {
    "skeleton": "Skeleton — clean pwntools harness",
    "ret2win": "ret2win — jump to win/flag",
    "ret2libc": "ret2libc — puts leak → system",
    "shellcode": "shellcode — NX-off / mprotect",
}


class ScriptGeneratorPlugin(Plugin):
    name = "Script Generator"
    description = (
        "Generate a pwntools exploit from the loaded binary, libc, gadgets and "
        "the crash offset found by Pattern Tool."
    )
    icon = "🧾"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._panel: QWidget | None = None
        self._ctx = ExploitContext()
        self._model: Any = None
        self._libc_info: Any = None

    # ------------------------------------------------------------------ widget
    def widget(self) -> QWidget:
        if self._panel is not None:
            return self._panel
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(4)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        self._template = QComboBox()
        for key, label in TEMPLATE_LABELS.items():
            self._template.addItem(label, key)
        self._template.currentIndexChanged.connect(lambda _i: self._refresh_preview())
        form.addRow("Template:", self._template)

        self._offset = QLineEdit()
        self._offset.setPlaceholderText("crash offset (auto from Pattern Tool)")
        self._offset.textChanged.connect(self._offset_changed)
        form.addRow("Offset:", self._offset)

        libc_row = QWidget()
        libc_layout = QHBoxLayout(libc_row)
        libc_layout.setContentsMargins(0, 0, 0, 0)
        self._libc_path = QLineEdit()
        self._libc_path.setPlaceholderText("libc.so.6 (auto from Libc Helper)")
        self._libc_path.textChanged.connect(self._libc_changed)
        libc_layout.addWidget(self._libc_path, 1)
        browse = QPushButton("…")
        browse.setMaximumWidth(30)
        browse.clicked.connect(self._browse_libc)
        libc_layout.addWidget(browse)
        form.addRow("Libc:", libc_row)

        host_row = QWidget()
        host_layout = QHBoxLayout(host_row)
        host_layout.setContentsMargins(0, 0, 0, 0)
        self._host = QLineEdit("127.0.0.1")
        self._host.setMaximumWidth(160)
        host_layout.addWidget(self._host)
        host_layout.addWidget(QLabel(":"))
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(1337)
        host_layout.addWidget(self._port)
        host_layout.addStretch(1)
        form.addRow("Remote:", host_row)
        outer.addLayout(form)

        actions = QHBoxLayout()
        generate_button = QPushButton("Generate")
        generate_button.setToolTip("Render the script from current context")
        generate_button.clicked.connect(self._generate)
        actions.addWidget(generate_button)
        self._copy_button = QPushButton("Copy")
        self._copy_button.clicked.connect(self._copy)
        actions.addWidget(self._copy_button)
        self._save_button = QPushButton("Save as…")
        self._save_button.clicked.connect(self._save)
        actions.addWidget(self._save_button)
        actions.addStretch(1)
        self._status = QLabel("Load a binary to begin.")
        self._status.setWordWrap(True)
        actions.addWidget(self._status, 1)
        outer.addLayout(actions)

        self._preview = QPlainTextEdit()
        self._preview.setFont(mono_font(self.ctx.settings))
        self._preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._preview.setPlaceholderText(
            "The generated pwntools script appears here — Generated by 80PWNER."
        )
        outer.addWidget(self._preview, 1)
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
        if topic == BINARY_LOADED and isinstance(payload, dict):
            model = payload.get("model")
            if model is not None:
                self._model = model
                self._ctx = ExploitContext.from_model(model)
                self._ctx.host = self._host.text().strip() or "127.0.0.1"
                self._ctx.port = int(self._port.value())
                self._status.setText(
                    f"{getattr(model, 'name', 'binary')}: "
                    f"{len(self._ctx.functions)} named symbols, "
                    f"{sum(1 for v in self._ctx.functions.values() if v)} addresses."
                )
                self._refresh_preview()
            return
        if topic == BINARY_CLOSED:
            self._model = None
            self._ctx = ExploitContext()
            self._preview.clear()
            self._status.setText("Binary closed.")
            return
        if topic == LIBC_LOADED and isinstance(payload, dict):
            info = payload.get("info")
            if info is not None:
                self._libc_info = info
                self._ctx.libc_path = str(info.path)
                self._ctx.libc_version = info.version
                self._ctx.libc_symbols = dict(info.symbols)
                self._ctx.libc_binsh = info.binsh
                self._ctx.libc_one_gadgets = [g.as_text() for g in info.one_gadgets]
                self._libc_path.setText(str(info.path))
                self._refresh_preview()
            return
        if topic == LIBC_BASE_COMPUTED and isinstance(payload, dict):
            base = payload.get("base")
            if isinstance(base, int):
                # The generated script derives the base from its own leak; the
                # computed value is noted for the operator in the preview.
                self._status.setText(f"Libc base from leak: {base:#x} (used as a sanity check).")
            return
        if topic == GADGET_SCAN_RESULT and isinstance(payload, dict):
            if payload.get("state") != "done":
                return
            gadgets = list(payload.get("gadgets") or ())
            from eightypwner.engines.ropchain import find_exact, find_pop_ret

            pop_rdi = find_pop_ret(gadgets, "rdi")
            ret = find_exact(gadgets, "ret")
            if pop_rdi is not None:
                self._ctx.gadgets["pop rdi"] = int(pop_rdi.address)
            if ret is not None:
                self._ctx.gadgets["ret"] = int(ret.address)
            if pop_rdi is not None or ret is not None:
                self._refresh_preview()
            return
        if topic == PATTERN_LOOKUP_RESULT and isinstance(payload, dict):
            offset = payload.get("offset")
            if isinstance(offset, int) and offset > 0:
                self._ctx.crash_offset = offset
                if not self._offset.text().strip():
                    self._offset.setText(str(offset))
                self._refresh_preview()

    # ------------------------------------------------------------------ inputs
    def _offset_changed(self, text: str) -> None:
        self._ctx.crash_offset = parse_int(text)
        self._refresh_preview()

    def _libc_changed(self, text: str) -> None:
        self._ctx.libc_path = text.strip()
        self._refresh_preview()

    def _browse_libc(self) -> None:
        start = str(Path("/lib"))
        path, _filter = QFileDialog.getOpenFileName(
            self._panel, "Choose libc", start, "ELF libraries (libc.so* *.so*);;All files (*)"
        )
        if path:
            self._libc_path.setText(path)

    def _template_key(self) -> str:
        return str(self._template.currentData() or "skeleton")

    # ----------------------------------------------------------------- render
    def _refresh_preview(self) -> None:
        if self._panel is None:
            return
        self._ctx.host = self._host.text().strip() or "127.0.0.1"
        self._ctx.port = int(self._port.value())
        try:
            text = generate(self._ctx, self._template_key())
        except Exception as exc:  # pragma: no cover — defensive
            log.exception("script generation failed")
            self._status.setText(f"⚠ {exc}")
            return
        self._preview.setPlainText(text)

    def _generate(self) -> None:
        self._refresh_preview()
        lines = self._preview.toPlainText().count("\n")
        missing = []
        if not self._ctx.crash_offset:
            missing.append("crash offset (Pattern Tool)")
        if self._template_key() in ("ret2libc", "shellcode") and not self._ctx.libc_path:
            missing.append("libc path (Libc Helper)")
        note = f" — add {', '.join(missing)}" if missing else ""
        self._status.setText(f"Generated {lines} lines{note}.")

    def _copy(self) -> None:
        text = self._preview.toPlainText()
        if not text.strip():
            self._status.setText("Nothing to copy — hit Generate first.")
            return
        copy_text(text)
        self._status.setText("Script copied to the clipboard.")

    def _save(self) -> None:
        text = self._preview.toPlainText()
        if not text.strip():
            self._status.setText("Nothing to save — hit Generate first.")
            return
        name = (self._ctx.binary_name or "exploit").replace(".", "_")
        path, _filter = QFileDialog.getSaveFileName(
            self._panel, "Save exploit", f"exploit_{name}.py", "Python (*.py)"
        )
        if not path:
            return
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError as exc:
            self._status.setText(f"⚠ Could not save: {exc}")
            return
        self._status.setText(f"Saved {path}")
