# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Payload Studio dock — shellcode, encoders and format-string writes.

Three tabs, one workflow: write/assemble shellcode (with presets and bad-byte
checks), XOR-encode it behind a self-decoding stub, and plan ``%n`` arbitrary
writes for format-string bugs. Copy output in the format your exploit needs.
"""

from __future__ import annotations

import logging
from typing import Any

from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from eightypwner.engines.fmtstr import build_plan, find_marker
from eightypwner.engines.shellcode import (
    ARCHES,
    PRESETS,
    ShellcodeError,
    assemble,
    bad_byte_offsets,
    contains_bad,
    disassemble,
    encode_xor,
    format_bytes,
    parse_hex_bytes,
)
from eightypwner.modules.builtin.common import copy_text, make_table, mono_font, parse_int, set_row
from eightypwner.modules.interface import Plugin

log = logging.getLogger(__name__)

FORMATS = ("python", "escaped", "hex", "c", "c_string", "base64")


class PayloadStudioPlugin(Plugin):
    name = "Payload Studio"
    description = (
        "Assemble shellcode from presets or your own asm, XOR-encode it past "
        "bad bytes, and plan %n format-string writes."
    )
    icon = "🧪"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._panel: QWidget | None = None
        self._last_bytes: bytes = b""

    # ------------------------------------------------------------------ widget
    def widget(self) -> QWidget:
        if self._panel is not None:
            return self._panel
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(4)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_assembler(), "Assembler")
        self._tabs.addTab(self._build_encoder(), "Encoder")
        self._tabs.addTab(self._build_fmtstr(), "Format string")
        outer.addWidget(self._tabs, 1)

        self._status = QLabel(
            "Assemble → copy bytes, check bad bytes, or move to Encoder. "
            "Format-string tab plans %n writes from your offset."
        )
        self._status.setWordWrap(True)
        outer.addWidget(self._status)
        return panel

    # --------------------------------------------------------------- assembler
    def _build_assembler(self) -> QWidget:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)

        row = QHBoxLayout()
        row.addWidget(QLabel("Arch:"))
        self._arch = QComboBox()
        self._arch.addItems(ARCHES)
        row.addWidget(self._arch)
        row.addWidget(QLabel("Preset:"))
        self._preset = QComboBox()
        self._preset.addItem("— load a preset —", None)
        for preset in PRESETS:
            self._preset.addItem(preset.name, preset)
        self._preset.currentIndexChanged.connect(self._load_preset)
        row.addWidget(self._preset, 2)
        assemble_button = QPushButton("Assemble")
        assemble_button.clicked.connect(self._assemble)
        row.addWidget(assemble_button)
        layout.addLayout(row)

        self._asm = QPlainTextEdit()
        self._asm.setFont(mono_font(self.ctx.settings))
        self._asm.setPlaceholderText(
            "; Intel syntax for x86/x86-64 — e.g.\n; xor rsi, rsi\n; push rsi\n; ..."
        )
        layout.addWidget(self._asm, 2)

        bad_row = QHBoxLayout()
        bad_row.addWidget(QLabel("Bad bytes:"))
        self._bad = QLineEdit()
        self._bad.setPlaceholderText("00 0a 0d")
        self._bad.setMaximumWidth(160)
        self._bad.textChanged.connect(lambda _t: self._check_bad())
        bad_row.addWidget(self._bad)
        bad_row.addWidget(QLabel("Output:"))
        self._format = QComboBox()
        self._format.addItems(FORMATS)
        self._format.currentIndexChanged.connect(lambda _i: self._render_output())
        bad_row.addWidget(self._format)
        copy_button = QPushButton("Copy bytes")
        copy_button.clicked.connect(self._copy_output)
        bad_row.addWidget(copy_button)
        bad_row.addStretch(1)
        layout.addLayout(bad_row)

        self._asm_out = QLineEdit()
        self._asm_out.setReadOnly(True)
        self._asm_out.setFont(mono_font(self.ctx.settings))
        self._asm_out.setPlaceholderText("Assembled bytes")
        layout.addWidget(self._asm_out)

        self._disasm = make_table(["Address", "Bytes", "Instruction"], settings=self.ctx.settings)
        layout.addWidget(self._disasm, 1)
        return wrap

    # ----------------------------------------------------------------- encoder
    def _build_encoder(self) -> QWidget:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)

        row = QHBoxLayout()
        row.addWidget(QLabel("Payload (hex):"))
        self._enc_in = QLineEdit()
        self._enc_in.setFont(mono_font(self.ctx.settings))
        self._enc_in.setPlaceholderText("\\x90\\x90\\xc3 or 90 90 c3")
        row.addWidget(self._enc_in, 1)
        row.addWidget(QLabel("Bad:"))
        self._enc_bad = QLineEdit()
        self._enc_bad.setMaximumWidth(120)
        self._enc_bad.setPlaceholderText("00 0a")
        row.addWidget(self._enc_bad)
        row.addWidget(QLabel("Key:"))
        self._enc_key = QLineEdit()
        self._enc_key.setMaximumWidth(70)
        self._enc_key.setPlaceholderText("auto")
        row.addWidget(self._enc_key)
        encode = QPushButton("Encode")
        encode.clicked.connect(self._encode)
        row.addWidget(encode)
        layout.addLayout(row)

        hint = QLabel(
            "Stub: jmp/call → pop rsi → xor byte [rsi+rcx-1], key → jmp payload "
            "(x86-64). With an empty key the smallest bad-byte-free key is chosen."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self._enc_out = QPlainTextEdit()
        self._enc_out.setReadOnly(True)
        self._enc_out.setFont(mono_font(self.ctx.settings))
        self._enc_out.setPlaceholderText("Encoded payload + decoder asm appear here.")
        layout.addWidget(self._enc_out, 1)

        buttons = QHBoxLayout()
        copy_payload = QPushButton("Copy payload")
        copy_payload.clicked.connect(
            lambda: copy_text(self._enc_out.toPlainText().split("\n\n")[0])
        )
        buttons.addWidget(copy_payload)
        to_encoder = QPushButton("Send assembled →")
        to_encoder.setToolTip("Copy the Assembler output into the payload field")
        to_encoder.clicked.connect(self._send_assembled)
        buttons.addWidget(to_encoder)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        return wrap

    # -------------------------------------------------------------- format str
    def _build_fmtstr(self) -> QWidget:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)

        find_row = QHBoxLayout()
        find_row.addWidget(QLabel("Marker:"))
        self._marker = QLineEdit("41414141")
        self._marker.setMaximumWidth(110)
        find_row.addWidget(self._marker)
        find_row.addWidget(QLabel("%p output:"))
        self._fmt_out = QLineEdit()
        self._fmt_out.setFont(mono_font(self.ctx.settings))
        self._fmt_out.setPlaceholderText("0x7ffd… 0x41414141 …")
        find_row.addWidget(self._fmt_out, 1)
        find = QPushButton("Find offset")
        find.clicked.connect(self._find_offset)
        find_row.addWidget(find)
        layout.addLayout(find_row)

        offset_row = QHBoxLayout()
        offset_row.addWidget(QLabel("Arg offset:"))
        self._fmt_offset = QSpinBox()
        self._fmt_offset.setRange(1, 4096)
        self._fmt_offset.setValue(6)
        offset_row.addWidget(self._fmt_offset)
        offset_row.addWidget(QLabel("Write size:"))
        self._fmt_size = QComboBox()
        self._fmt_size.addItems(["1", "2", "4", "8"])
        self._fmt_size.setCurrentText("2")
        offset_row.addWidget(self._fmt_size)
        offset_row.addWidget(QLabel("Bad:"))
        self._fmt_bad = QLineEdit()
        self._fmt_bad.setMaximumWidth(100)
        self._fmt_bad.setPlaceholderText("0a 0d")
        offset_row.addWidget(self._fmt_bad)
        build = QPushButton("Build plan")
        build.clicked.connect(self._build_fmt_plan)
        offset_row.addWidget(build)
        offset_row.addStretch(1)
        layout.addLayout(offset_row)

        layout.addWidget(
            QLabel("Writes — one per line: address:value (hex), e.g. 0x404060:0x401230")
        )
        self._writes = QPlainTextEdit()
        self._writes.setFont(mono_font(self.ctx.settings))
        self._writes.setMaximumHeight(90)
        self._writes.setPlaceholderText("0x404060:0x401230\n0x404070:0x0")
        layout.addWidget(self._writes)

        self._fmt_result = QPlainTextEdit()
        self._fmt_result.setReadOnly(True)
        self._fmt_result.setFont(mono_font(self.ctx.settings))
        self._fmt_result.setPlaceholderText(
            "Plan: format string, address table and exact byte count."
        )
        layout.addWidget(self._fmt_result, 1)

        copy = QPushButton("Copy payload")
        copy.clicked.connect(self._copy_fmt)
        layout.addWidget(copy)
        return wrap

    # --------------------------------------------------------------- lifecycle
    def initialize(self, parent: Any = None) -> None:
        return None

    # ---------------------------------------------------------------- assemble
    def _load_preset(self, index: int) -> None:
        preset = self._preset.itemData(index)
        if preset is None:
            return
        self._asm.setPlainText(str(preset.asm).strip())
        arch_index = self._arch.findText(preset.arch)
        if arch_index >= 0:
            self._arch.setCurrentIndex(arch_index)

    def _parse_bad(self, text: str) -> bytes:
        if not text.strip():
            return b""
        try:
            return parse_hex_bytes(text)
        except ShellcodeError:
            return b""

    def _assemble(self) -> None:
        arch = self._arch.currentText()
        source = self._asm.toPlainText().strip()
        if not source:
            self._status.setText("Write something to assemble (or pick a preset).")
            return
        try:
            data = assemble(source, arch)
        except ShellcodeError as exc:
            self._status.setText(f"⚠ {exc}")
            return
        self._last_bytes = data
        self._render_output()
        try:
            rows = disassemble(data, arch)
        except ShellcodeError:
            rows = []
        self._disasm.setRowCount(len(rows))
        for row, item in enumerate(rows):
            set_row(
                self._disasm,
                row,
                [f"{item.address:#x}", item.bytes_hex, item.text],
                addr=item.address,
            )
        self._status.setText(
            f"{len(data)} bytes for {arch}"
            + (f" — bad bytes at {self._bad_offsets(data)}" if self._bad_offsets(data) else "")
        )

    def _render_output(self) -> None:
        if not self._last_bytes:
            return
        try:
            text = format_bytes(self._last_bytes, self._format.currentText())
        except ShellcodeError as exc:
            self._status.setText(f"⚠ {exc}")
            return
        self._asm_out.setText(text)

    def _bad_offsets(self, data: bytes) -> list[int]:
        return bad_byte_offsets(data, self._parse_bad(self._bad.text()))

    def _check_bad(self) -> None:
        if not self._last_bytes:
            return
        bad = self._parse_bad(self._bad.text())
        if not bad:
            self._status.setText(f"{len(self._last_bytes)} bytes — no bad-byte filter set.")
            return
        offsets = bad_byte_offsets(self._last_bytes, bad)
        if offsets:
            self._status.setText(f"⚠ bad bytes at offsets {offsets[:12]}")
        else:
            self._status.setText("Clean: no bad bytes in the payload.")

    def _copy_output(self) -> None:
        text = self._asm_out.text().strip()
        if not text:
            self._status.setText("Assemble something first.")
            return
        copy_text(text)
        self._status.setText("Bytes copied.")

    # ----------------------------------------------------------------- encoder
    def _send_assembled(self) -> None:
        if not self._last_bytes:
            self._status.setText("Assemble a payload first.")
            return
        self._enc_in.setText(format_bytes(self._last_bytes, "escaped"))
        self._status.setText("Assembled payload moved to the Encoder tab.")

    def _encode(self) -> None:
        try:
            data = parse_hex_bytes(self._enc_in.text())
        except ShellcodeError as exc:
            self._status.setText(f"⚠ {exc}")
            return
        if not data:
            self._status.setText("Paste payload bytes to encode.")
            return
        bad = self._parse_bad(self._enc_bad.text())
        key = parse_int(self._enc_key.text())
        if key is not None and not 0 < key < 256:
            self._status.setText("XOR key must be 1..255 (or blank for auto).")
            return
        try:
            encoded = encode_xor(data, bad, key, self._arch.currentText() or "x86_64")
        except ShellcodeError as exc:
            self._status.setText(f"⚠ {exc}")
            return
        self._enc_out.setPlainText(
            f"# key {encoded.key:#x}  ·  {len(data)} → {len(encoded.payload)} bytes "
            f"(stub {len(encoded.stub)})\n"
            f"{format_bytes(encoded.payload, 'python')}\n\n"
            f"# decoder asm\n{encoded.decoder_asm}"
        )
        self._status.setText(
            f"Encoded with key {encoded.key:#x}"
            + (
                f" — stub bytes contain bad bytes at {bad_byte_offsets(encoded.payload, bad)[:8]}"
                if bad and contains_bad(encoded.payload, bad)
                else " — payload is bad-byte clean."
            )
        )

    # -------------------------------------------------------------- format str
    def _find_offset(self) -> None:
        marker = self._marker.text().strip() or "41414141"
        output = self._fmt_out.text().strip()
        if not output:
            self._status.setText("Paste the program's %p output first.")
            return
        found = find_marker(output, marker)
        if found is None:
            self._status.setText(
                f"Marker {marker} not found — make sure it is in the buffer and the "
                "output is space-separated hex."
            )
            return
        index, token = found
        self._fmt_offset.setValue(index)
        self._status.setText(f"Marker is argument ${index} (token {token}).")

    def _build_fmt_plan(self) -> None:
        writes: list[tuple[int, int]] = []
        for line in self._writes.toPlainText().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                left, right = line.split(":", 1)
            elif "=" in line:
                left, right = line.split("=", 1)
            else:
                self._status.setText(f"⚠ Bad line {line!r} — use address:value.")
                return
            address = parse_int(left)
            value = parse_int(right)
            if address is None or value is None:
                self._status.setText(f"⚠ Bad line {line!r} — use hex address:value.")
                return
            writes.append((address, value))
        if not writes:
            self._status.setText("Add at least one address:value write.")
            return
        try:
            plan = build_plan(
                int(self._fmt_offset.value()),
                writes,
                bits=64,
                write_size=int(self._fmt_size.currentText()),
                bad_bytes=self._parse_bad(self._fmt_bad.text()),
            )
        except (ValueError, ShellcodeError) as exc:
            self._status.setText(f"⚠ {exc}")
            return
        self._fmt_result.setPlainText(
            plan.text()
            + "\n\n"
            + "# pwntools equivalent\n"
            + f"fmtstr_payload({plan.offset}, {{"
            + ", ".join(f"{address:#x}: {value:#x}" for address, value in writes)
            + "}, write_size='short')"
        )
        self._status.setText(plan.note)

    def _copy_fmt(self) -> None:
        text = self._fmt_result.toPlainText().strip()
        if not text:
            self._status.setText("Build a plan first.")
            return
        copy_text(text)
        self._status.setText("Format-string plan copied.")
