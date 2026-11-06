# 80PWNER — by Anas Mahfouz (The80)

"""Pattern Tool (Step 6 B): de Bruijn pattern generator + crash-offset finder.

Left half: generate a pwntools-compatible cyclic pattern (length and
subsequence size n=2..8), copy it for the exploit script. Right half: type a
crash value (0x… hex, decimal, byte pairs "61 61 61 62", or ASCII "baaa"),
or pick a register from the live debugger dropdown, and get the offset into
the pattern. When the debuggee crashes, ``suggest_offset`` scans the stopped
register dump automatically and proposes the offset (spec: the debugger
bus event carries regs; only crashing stops count).

Heavy generation runs in the shared daemonic worker ('pattern_generated'
/ 'pattern_lookup_result' payloads back to the UI thread).
"""

from __future__ import annotations

import logging
import threading
from contextlib import suppress
from types import SimpleNamespace
from typing import Any, ClassVar

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
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

from eightypwner.engines.gdb_mi import T_REGISTERS, T_STATE, T_STOPPED
from eightypwner.engines.pattern import (
    cyclic,
    suggest_offset,
)
from eightypwner.engines.pattern import (
    lookup as pattern_lookup,
)
from eightypwner.modules.interface import Plugin
from eightypwner.ui.fonts import resolve_monospace

log = logging.getLogger(__name__)

PATTERN_GENERATED = "pattern_generated"
# {"state": done|error|cancelled, "text": str, "n": int, "length": int,
#  "error": str, "truncated": bool}

PATTERN_LOOKUP_RESULT = "pattern_lookup_result"
# {"query": str, "n": int, "offset": int, "why": str, "origin": manual|register|auto}

CRASH_SIGNALS: ClassVar[tuple[str, ...]] = (  # signal names that mean memory corruption
    "sigsegv",
    "sigbus",
    "sigill",
    "sigfpe",
    "sigabrt",
)
CRASH_REASONS: ClassVar[tuple[str, ...]] = ("sigsegv", "sigbus", "sigill", "sigfpe")

GENERATED_PREVIEW = 4096  # chars kept in the text box; the copy button has all
MAX_LENGTH = 2_000_000  # UI-side sanity cap (2 MB of pattern is plenty)


def _copy(text: str) -> None:
    app = QApplication.instance()
    if app is not None:
        with suppress(Exception):
            app.clipboard().setText(text)


class _Relay(QObject):
    """Re-dispatches bus events onto the thread this object lives on (UI)."""

    route = Signal(str, object)


class PatternToolPlugin(Plugin):
    name = "Pattern Tool"
    description = (
        "Generate cyclic patterns and find the crash offset "
        "(hex / decimal / bytes / ASCII / live registers)"
    )
    icon = "📏"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._panel: QWidget | None = None
        self._lock = threading.Lock()
        self._pending: tuple[str, dict[str, Any]] | None = None  # (job, args)
        self._cancel = threading.Event()
        self._closing = False
        self._wake = threading.Event()
        self._worker: threading.Thread | None = None
        self._last_pattern: bytes = b""
        self._last_n: int = 4
        self._registers: dict[str, str] = {}  # latest debugger_registers values
        self._running_state = "idle"

    # ------------------------------------------------------------ worker
    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(
                target=self._run_loop, name="pattern-tool", daemon=True
            )
            self._worker.start()

    def _run_loop(self) -> None:
        import time

        while not self._closing:
            with self._lock:
                job = self._pending
                self._pending = None
            if job is None:
                self._wake.wait(0.2)
                self._wake.clear()
                continue
            kind, args = job
            with suppress(Exception):
                try:
                    if kind == "generate":
                        self._job_generate(args)
                    elif kind == "lookup":
                        self._job_lookup(args)
                except Exception:
                    log.exception("pattern job crashed")
            time.sleep(0.02)

    def _job_generate(self, args: dict[str, Any]) -> None:
        length = int(args["length"])
        n = int(args["n"])
        try:
            data = cyclic(length, n=n)
        except ValueError as exc:
            self._publish(PATTERN_GENERATED, {"state": "error", "error": str(exc), "n": n})
            return
        self._last_pattern = data
        self._last_n = n
        text = data.decode("ascii", errors="replace")
        self._publish(
            PATTERN_GENERATED,
            {
                "state": "done",
                "text": text,
                "n": n,
                "length": length,
                "truncated": False,
            },
        )

    def _job_lookup(self, args: dict[str, Any]) -> None:
        query = str(args["query"])
        n = int(args["n"])
        regs = args.get("regs") or {}
        suggestion = args.get("suggest") is True
        if suggestion:
            found = suggest_offset(regs, n=n)
            self._publish(
                PATTERN_LOOKUP_RESULT,
                {
                    "query": query,
                    "n": n,
                    "offset": found[0] if found else -1,
                    "why": (
                        f"{found[1]} → offset {found[0]}" if found else ""
                    ),
                    "origin": "auto",
                    "has_guess": found is not None,
                },
            )
            return
        offset, why = pattern_lookup(query, n=n)
        self._publish(
            PATTERN_LOOKUP_RESULT,
            {
                "query": query,
                "n": n,
                "offset": offset,
                "why": why,
                "origin": str(args.get("origin") or "manual"),
            },
        )

    def _publish(self, topic: str, payload: dict[str, Any]) -> None:
        with suppress(Exception):
            self.ctx.bus.publish(topic, payload)

    def _should_cancel(self) -> bool:
        return self._cancel.is_set() or self._closing

    # ------------------------------------------------------------- panel
    def widget(self) -> QWidget:
        if getattr(self, "_panel", None) is not None:
            return self._panel
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(6)

        # ---------------- generator
        gen_head = QHBoxLayout()
        gen_head.addWidget(QLabel("Length:"))
        self._len_spin = QSpinBox()
        self._len_spin.setRange(1, MAX_LENGTH)
        self._len_spin.setValue(500)
        self._len_spin.setMinimumWidth(96)
        self._len_spin.setToolTip("Pattern size in bytes (≤ 2 MB)")
        gen_head.addWidget(self._len_spin)
        gen_head.addWidget(QLabel("n:"))
        self._n_spin_gen = QSpinBox()
        self._n_spin_gen.setRange(2, 8)
        self._n_spin_gen.setValue(4)
        self._n_spin_gen.setMinimumWidth(52)
        self._n_spin_gen.setToolTip(
            "Subsequence size — offset results must use the same n"
        )
        gen_head.addWidget(self._n_spin_gen)
        self._gen_btn = QPushButton("Generate")
        self._gen_btn.clicked.connect(self._on_generate)
        gen_head.addWidget(self._gen_btn)
        self._copy_pat_btn = QPushButton("Copy pattern")
        self._copy_pat_btn.setEnabled(False)
        self._copy_pat_btn.clicked.connect(self._on_copy_pattern)
        gen_head.addWidget(self._copy_pat_btn)
        gen_head.addStretch(1)
        outer.addLayout(gen_head)

        self._pattern_view = QPlainTextEdit()
        self._pattern_view.setReadOnly(True)
        self._pattern_view.setFont(QFont(resolve_monospace(), 10))
        self._pattern_view.setPlaceholderText(
            "The generated cyclic pattern shows here (first 4 KB in the box — "
            "Copy pattern copies all of it)."
        )
        outer.addWidget(self._pattern_view, 2)

        # ---------------- offset lookup
        outer.addWidget(QLabel("Crash value → offset"))
        form = QFormLayout()
        form.setSpacing(4)
        self._query_edit = QLineEdit()
        self._query_edit.setPlaceholderText("0x61616162 · 100 · 61 61 61 62 · baaa")
        self._query_edit.setToolTip(
            "Hex value, decimal, space-separated byte pairs, or the ASCII chunk"
        )
        find_row = QHBoxLayout()
        self._find_btn = QPushButton("Find offset")
        self._find_btn.clicked.connect(self._on_find_clicked)
        find_row.addWidget(self._find_btn)
        form.addRow(self._query_edit, find_row)

        reg_row = QHBoxLayout()
        reg_row.addWidget(QLabel("Register:"))
        self._reg_combo = QComboBox()
        self._reg_combo.setToolTip("Live register values from the debugger")
        reg_row.addWidget(self._reg_combo, 1)
        self._use_reg_btn = QPushButton("Use value")
        self._use_reg_btn.setToolTip("Fill the lookup box with the chosen register")
        self._use_reg_btn.clicked.connect(self._on_use_register)
        reg_row.addWidget(self._use_reg_btn)
        form.addRow(reg_row)
        outer.addLayout(form)

        self._result = QLabel("No lookup yet — generate a pattern with n=4, crash, paste the value.")
        self._result.setWordWrap(True)
        self._result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(self._result)
        self._search_note = QLabel("")  # truncated etc.
        self._search_note.setWordWrap(True)
        outer.addWidget(self._search_note)
        outer.addStretch(1)
        return panel

    # ------------------------------------------------------------- events
    def initialize(self, parent: Any = None) -> None:
        self._relay = _Relay()
        self._relay.route.connect(self._handle_event)
        subscribe = (
            self.ctx.ui_bus.subscribe
            if self.ctx.ui_bus is not None
            else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_bus_event)
        self._ensure_worker()

    def shutdown(self) -> None:
        self._closing = True
        self._cancel.set()
        self._wake.set()
        worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=1.0)
        with suppress(Exception):
            self._unsub()

    def on_bus_event(self, topic: str, payload: Any) -> None:
        """Bus callback; worker publications hop via the UI-thread relay."""
        app = QApplication.instance()
        if app is not None and threading.current_thread() is not app.thread():
            with suppress(RuntimeError):
                self._relay.route.emit(topic, payload)
            return
        self._handle_event(topic, payload)

    def _handle_event(self, topic: str, payload: Any) -> None:
        if topic == T_STATE and isinstance(payload, dict):
            self._running_state = str(payload.get("state", self._running_state))
        elif topic == T_REGISTERS and isinstance(payload, dict):
            values = payload.get("values")
            if isinstance(values, dict):
                self._registers = dict(values)
                self._fill_register_combo()
        elif topic == T_STOPPED and isinstance(payload, dict):
            regs = payload.get("regs")
            if isinstance(regs, dict):
                self._registers = dict(regs)
                self._fill_register_combo()
                self._maybe_auto_suggest(payload.copy())
        elif topic == PATTERN_GENERATED and isinstance(payload, dict):
            self._on_generated(payload)
        elif topic == PATTERN_LOOKUP_RESULT and isinstance(payload, dict):
            self._on_lookup_result(payload)

    # ------------------------------------------------------------- action
    def _on_generate(self) -> None:
        length = self._len_spin.value()
        n = self._n_spin_gen.value()
        with self._lock:
            self._pending = ("generate", {"length": length, "n": n})
            self._cancel.clear()
        self._ensure_worker()
        self._wake.set()
        self._search_note.setText("Generating pattern…")

    def _on_copy_pattern(self) -> None:
        if self._last_pattern:
            _copy(self._last_pattern.decode("ascii", errors="replace"))

    def _on_find_clicked(self) -> None:
        query = self._query_edit.text().strip()
        if not query:
            self._result.setText("Type a value first (0x…, decimal, bytes, or ASCII).")
            return
        self.request_lookup(query)

    def request_lookup(self, query: str, origin: str = "manual") -> None:
        with self._lock:
            self._pending = (
                "lookup",
                {"query": query, "n": self._last_n, "origin": origin},
            )
            self._cancel.clear()
        self._ensure_worker()
        self._wake.set()
        self._result.setText("Looking up…")

    def _on_use_register(self) -> None:
        reg = self._reg_combo.currentText()
        value = self._registers.get(reg, "")
        if not value:
            self._result.setText("No register value available — the debugger must be stopped.")
            return
        self._query_edit.setText(value)

    # ------------------------------------------------------------- debugger
    def _fill_register_combo(self) -> None:
        combo = getattr(self, "_reg_combo", None)
        if combo is None:
            return
        current = combo.currentText()
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(sorted(self._registers))
        combo.blockSignals(False)
        if current:
            combo.setCurrentText(current)

    def _maybe_auto_suggest(self, payload: dict[str, Any]) -> None:
        """Crash stops get a register-based offset suggestion automatically."""
        reason = str(payload.get("reason", "")).lower()
        signal = str(payload.get("signal", "")).lower()
        crashed = (
            "signal" in reason
            or any(sig in reason for sig in CRASH_REASONS)
            or any(name == signal or name in signal for name in CRASH_SIGNALS)
        )
        if not crashed or self._running_state not in ("stopped", "exited"):
            return
        with self._lock:
            self._pending = (
                "lookup",
                {
                    "query": "(auto: crashing stop registers)",
                    "n": self._last_n,
                    "regs": self._registers,
                    "suggest": True,
                },
            )
        self._ensure_worker()
        self._wake.set()
        self._result.setText("Crash detected — scanning registers for pattern data…")

    # ------------------------------------------------------------- results
    def _on_generated(self, payload: dict[str, Any]) -> None:
        state = str(payload.get("state"))
        if state == "error":
            self._search_note.setText(f"Generation failed: {payload.get('error', '?')}")
            return
        text = str(payload.get("text", ""))
        self._last_pattern = text.encode("ascii", errors="replace")
        self._last_n = int(payload.get("n", 4))
        preview = text[:GENERATED_PREVIEW]
        if len(text) > len(preview):
            preview += "\n… (first 4 KB shown — 'Copy pattern' copies everything)"
            truncated = True
        else:
            truncated = False
        self._pattern_view.setPlainText(preview)
        self._copy_pat_btn.setEnabled(bool(text))
        self._search_note.setText(
            f"{payload.get('length')} bytes, n={self._last_n} — copy it over the buffer."
            + (" (boxed preview truncated)" if truncated else "")
        )

    def _on_lookup_result(self, payload: dict[str, Any]) -> None:
        offset = int(payload.get("offset", -1))
        why = str(payload.get("why", ""))
        origin = str(payload.get("origin", "manual"))
        prefix = {"auto": "Auto ", "register": "Register "}.get(origin, "")
        if offset < 0:
            self._result.setText(f"{prefix}No offset found — {why}")
            return
        self._result.setText(f"{prefix}{why}")

    # Keep the internal state reachable for tests without poking privates of Qt widgets
    def _probe(self) -> SimpleNamespace:  # pragma: no cover - test affordance
        return SimpleNamespace(
            registers=dict(self._registers),
            last_n=self._last_n,
            running_state=self._running_state,
        )
