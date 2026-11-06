# 80PWNER — by Anas Mahfouz (The80)

"""Gadget Finder (Step 6 A): ROP/JOP gadget dock.

Speaks to :mod:`eightypwner.engines.gadgets` in a daemonic worker thread —
the scan never touches widgets; results come back as ``gadget_scan_result``
bus payloads (progress / done / cancelled / error) and land in the tree.
Results are cached per module path; filter widgets and search-as-you-type
re-run the pure ``apply_query`` on the UI thread, so re-filtering is instant.
"""

from __future__ import annotations

import logging
import re
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any, ClassVar

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import BINARY_CLOSED, BINARY_LOADED
from eightypwner.engines.gadgets import (
    Gadget,
    GadgetQuery,
    UnsupportedArchError,
    apply_query,
    find_gadgets,
)
from eightypwner.modules.interface import Plugin
from eightypwner.ui.fonts import resolve_monospace

log = logging.getLogger(__name__)

GADGET_SCAN_RESULT = "gadget_scan_result"
# worker → UI payload:
#   {"module": label, "path": str, "state": progress|done|cancelled|error,
#    "progress": float, "gadgets": [Gadget], "note": str, "error": str,
#    "arch": str}

MAX_ROWS = 5000
MAX_GADGET_BYTES_UI = 32

KIND_LABELS: ClassVar[tuple[tuple[str, str], ...]] = (  # (kind, checkbox text)
    ("ret", "ret"),
    ("jmp", "jmp reg"),
    ("call", "call reg"),
    ("syscall", "syscall"),
    ("int80", "int 0x80"),
)


def _copy(text: str) -> None:
    app = QApplication.instance()
    if app is not None:
        with suppress(Exception):
            app.clipboard().setText(text)


def p64_hex(addr: int, width: int) -> str:
    """pwntools-style escaped bytes for an address: ``\\x61\\x11...``."""
    return "".join(f"\\x{b:02x}" for b in addr.to_bytes(width, "little"))


def parse_bad_bytes(text: str) -> bytes | None:
    """``'00 0a 0d'`` / ``'000a0d'`` → bytes; None when malformed."""
    cleaned = re.sub(r"[\s,:]+", "", text.strip())
    if not cleaned:
        return b""
    if len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return None
    return bytes.fromhex(cleaned)


class _Relay(QObject):
    """Re-dispatches bus events onto the thread this object lives on (UI)."""

    route = Signal(str, object)


class GadgetFinderPlugin(Plugin):
    name = "Gadget Finder"
    description = (
        "Scan binaries and libraries for ROP/JOP gadgets "
        "(ret / jmp reg / call reg / syscall / int 0x80)"
    )
    icon = "🪝"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._modules: dict[str, tuple[Any, str]] = {}  # label → (model, origin)
        self._results: dict[str, list[Gadget]] = {}  # module path → gadget cache
        self._lock = threading.Lock()
        self._pending: tuple[str, Any] | None = None  # queued (label, model)
        self._cancel = threading.Event()
        self._closing = False
        self._wake = threading.Event()
        self._worker: threading.Thread | None = None
        self._panel: QWidget | None = None
        self._current_module = ""  # module whose gadgets the tree shows
        self._all: list[Gadget] = []  # shown module's raw gadgets (unfiltered)
        self._note = ""

    # ------------------------------------------------------------ worker
    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(
                target=self._run_loop, name="gadget-scan", daemon=True
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
            label, model = job
            path = str(getattr(model, "path", ""))
            try:
                self._publish(
                    {"module": label, "path": path, "state": "progress", "progress": 0.0}
                )

                def progress(fraction: float, _label: str = label, _path: str = path) -> None:
                    self._publish(
                        {
                            "module": _label,
                            "path": _path,
                            "state": "progress",
                            "progress": max(0.0, min(1.0, fraction)),
                        }
                    )

                result = find_gadgets(
                    model, progress_cb=progress, should_cancel=self._should_cancel
                )
                state = "cancelled" if self._cancel.is_set() else "done"
                self._cancel.clear()
                self._publish(
                    {
                        "module": label,
                        "path": path,
                        "state": state,
                        "gadgets": result.gadgets,
                        "note": result.note,
                        "arch": getattr(model, "arch", "?"),
                    }
                )
            except UnsupportedArchError as exc:
                self._cancel.clear()
                self._publish(
                    {"module": label, "path": path, "state": "error", "error": str(exc)}
                )
            except Exception:
                log.exception("gadget scan crashed")
                self._cancel.clear()
                self._publish(
                    {
                        "module": label,
                        "path": path,
                        "state": "error",
                        "error": "Scan failed — see the log for details.",
                    }
                )
            time.sleep(0.02)

    def _should_cancel(self) -> bool:
        return self._cancel.is_set() or self._closing

    def _publish(self, payload: dict[str, Any]) -> None:
        with suppress(Exception):
            self.ctx.bus.publish(GADGET_SCAN_RESULT, payload)

    # ------------------------------------------------------------- panel
    def widget(self) -> QWidget:
        if getattr(self, "_panel", None) is not None:
            return self._panel  # one panel per plugin; rebuilds would swap the view
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(4)

        mods = QHBoxLayout()
        mods.addWidget(QLabel("Module:"))
        self._module_combo = QComboBox()
        self._module_combo.setToolTip(
            "The binary under analysis plus any library you loaded to scan"
        )
        self._module_combo.currentTextChanged.connect(self._module_changed)
        mods.addWidget(self._module_combo, 1)
        load_btn = QPushButton("Load module…")
        load_btn.setToolTip("Scan an extra file, e.g. libc.so.6")
        load_btn.clicked.connect(lambda: self._load_module_dialog())
        mods.addWidget(load_btn)
        outer.addLayout(mods)

        scanrow = QHBoxLayout()
        self._scan_btn = QPushButton("Scan gadgets")
        self._scan_btn.clicked.connect(self._on_scan_clicked)
        scanrow.addWidget(self._scan_btn)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._on_cancel)
        scanrow.addWidget(self._cancel_btn)
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        self._progress.hide()
        scanrow.addWidget(self._progress, 1)
        outer.addLayout(scanrow)

        self._status = QLabel("Load a binary, pick a module, then press Scan gadgets.")
        self._status.setWordWrap(True)
        outer.addWidget(self._status)

        form = QFormLayout()
        form.setSpacing(4)
        self._regs_edit = QLineEdit()
        self._regs_edit.setPlaceholderText("rdi, rsp")
        self._regs_edit.setToolTip(
            "Comma/space separated register names that must appear in the gadget"
        )
        form.addRow("Registers", self._regs_edit)
        self._regex_edit = QLineEdit()
        self._regex_edit.setPlaceholderText("^pop rdi")
        self._regex_edit.setToolTip("Regex over the disassembly text (case-insensitive)")
        form.addRow("Pattern", self._regex_edit)
        limit_row = QHBoxLayout()
        self._len_spin = QSpinBox()
        self._len_spin.setRange(1, 128)
        self._len_spin.setValue(MAX_GADGET_BYTES_UI)
        self._len_spin.setPrefix("≤ ")
        self._len_spin.setSuffix(" bytes")
        self._len_spin.setToolTip("Maximum gadget byte length")
        limit_row.addWidget(self._len_spin)
        self._bad_edit = QLineEdit()
        self._bad_edit.setPlaceholderText("bad bytes: 00 0a 0d")
        self._bad_edit.setToolTip(
            "Hex bytes that must not appear in the gadget bytes or its address"
        )
        limit_row.addWidget(self._bad_edit, 1)
        form.addRow("Length + bad", limit_row)
        kind_row = QHBoxLayout()
        self._kind_checks: dict[str, QCheckBox] = {}
        for kind, text in KIND_LABELS:
            box = QCheckBox(text)
            box.setChecked(True)
            self._kind_checks[kind] = box
            kind_row.addWidget(box)
        kind_row.addStretch(1)
        form.addRow("Endings", kind_row)
        outer.addLayout(form)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search results as you type…")
        self._search_edit.setToolTip("Substring filter over instructions and bytes")
        self._search_edit.textChanged.connect(self._on_search_changed)
        outer.addWidget(self._search_edit)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(4)
        self._tree.setHeaderLabels(["Address", "Bytes", "Instructions", "Length"])
        self._tree.setRootIsDecorated(False)
        self._tree.setAlternatingRowColors(True)
        self._tree.setUniformRowHeights(True)
        self._tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._context_menu)
        self._tree.itemDoubleClicked.connect(self._item_double_clicked)
        self._tree.setFont(resolve_monospace())
        self._tree.setSortingEnabled(True)
        self._tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        outer.addWidget(self._tree, 1)

        self._table_note = QLabel("")
        self._table_note.setWordWrap(True)
        outer.addWidget(self._table_note)

        self._refresh_module_combo()
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
        self._unsub = subscribe("*", self.on_event)
        self._ensure_worker()
        theme = getattr(self.ctx, "theme", None)
        if theme is not None:
            theme.theme_changed.connect(self._on_theme_changed)

    def shutdown(self) -> None:
        self._closing = True
        self._cancel.set()
        self._wake.set()
        worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=1.0)
        with suppress(Exception):
            self._unsub()

    def _on_theme_changed(self, theme: Any) -> None:
        panel = getattr(self, "_panel", None)
        if panel is not None:
            panel.update()

    def on_event(self, topic: str, payload: Any) -> None:
        """Bus callback. Widget handlers always run on the UI thread: when a
        worker publishes (tests with ``ui_bus=None``, or the raw-bus path),
        re-dispatch through a queued Qt signal instead."""
        app = QApplication.instance()
        if app is not None and threading.current_thread() is not app.thread():
            # worker thread: hop to the UI thread (queued auto connection)
            with suppress(RuntimeError):
                self._relay.route.emit(topic, payload)
            return
        self._handle_event(topic, payload)

    def _handle_event(self, topic: str, payload: Any) -> None:
        """Actual event handling — always on the UI thread by the time we're here."""
        if topic == BINARY_LOADED and isinstance(payload, dict):
            model = payload.get("model")
            if model is not None:
                self._set_binary_module(model)
        elif topic == BINARY_CLOSED:
            self._drop_binary_modules()
        elif topic == GADGET_SCAN_RESULT and isinstance(payload, dict):
            self._on_scan_payload(payload)

    # ------------------------------------------------------------- modules
    def _set_binary_module(self, model: Any) -> None:
        """binary_loaded: claim the default module and invalidate its cache."""
        label = str(getattr(model, "name", getattr(model, "path", "binary")))
        with self._lock:
            self._modules[label] = (model, "binary")
            self._results.pop(str(getattr(model, "path", "")), None)
        self._refresh_module_combo()
        self._module_combo.setCurrentText(label)
        self._show_module(label)

    def _drop_binary_modules(self) -> None:
        """binary_closed: drop the binary module; loaded libraries survive."""
        with self._lock:
            for label in [
                key for key, (_model, origin) in self._modules.items() if origin == "binary"
            ]:
                model = self._modules.pop(label)[0]
                self._results.pop(str(getattr(model, "path", "")), None)
        self._refresh_module_combo()
        if self._current_module not in self._modules:
            self._current_module = ""
            self._all = []
            self._fill_table()
            self._status.setText("Load a binary, pick a module, then press Scan gadgets.")

    def _refresh_module_combo(self) -> None:
        combo = getattr(self, "_module_combo", None)
        if combo is None:
            return
        combo.blockSignals(True)
        combo.clear()
        with self._lock:
            labels = sorted(self._modules)
        combo.addItems(labels)
        combo.blockSignals(False)

    def _module_changed(self, label: str) -> None:
        if label in self._modules:
            self._show_module(label)

    def _show_module(self, label: str) -> None:
        with self._lock:
            entry = self._modules.get(label)
            path = str(getattr(entry[0], "path", "")) if entry else ""
            cached = list(self._results.get(path, ())) if entry else []
        self._current_module = label
        self._all = cached
        self._fill_table()
        self._status.setText(
            f"{label}: {len(cached)} cached gadgets — re-scan to refresh."
            if cached
            else f"{label}: not scanned yet — press Scan gadgets."
        )

    def load_library_path(self, path: str) -> str:
        """Attach a file as a scannable library module; '' ok, else message."""
        from eightypwner.engines.binary_parser import parse_binary

        try:
            model = parse_binary(Path(path).expanduser())
        except Exception:
            log.exception("library load failed for %s", path)
            message = f"Could not parse {Path(path).name} as an ELF/PE/Mach-O binary."
            self._status.setText(message)
            return message
        base = f"{model.name} (library)"
        label = base
        attempt = 0
        with self._lock:
            while label in self._modules:
                attempt += 1
                label = f"{base} #{attempt}"
            self._modules[label] = (model, "library")
        self._refresh_module_combo()
        self._module_combo.setCurrentText(label)
        return ""

    def _load_module_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self._panel, "Load library for gadget scan", "", "Binaries (*)"
        )
        if path:
            message = self.load_library_path(path)
            if message:
                self._status.setText(message)

    # ------------------------------------------------------------- scanning
    def _on_scan_clicked(self) -> None:
        self.request_scan(self._module_combo.currentText())

    def request_scan(self, label: str) -> None:
        """Queue a scan for module *label*; the worker publishes the results."""
        with self._lock:
            entry = self._modules.get(label)
            if entry is None:
                self._status.setText(f"No module named {label!r} — load a binary first.")
                return
            model = entry[0]
            self._results.pop(str(getattr(model, "path", "")), None)
            self._pending = (label, model)
            self._cancel.clear()
        self._ensure_worker()
        self._wake.set()
        self._scan_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress.show()
        self._progress.setValue(0)
        self._status.setText(f"Scanning {label} — progress updates live…")

    def _on_cancel(self) -> None:
        self._cancel.set()
        self._status.setText("Cancelling scan — partial results will be kept…")

    def _on_scan_payload(self, payload: dict[str, Any]) -> None:
        """UI thread: worker → cache + tree."""
        state = str(payload.get("state", ""))
        path = str(payload.get("path", ""))
        module = str(payload.get("module", ""))
        if state == "progress":
            self._progress.setValue(int(float(payload.get("progress", 0)) * 100))
            return
        if state in ("done", "cancelled"):
            gadgets = list(payload.get("gadgets") or ())
            with self._lock:
                self._results[path] = gadgets
            if self._current_module != module:
                return  # quietly cache for later module switching
            self._all = gadgets
            self._note = str(payload.get("note") or "")
            self._scan_btn.setEnabled(True)
            self._cancel_btn.setEnabled(False)
            self._progress.hide()
            extra = f" — {self._note.strip()}" if self._note.strip() else ""
            if state == "done":
                text = f"{module} [{payload.get('arch', '?')}]: {len(gadgets)} gadgets"
            else:
                text = f"{module}: scan cancelled — {len(gadgets)} partial gadgets"
            self._status.setText(text + extra)
            self._fill_table()
        elif state == "error":
            self._scan_btn.setEnabled(True)
            self._cancel_btn.setEnabled(False)
            self._progress.hide()
            self._status.setText(str(payload.get("error", "Scan failed")))
            if module == self._current_module:
                self._all = []
                self._fill_table()

    # ------------------------------------------------------------- filtering
    def current_query(self) -> tuple[GadgetQuery | None, str]:
        """Filter widgets → (GadgetQuery, or None with a user-facing error)."""
        regs = tuple(
            token
            for token in (
                word.strip().lower()
                for word in re.split(r"[\s,;]+", self._regs_edit.text())
            )
            if token
        )
        pattern = self._regex_edit.text().strip()
        try:
            re.compile(pattern)
        except re.error as exc:
            return None, f"Invalid regex: {exc}"
        bad = parse_bad_bytes(self._bad_edit.text())
        if bad is None:
            return None, "Bad bytes must be hex byte pairs, e.g. 00 0a 0d."
        kinds = tuple(kind for kind, box in self._kind_checks.items() if box.isChecked())
        query = GadgetQuery(
            regs=regs,
            regex=pattern,
            max_bytes=self._len_spin.value(),
            bad_bytes=bad,
            kinds=kinds,
        )
        return query, ""

    def _current_rows(self) -> list[Gadget]:
        """apply_query + search-as-you-type over the shown module's gadgets."""
        query, err = self.current_query()
        if query is None:
            self._status.setText(err)
            return []
        rows = apply_query(self._all, query)
        needle = self._search_edit.text().strip().lower()
        if needle:
            rows = [g for g in rows if needle in g.insns.lower() or needle in g.bytes_hex]
        return rows

    def _on_search_changed(self, _text: str) -> None:
        self._fill_table()

    def _refresh_table(self) -> None:
        self._fill_table()

    def _fill_table(self) -> None:
        tree = getattr(self, "_tree", None)
        if tree is None:
            return
        rows = self._current_rows()
        tree.setSortingEnabled(False)  # sorting during mass insert is O(n²)
        tree.clear()
        for gadget in rows[:MAX_ROWS]:
            item = QTreeWidgetItem(
                [hex(gadget.address), gadget.bytes_hex, gadget.insns, str(gadget.size)]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, gadget.address)
            item.setData(3, Qt.ItemDataRole.UserRole, gadget.size)
            tree.addTopLevelItem(item)
        for column in range(tree.columnCount()):
            tree.resizeColumnToContents(column)
        tree.setSortingEnabled(True)
        notes = []
        if len(rows) > MAX_ROWS:
            notes.append(f"showing first {MAX_ROWS} of {len(rows)} matches")
        if self._note.strip():
            notes.append(self._note.strip())
        self._table_note.setText("; ".join(notes))

    # ------------------------------------------------------------- copying
    def _item_double_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        _copy(p64_hex(int(item.data(0, Qt.ItemDataRole.UserRole)), 8))

    def _gadget_of(self, item: QTreeWidgetItem) -> Gadget | None:
        addr = item.data(0, Qt.ItemDataRole.UserRole)
        size = item.data(3, Qt.ItemDataRole.UserRole)
        if addr is None or size is None:
            return None
        for gadget in self._all:
            if gadget.address == addr and gadget.size == size:
                return gadget
        return None

    def _context_menu(self, pos: Any) -> None:
        tree = getattr(self, "_tree", None)
        if tree is None:
            return
        item = tree.itemAt(pos)
        if item is None:
            return
        addr = int(item.data(0, Qt.ItemDataRole.UserRole))
        gadget = self._gadget_of(item)
        menu = QMenu(tree)
        menu.addSection(hex(addr))
        a_p64 = QAction(f"Copy address as p64 ('{p64_hex(addr, 8)}')", menu)
        a_p64.triggered.connect(lambda: _copy(p64_hex(addr, 8)))
        a_p32 = QAction(f"Copy address as p32 ('{p64_hex(addr, 4)}')", menu)
        a_p32.triggered.connect(lambda: _copy(p64_hex(addr, 4)))
        a_rawhex = QAction(f"Copy raw address hex ({hex(addr)})", menu)
        a_rawhex.triggered.connect(lambda: _copy(hex(addr)))
        a_bytes = QAction("Copy gadget bytes hex", menu)
        a_bytes.triggered.connect(lambda: _copy(gadget.bytes_hex if gadget else item.text(1)))
        a_text = QAction("Copy gadget text", menu)
        a_text.triggered.connect(lambda: _copy(gadget.insns if gadget else item.text(2)))
        for action in (a_p64, a_p32, a_rawhex, a_bytes, a_text):
            menu.addAction(action)
        menu.exec(tree.viewport().mapToGlobal(pos))
