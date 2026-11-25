# 80PWNER — by Anas Mahfouz (The 80)

"""Stack Visualizer (Step 5): a live graphical view of the current stack frame.

The dock shows the selected debuggee frame as a vertical diagram — highest
addresses at the top — with rows for caller arguments, the return address,
the saved frame pointer, the stack canary (when present) and the local
variables/buffers, plus dim filler rows for unknown bytes. Every row shows
its address, RBP/RSP offsets, size, raw value and a pointer/ASCII
annotation. Hotspot distances ("buffer start -> return address: 72 bytes")
update live and copy with one click.

Data flow (spec §4): runtime events (``debugger_stopped`` etc.) arrive on
the UI thread via UiBus; the plugin records snapshots and wakes ONE worker
thread, which assembles registers + the stack window + DWARF/disassembly
knowledge into a
:class:`eightypwner.engines.stack_frame.FrameLayout` and publishes
``stack_frame_ready`` back through the bus. The worker never touches
widgets; the widget never blocks on gdb.
"""

from __future__ import annotations

import logging
import threading
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import (
    ADDRESS_SELECTED,
    BINARY_CLOSED,
    BINARY_LOADED,
)
from eightypwner.engines.gdb_mi import (
    T_BACKTRACE,
    T_EVAL,
    T_EXITED,
    T_MEMORY_GOTO_REQUEST,
    T_MEMORY_READ,
    T_REGISTERS,
    T_STACK_CONTEXT_REQUEST,
    T_STACK_EVAL_REQUEST,
    T_STACK_WORDS,
    T_STATE,
    T_STOPPED,
)
from eightypwner.engines.stack_frame import (
    KIND_LABEL,
    analyze_frame,
    frame_distances,
    word_size_for_arch,
)
from eightypwner.modules.interface import Plugin
from eightypwner.ui.fonts import resolve_monospace

if TYPE_CHECKING:
    from eightypwner.engines.binary_parser import BinaryModel
    from eightypwner.engines.stack_frame import FrameLayout, StackRow

log = logging.getLogger(__name__)

STACK_FRAME_READY = "stack_frame_ready"  # worker → UI: {"layout", "changed", …}

FRAME_WINDOW_BYTES = 1024  # SP window read per stop (covers locals + caller args)

_ROW_H = 30
_MARGIN = 8
_INFO_H = 24

# kind → (background, foreground, border) token names
KIND_TOKENS: dict[str, tuple[str, str, str]] = {
    "ret_addr": ("accent", "on_accent", "accent"),
    "saved_rbp": ("accent_dim", "fg", "accent"),
    "canary": ("warn_bg", "warn", "warn"),
    "buffer": ("panel_alt", "accent", "accent"),
    "local": ("panel", "fg", "border"),
    "param": ("panel_alt", "fg", "accent_dim"),
    "gap": ("bg", "dim", "border"),
    "window": ("panel", "fg", "border"),
}


def _hexint(text: Any) -> int | None:
    """Parse gdb hex-ish output ('0x4011d2', '0x… <main+12>') or None."""
    if text is None:
        return None
    token = str(text).strip()
    if not token:
        return None
    token = token.split("<", 1)[0].strip()
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token, 0)
    except (TypeError, ValueError):
        return None


def _copy(text: str) -> None:
    """One-click clipboard copy (UI thread)."""
    app = QApplication.instance()
    if app is not None:
        with suppress(Exception):
            app.clipboard().setText(text)


class StackFrameView(QAbstractScrollArea):
    """QPainter-drawn vertical frame diagram; high addresses on top."""

    def __init__(self, plugin: StackVisualizerPlugin) -> None:
        super().__init__()
        self._plugin = plugin
        self._layout: FrameLayout | None = None
        self._changed: frozenset[int] = frozenset()
        self._empty_text = "Load a binary and start a debug session."
        self.viewport().setMinimumSize(560, 260)
        self.setFrameShape(QAbstractScrollArea.Shape.NoFrame)
        self.verticalScrollBar().setSingleStep(_ROW_H)
        self.setMouseTracking(False)

    # ------------------------------------------------------------ state in
    def set_frame(
        self,
        layout: FrameLayout | None,
        changed: frozenset[int] = frozenset(),
        empty_text: str | None = None,
    ) -> None:
        self._layout = layout
        self._changed = frozenset(changed or ())
        if empty_text:
            self._empty_text = empty_text
        if layout is not None and layout.error is not None:
            self._empty_text = layout.notes[0] if layout.notes else layout.error
            self._layout = None if layout.error else layout
        self.verticalScrollBar().setValue(0)
        self.updateGeometry()
        self.viewport().update()

    def clear_frame(self, empty_text: str) -> None:
        self.set_frame(None, frozenset(), empty_text)

    def _tokens(self) -> dict[str, str]:
        theme = getattr(self._plugin.ctx, "theme", None)
        if theme is not None:
            return dict(theme.theme().tokens)
        from eightypwner.ui.theme import DARK_TOKENS

        return dict(DARK_TOKENS)

    # ----------------------------------------------------------- geometry
    def _content_height(self) -> int:
        rows = len(self._layout.rows) if self._layout is not None else 0
        notes = len(self._layout.notes) if self._layout is not None else 0
        return _MARGIN + _INFO_H + rows * _ROW_H + notes * 16 + _MARGIN + 6

    def _row_rect(self, index: int, height: int) -> QRect:
        x = _MARGIN
        w = max(self.viewport().width() - 2 * _MARGIN, 40)
        y = _MARGIN + _INFO_H + (index - self.verticalScrollBar().value()) * _ROW_H
        return QRect(x, y, w, _ROW_H - 2)

    def row_at(self, y: int, height: int) -> StackRow | None:
        """The diagram row under viewport coordinate *y* (or None)."""
        if self._layout is None:
            return None
        offset = (y - (_MARGIN + _INFO_H)) + self.verticalScrollBar().value()
        index = int(offset // _ROW_H)
        if 0 <= index < len(self._layout.rows):
            return self._layout.rows[index]
        return None

    # ------------------------------------------------------------- paint
    def _columns(self, width: int) -> dict[str, Any]:
        """Fixed row-column geometry for viewport *width* (kept testable).

        Columns fold progressively on narrow docks: the proportional bar,
        then the pointer annotation, then the label disappear, so the raw
        value always stays visible and nothing ever exceeds the viewport
        edge. Text rects with ``width() <= 8`` are not drawn.
        """
        right_edge = max(width - 6, 40)
        value_w = min(170, max(right_edge // 3, 80))
        value_rect = QRect(right_edge - value_w, 0, value_w, 0)
        columns: dict[str, Any] = {
            "addr": QRect(4, 0, min(130, right_edge - 8), 0),
            "offsets": QRect(0, 0, 0, 0),
            "label": QRect(0, 0, 0, 0),
            "annot": QRect(0, 0, 0, 0),
            "value": value_rect,
            "bar_x": 0,
            "bar_x1": 0,  # degenerate → bar + chip skipped while scrolling
        }
        offsets_w = max(min(168, value_rect.left() - 146), 0)
        columns["offsets"] = QRect(140, 0, offsets_w, 0)
        if width < 540 or offsets_w < 60:  # too narrow: skip fold-able extras
            return columns
        columns["bar_x"] = 312
        cluster_left = value_rect.left() - 12
        if width >= 700:  # pointer annotation only when it fits
            annot_rect = QRect(cluster_left - 110, 0, 110, 0)
            cluster_left = annot_rect.left() - 4
            columns["annot"] = annot_rect
        label_w = 158 if width >= 880 else (90 if width >= 640 else 0)
        if label_w:
            label_rect = QRect(cluster_left - label_w, 0, label_w, 0)
            cluster_left = label_rect.left()
            columns["label"] = label_rect
        bar_x1 = cluster_left - 8
        if bar_x1 - 312 < 24 and columns["label"].width():
            # fold the label first so the proportional bar keeps its zone
            columns["label"] = QRect(0, 0, 0, 0)
            cluster_left = columns["annot"].left() - 4
            bar_x1 = cluster_left - 8
        columns["bar_x1"] = bar_x1 if bar_x1 - 312 >= 24 else 0
        if not columns["bar_x1"]:
            columns["bar_x"] = 0
        return columns

    def paintEvent(self, event: Any) -> None:  # noqa: N802 (Qt name)
        tokens = self._tokens()
        painter = QPainter(self.viewport())
        self._paint_body(painter, tokens, self.viewport().size())
        painter.end()

    def _paint_body(
        self, painter: QPainter, tokens: dict[str, str], size: Any
    ) -> None:
        width, height = size.width(), size.height()
        painter.fillRect(0, 0, width, height, QColor(tokens["bg"]))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        layout = self._layout
        fm = QFontMetrics(self.font())
        if layout is None:
            self._paint_empty(painter, tokens, fm, width, height)
            return

        # keep the vertical scrollbar in sync with the content
        scrollbar = self.verticalScrollBar()
        scrollbar.setPageStep(max(_ROW_H * 3, 1))
        scrollbar.setRange(0, max(0, self._content_height() - height))

        mono = QFont(self.font())
        mono.setBold(True)
        info_y = _MARGIN
        painter.setPen(QColor(tokens["dim"]))
        elided_info = fm.elidedText(
            f"{layout.func_name} · {layout.arch} · rbp={self._h(layout.rbp)} "
            f"rsp={self._h(layout.rsp)} · source: {layout.source}",
            Qt.TextElideMode.ElideRight,
            width - 2 * _MARGIN,
        )
        painter.drawText(_MARGIN, info_y + fm.ascent(), elided_info)

        top = layout.rbp + 2 * layout.word if layout.rbp is not None else layout.rsp + 1
        span = max(top - layout.rsp, layout.word)
        cols = self._columns(width)
        bar_x = cols["bar_x"]
        bar_x1 = cols["bar_x1"]
        bar_zone = max(bar_x1 - bar_x, 24)

        for index, row in enumerate(layout.rows):
            rect = self._row_rect(index, height)
            if rect.bottom() < _MARGIN or rect.top() > height - _MARGIN:
                continue  # outside the visible scroll region
            bg, fg, border = KIND_TOKENS.get(row.kind, ("panel", "fg", "border"))
            painter.fillRect(rect, QColor(tokens[bg]))
            painter.setPen(QColor(tokens[border]))
            painter.drawRect(rect.adjusted(0, 0, -1, -1))
            painter.setPen(QColor(tokens[fg]))

            # -- address column
            painter.setPen(QColor(tokens["dim"]))
            addr_text = f"{row.address:#x}"
            if row.marker:
                chip = "RBP" if row.marker == "rbp" else "RSP"
                addr_text = f"${chip} {addr_text}"
            addr_rect = QRect(
                cols["addr"].left(), rect.y(), cols["addr"].width(), rect.height()
            )
            shown = fm.elidedText(addr_text, Qt.TextElideMode.ElideLeft, addr_rect.width() - 4)
            if shown.startswith("…"):
                # keep addresses readable: drop the (redundant) 0x prefix first
                shown = fm.elidedText(
                    addr_text.replace("0x", "", 1), Qt.TextElideMode.ElideLeft,
                    addr_rect.width() - 4,
                )
            painter.drawText(
                addr_rect,
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                shown,
            )
            # -- offsets column (hidden on very narrow docks)
            if cols["offsets"].width() > 8:
                rbp_off = (
                    f"rbp{row.offset_rbp:+#x}"
                    if row.offset_rbp is not None
                    else "rbp?"
                )
                rsp_off = f"rsp{row.offset_rsp:+#x}"
                host_text = f"{rbp_off} {rsp_off} {row.size}B"
                painter.drawText(
                    QRect(
                        cols["offsets"].left(), rect.y(),
                        cols["offsets"].width(), rect.height(),
                    ),
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                    fm.elidedText(
                        host_text, Qt.TextElideMode.ElideRight,
                        cols["offsets"].width() - 4,
                    ),
                )
            # -- proportional bar (position = address span); hidden when folded
            bar_height = rect.height() - 4
            bar_visible = bar_x1 > bar_x
            if bar_visible:
                start_px = (
                    bar_x + (top - (row.address + max(row.size, 1))) / span * bar_zone
                )
                width_px = max(row.size / span * bar_zone, 6.0)
                bar_rect = QRect(
                    int(start_px), rect.y() + 2, int(min(width_px, bar_zone)), bar_height
                )
                bar_rect = bar_rect.intersected(
                    QRect(bar_x - 2, rect.y(), bar_zone + 4, rect.height())
                )
                bar_color = QColor(tokens["accent"])
                if row.kind in ("gap", "local", "window"):
                    bar_color = QColor(tokens["panel_alt"])
                painter.fillRect(bar_rect, bar_color)
                if row.kind in ("gap", "local", "window"):
                    painter.setPen(QColor(tokens["border"]))
                    painter.drawRect(bar_rect)
                # -- marker chip pinned at the bar end (RSP/RBP position)
                if row.marker:
                    chip_zone = QRect(bar_x1 - 34, rect.y() + 2, 34, bar_height)
                    painter.fillRect(chip_zone, QColor(tokens["accent"]))
                    painter.setPen(QColor(tokens["on_accent"]))
                    chip_text = "RBP" if row.marker == "rbp" else "RSP"
                    painter.drawText(
                        chip_zone,
                        Qt.AlignmentFlag.AlignCenter,
                        chip_text,
                    )
            if row.address in self._changed and row.value is not None:
                painter.setPen(QPen(QColor(tokens["accent"]), 2))
                painter.drawRect(rect.adjusted(-2, -2, 1, 1))
            # -- marker chip pinned at the bar end (RSP/RBP position)
            if row.marker:
                chip_zone = QRect(bar_x1 - 34, rect.y() + 2, 34, bar_height)
                painter.fillRect(chip_zone, QColor(tokens["accent"]))
                painter.setPen(QColor(tokens["on_accent"]))
                chip_text = "RBP" if row.marker == "rbp" else "RSP"
                painter.drawText(
                    chip_zone,
                    Qt.AlignmentFlag.AlignCenter,
                    chip_text,
                )
            # -- raw value column (rightmost)
            value_text = (
                f"{row.value:#0{layout.word * 2 + 2}x}" if row.value is not None else "—"
            )
            painter.setPen(QColor(tokens["fg"]))
            painter.drawText(
                QRect(cols["value"].left(), rect.y(), cols["value"].width(), rect.height()),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                fm.elidedText(value_text, Qt.TextElideMode.ElideLeft, cols["value"].width() - 4),
            )
            # -- annotation column (hidden when it doesn't fit)
            if cols["annot"].width() > 8:
                painter.setPen(
                    QColor(tokens["accent"]) if row.is_pointer else QColor(tokens["dim"])
                )
                painter.drawText(
                    QRect(cols["annot"].left(), rect.y(), cols["annot"].width(), rect.height()),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    fm.elidedText(row.annotation, Qt.TextElideMode.ElideLeft, cols["annot"].width() - 4),
                )
            # -- label column (hidden when it doesn't fit)
            if cols["label"].width() > 8:
                painter.setPen(QColor(tokens[fg]))
                label = row.label or KIND_LABEL.get(row.kind, "")
                painter.drawText(
                    QRect(cols["label"].left(), rect.y(), cols["label"].width(), rect.height()),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    fm.elidedText(label, Qt.TextElideMode.ElideRight, cols["label"].width() - 4),
                )

        # notes footer
        notes_y = _MARGIN + _INFO_H + len(layout.rows) * _ROW_H + 2
        painter.setPen(QColor(tokens["dim"]))
        for note in layout.notes:
            painter.drawText(
                _MARGIN, notes_y + fm.ascent(),
                fm.elidedText(f"· {note}", Qt.TextElideMode.ElideRight, width - 2 * _MARGIN),
            )
            notes_y += 16

    @staticmethod
    def _h(value: int | None) -> str:
        return f"{value:#x}" if value is not None else "?"

    def _paint_empty(
        self,
        painter: QPainter,
        tokens: dict[str, str],
        fm: QFontMetrics,
        width: int,
        height: int,
    ) -> None:
        self.verticalScrollBar().setRange(0, 0)
        painter.setPen(QColor(tokens["dim"]))
        text = self._empty_text
        # rough word wrap into the paint area
        max_chars = max(24, width // int(max(fm.horizontalAdvance("M"), 1)) - 2)
        lines: list[str] = []
        words = text.split()
        while words:
            line = ""
            while words and len(line) + len(words[0]) + 1 <= max_chars:
                line = f"{line} {words.pop(0)}".strip()
            lines.append(line or words.pop(0))
        block_h = len(lines) * (fm.height() + 4)
        y = max(height // 2 - block_h // 2, _MARGIN + 4)
        for line in lines:
            painter.drawText(0, y + fm.ascent(), width, fm.height(), Qt.AlignmentFlag.AlignHCenter, line)
            y += fm.height() + 4
        painter.setPen(QColor(tokens["accent_dim"]))
        hint = "The diagram fills in automatically once the debugger stops."
        painter.drawText(0, y + 8 + fm.ascent(), width, fm.height(), Qt.AlignmentFlag.AlignHCenter, hint)

    # -------------------------------------------------------------- input
    def mousePressEvent(self, event: Any) -> None:  # noqa: N802 (Qt name)
        self._emit_row_selection(event.position().toPoint().y())
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: Any) -> None:  # noqa: N802 (Qt name)
        row = self.row_at(event.position().toPoint().y(), self.viewport().height())
        if row is not None and row.is_pointer and row.value:
            self._plugin.ctx.bus.publish(
                T_MEMORY_GOTO_REQUEST, {"address": int(row.value), "size": 256}
            )
        super().mouseDoubleClickEvent(event)

    def _emit_row_selection(self, y: int) -> None:
        row = self.row_at(y, self.viewport().height())
        if row is not None:
            self._plugin.ctx.bus.publish(ADDRESS_SELECTED, {"address": row.address})


class StackVisualizerPlugin(Plugin):
    """Dockable stack frame visualizer."""

    name = "Stack Visualizer"
    description = "Live stack frame diagram: buffers, canary, saved RBP, return address."
    icon = "🧱"

    # ---------------------------------------------------------------- widget
    def widget(self) -> QWidget:
        if getattr(self, "_panel", None) is not None:
            return self._panel  # one panel per plugin; rebuilding would swap the view
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(4)

        # -------------------------------------------------- toolbar row
        bar = QHBoxLayout()
        self._frame_combo = QComboBox()
        self._frame_combo.setToolTip("Select the frame level to inspect")
        self._frame_combo.setMinimumWidth(220)
        self._frame_combo.currentIndexChanged.connect(self._frame_changed)
        refresh = QPushButton("Refresh")
        refresh.setToolTip("Re-read registers + stack window for the current frame")
        refresh.clicked.connect(self._request_context)
        copy_all = QPushButton("Copy distances")
        copy_all.setToolTip("Copy every distance to the clipboard (one per line)")
        copy_all.clicked.connect(self._copy_all_distances)
        bar.addWidget(QLabel("Frame:"))
        bar.addWidget(self._frame_combo, 0, Qt.AlignmentFlag.AlignLeft)
        bar.addWidget(refresh)
        bar.addStretch(1)
        bar.addWidget(copy_all)
        outer.addLayout(bar)

        # -------------------------------------------------- distances strip
        self._distances_host = QWidget()
        self._distances_row = QHBoxLayout(self._distances_host)
        self._distances_row.setContentsMargins(0, 0, 0, 0)
        self._distances_row.setSpacing(6)
        outer.addWidget(self._distances_host)

        # -------------------------------------------------- main diagram
        self._view = StackFrameView(self)
        mono = QFont(resolve_monospace(self.ctx.settings.get("font.mono_family") or ""))
        mono.setPointSizeF(max(mono.pointSizeF() - 1.0, 8.0))
        self._view.setFont(mono)
        self._view.set_frame(None, frozenset(), self._empty_no_gdb_text())
        outer.addWidget(self._view, 1)

        # -------------------------------------------------- state
        self._model: BinaryModel | None = None
        self._unsub: Any = None
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._closing = False
        self._worker: threading.Thread | None = None
        # worker-visible snapshot (guarded by _lock; latest wins)
        self._regs: dict[str, str] | None = None
        self._window: tuple[int, bytes] | None = None
        self._frames: list[dict[str, Any]] = []
        self._level = 0
        self._running_state = "idle"
        self._delta_main: int | None = None
        self._eval_requested = False
        self._prev_values: dict[int, int] = {}
        self._disassembler: Any = None
        self._func_starts: dict[int, int] = {}
        return panel

    def _empty_no_gdb_text(self) -> str:
        return (
            "Load a binary, start a debug session (open the Debugger dock, set a "
            "breakpoint, run) and the frame diagram appears here with live "
            "values. gdb missing → every static module keeps working."
        )

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
        self._closing = True
        self._wake.set()
        with suppress(Exception):
            self._unsub()
        worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=1.0)

    def _on_theme_changed(self, theme: Any) -> None:
        self._view.viewport().update()
        self._view.update()

    # -------------------------------------------------------------- events / UI
    def on_event(self, topic: str, payload: Any) -> None:
        """UI thread: record runtime snapshots, wake the worker."""
        if topic == BINARY_LOADED and isinstance(payload, dict):
            model = payload.get("model")
            if model is not None:
                self._model = model
                self._delta_main = None
                self._eval_requested = False
                self._view.clear_frame(self._empty_no_gdb_text())
            self._maybe_request_eval()
        elif topic == BINARY_CLOSED:
            self._model = None
            self._view.clear_frame(self._empty_no_gdb_text())
        elif topic == T_STATE and isinstance(payload, dict):
            self._running_state = str(payload.get("state", self._running_state))
            if self._running_state in ("exited", "idle", "running"):
                self._view.clear_frame(
                    "No stopped debuggee — run to a breakpoint so registers and "
                    "the stack window exist, then the diagram reappears."
                    if self._running_state != "running"
                    else "Program is running — the diagram resumes at the next stop."
                )
            self._wake_worker()
        elif topic == T_STOPPED and isinstance(payload, dict):
            self._running_state = "stopped"
            if payload.get("regs"):
                self._store_regs(payload["regs"])
            self._request_context()
        elif topic == T_REGISTERS and isinstance(payload, dict):
            self._store_regs(payload)
            self._wake_worker()
        elif topic in (T_STACK_WORDS, T_MEMORY_READ) and isinstance(payload, dict):
            self._store_window(payload)
            self._wake_worker()
        elif topic == T_BACKTRACE and isinstance(payload, dict):
            self._store_frames(payload.get("frames") or [])
        elif topic == T_EXITED:
            self._running_state = "exited"
            self._view.clear_frame(
                "Debuggee exited — start it again to analyze a fresh frame."
            )
        elif topic == T_EVAL and isinstance(payload, dict):
            self._store_eval(payload)
        elif topic == STACK_FRAME_READY and isinstance(payload, dict):
            self._on_frame_ready(payload)

    def _store_regs(self, payload: Any) -> None:
        values = payload.get("values") if isinstance(payload, dict) else payload
        if isinstance(values, dict) and values:
            with self._lock:
                self._regs = dict(values)

    def _store_window(self, payload: dict[str, Any]) -> None:
        hexdata = payload.get("hex")
        if not hexdata:
            rows = payload.get("words") or []
            pairs = []
            for row in rows:
                word_hex = str(row.get("word_hex", "")).rjust(16, "0")
                pairs.append(word_hex)
            if pairs:
                hexdata = "".join(pairs)
            base = payload.get("base")
        else:
            base = payload.get("address")
        base_addr = _hexint(base)
        try:
            data = bytes.fromhex(str(hexdata)) if hexdata else b""
        except ValueError:
            data = b""
        if base_addr is None or not data:
            return
        with self._lock:
            self._window = (base_addr, data)

    def _store_frames(self, frames: list[Any]) -> None:
        with self._lock:
            self._frames = [f for f in frames if isinstance(f, dict)]
            current = self._level
        self._refresh_frame_combo()
        with suppress(Exception):
            self._frame_combo.setCurrentIndex(min(current, max(self._frame_combo.count() - 1, 0)))

    def _store_eval(self, payload: dict[str, Any]) -> None:
        expr = str(payload.get("expr", ""))
        if expr != "&main":
            return
        runtime = _hexint(payload.get("value"))
        static = self._static_main_addr()
        if runtime is None or static is None:
            return
        with self._lock:
            self._delta_main = runtime - static
        self._wake_worker()

    def _refresh_frame_combo(self) -> None:
        self._frame_combo.blockSignals(True)
        self._frame_combo.clear()
        for frame in self._frames:
            level = str(frame.get("level", "?"))
            func = str(frame.get("func", "")) or str(frame.get("file", "")) or "?"
            self._frame_combo.addItem(f"#{level} {func}")
        self._frame_combo.blockSignals(False)

    def wake_worker(self) -> None:  # exposed for tests
        self._wake_worker()

    def _wake_worker(self) -> None:
        with self._lock:
            if self._running_state != "stopped":
                # nothing to analyze (also stops a stale analysis after exit)
                return
            need_worker = self._worker is None
            if need_worker:
                self._worker = threading.Thread(
                    target=self._worker_main, name="80pwner-stackviz", daemon=True
                )
        if need_worker:
            self._worker.start()
        self._wake.set()

    # ---------------------------------------------------------- worker results
    def _on_frame_ready(self, payload: dict[str, Any]) -> None:
        """UI thread: swap the model in and rebuild the distance strip."""
        layout = payload.get("layout")
        changed = payload.get("changed") or []
        # clear buttons *and* accumulated stretch items
        while self._distances_row.count():
            item = self._distances_row.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if layout is None:
            self._view.set_frame(
                None, frozenset(), str(payload.get("error") or self._empty_no_gdb_text())
            )
            return
        self._view.set_frame(layout, frozenset(changed))
        self._distances_host.setFixedHeight(34)  # never collapses during relayouts
        distances = frame_distances(layout)
        for display, _dist in distances:
            button = QPushButton(f"⧉ {display}")
            button.setToolTip(f"Click to copy: {display}")
            button.clicked.connect(lambda _=False, text=display: _copy(text))
            self._distances_row.addWidget(button)
        self._distances_row.addStretch(1)
        self._distances_host.setVisible(True)

    def _copy_all_distances(self) -> None:
        texts = [
            self._distances_row.itemAt(i).widget().text().removeprefix("⧉ ")
            for i in range(self._distances_row.count())
            if isinstance(self._distances_row.itemAt(i).widget(), QPushButton)
        ]
        if texts:
            _copy("\n".join(texts))

    # ---------------------------------------------------------------- frame UI
    def _frame_changed(self, index: int) -> None:
        if index < 0:
            return
        frames = self._frames
        if 0 <= index < len(frames):
            with suppress(TypeError, ValueError):
                level = int(str(frames[index].get("level", "0")))
                self._level = level
        self._request_context()

    def _request_context(self) -> None:
        """Ask the engine for the selected frame's registers + SP window."""
        with self._lock:
            level = self._level
        self.ctx.bus.publish(
            T_STACK_CONTEXT_REQUEST, {"level": level, "window": FRAME_WINDOW_BYTES}
        )

    # ------------------------------------------------------------- PIE eval
    def _static_main_addr(self) -> int | None:
        model = self._model
        if model is None:
            return None
        for symbol in model.symbols:
            if symbol.name == "main":
                return symbol.value
        return None

    def _maybe_request_eval(self) -> None:
        """PIE binaries need the runtime main address for annotations."""
        model = self._model
        if model is None or self._eval_requested:
            return
        statuses = {item.name: item.status for item in model.checksec}
        if statuses.get("PIE") != "enabled" or self._static_main_addr() is None:
            return
        self._eval_requested = True
        self.ctx.bus.publish(T_STACK_EVAL_REQUEST, {"expr": "&main"})

    # ----------------------------------------------------------------- worker
    def _worker_main(self) -> None:
        while not self._closing:
            self._wake.wait(0.5)
            self._wake.clear()
            if self._closing:
                return
            try:
                result = self._analyze()
            except Exception:
                log.exception("Stack frame analysis failed")
                result = (None, frozenset(), self._empty_no_gdb_text())
            layout, changed, error = result
            self.ctx.bus.publish(
                STACK_FRAME_READY,
                {
                    "layout": layout,
                    "changed": sorted(changed),
                    "error": error,
                },
            )

    def _analyze(self) -> tuple[FrameLayout | None, frozenset[int], str]:
        with self._lock:
            model = self._model
            regs = self._regs
            window = self._window
            frames = list(self._frames)
            level = self._level
            delta = self._delta_main
        empty = (None, frozenset(), self._empty_no_gdb_text())
        if model is None:
            return empty
        if self._running_state != "stopped":
            return (
                None,
                frozenset(),
                "No stopped debuggee — run to a breakpoint so registers and the "
                "stack window exist.",
            )
        if regs is None or window is None:
            return (
                None,
                frozenset(),
                "Waiting for the debugger's register + stack snapshot — set a "
                "breakpoint and hit it, or press Refresh.",
            )

        word = word_size_for_arch(model.arch)
        if word is None:
            layout = analyze_frame(
                arch=model.arch,
                frame_level=level,
                func_name=self._frame_name(frames, level),
                pc=0,
                rbp=None,
                rsp=0,
                window_base=0,
                window_bytes=b"",
                hints=None,
            )
            return layout, frozenset(), layout.notes[0] if layout.notes else ""

        rbp_name = "$rbp" if word == 8 else "$ebp"
        rsp = _hexint(regs.get("$rsp") or regs.get("$esp"))
        rbp = _hexint(regs.get(rbp_name))
        pc = _hexint(regs.get("$rip") or regs.get("$eip") or regs.get("$pc"))
        if rsp is None:
            return (
                None,
                frozenset(),
                "No SP value in the register snapshot — the frame cannot be "
                "located.",
            )
        window_base, window_bytes = window
        compat_pc = pc if pc is not None else 0

        frame_name = self._frame_name(frames, level)
        frame_addr = self._frame_addr(frames, level) or compat_pc
        hints = self._function_hints(model, frame_addr)
        dwarf_vars = self._dwarf_vars(model, frame_addr)
        canary_enabled = "enabled" in {
            item.name: item.status for item in model.checksec
        }.get("Stack canary", "")
        symbols = [(s.value, s.name, s.size) for s in model.symbols]
        layout = analyze_frame(
            arch=model.arch,
            frame_level=level,
            func_name=frame_name,
            pc=compat_pc,
            rbp=rbp,
            rsp=rsp,
            window_base=window_base,
            window_bytes=window_bytes,
            hints=hints,
            dwarf_vars=dwarf_vars,
            canary_enabled=canary_enabled,
            text_delta=delta or 0,
            symbols=symbols,
        )
        changed = self._diff_values(layout)
        return layout, changed, ""

    @staticmethod
    def _frame_name(frames: list[dict[str, Any]], level: int) -> str:
        for frame in frames:
            if str(frame.get("level", "")) == str(level):
                return str(frame.get("func", "")) or "?"
        return "?"

    @staticmethod
    def _frame_addr(frames: list[dict[str, Any]], level: int) -> int | None:
        for frame in frames:
            if str(frame.get("level", "")) == str(level):
                return _hexint(frame.get("address"))
        return None

    def _function_hints(self, model: BinaryModel, frame_addr: int) -> Any:
        """Disassembly hints for the function containing *frame_addr*."""
        with self._lock:
            disassembler = self._disassembler
        if disassembler is None or getattr(disassembler, "model", None) is not model:
            try:
                from eightypwner.engines.disassembler import Disassembler

                disassembler = Disassembler(model)
                self._disassembler = disassembler
            except Exception:  # capstone missing / unsupported arch
                log.debug("Disassembler unavailable for frame hints", exc_info=True)
                return None
        start = self._function_start(model, frame_addr)
        if start is None:
            return None
        try:
            instructions = list(disassembler.decode_function(start))
        except Exception:
            log.debug("Function decode failed at %#x", start, exc_info=True)
            return None
        from eightypwner.engines.stack_frame import hints_from_instructions

        return hints_from_instructions(instructions, bits=model.bits)

    def _function_start(self, model: BinaryModel, frame_addr: int) -> int | None:
        """Best-known start address of the function containing *frame_addr*."""
        candidates = [
            symbol
            for symbol in model.symbols
            if symbol.value <= frame_addr
            and (symbol.size == 0 or frame_addr < symbol.value + symbol.size)
        ]
        executable_first = [
            symbol for symbol in candidates if symbol.size > 0
        ] or candidates
        if executable_first:
            return min(executable_first, key=lambda s: (s.size or 1, s.value)).value
        # no usable symbol: static discovery as a fallback (cached)
        with self._lock:
            cached = self._func_starts.get(frame_addr)
        if cached is not None:
            return cached
        try:
            from eightypwner.engines.functions import FunctionFinder

            index = FunctionFinder(model).discover()
            start = next(
                (
                    func.address
                    for func in index.functions
                    if func.address <= frame_addr < func.address + max(func.size, 1)
                ),
                None,
            )
        except Exception:
            log.debug("Function discovery failed", exc_info=True)
            return None
        with self._lock:
            if start is not None:
                self._func_starts[frame_addr] = start
        return start

    def _dwarf_vars(self, model: BinaryModel, frame_addr: int) -> list[Any]:
        from eightypwner.engines.stack_frame import dwarf_frame_variables

        try:
            return dwarf_frame_variables(model.path, frame_addr)
        except Exception:  # malformed DWARF never breaks the dock
            log.debug("DWARF lookup failed", exc_info=True)
            return []

    def _diff_values(self, layout: FrameLayout) -> frozenset[int]:
        """Addresses whose word value changed since the previous stop."""
        with self._lock:
            previous = self._prev_values
        changed: set[int] = set()
        current: dict[int, int] = {}
        for row in layout.rows:
            if row.value is None:
                continue
            current[row.address] = row.value
            if row.address in previous and previous[row.address] != row.value:
                changed.add(row.address)
        with self._lock:
            self._prev_values = current
        return frozenset(changed)
