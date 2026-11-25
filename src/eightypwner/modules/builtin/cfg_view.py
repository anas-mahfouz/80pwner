# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Control Flow dock (Step 7 A) — interactive basic-block graph.

Renders the CFG reachable from a function entry (or any address) with layered
layout, colored exits (ret / conditional / indirect), click-through to the
disassembler, a block inspector, and DOT export for writeups.

Builds happen in a worker thread; the UI only receives finished
``CfgResult`` objects (via a queued signal), so large functions never freeze
the workbench.
"""

from __future__ import annotations

import logging
import threading
from contextlib import suppress
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtWidgets import (
    QComboBox,
    QCompleter,
    QGraphicsPathItem,
    QGraphicsPolygonItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import (
    ADDRESS_SELECTED,
    BINARY_CLOSED,
    BINARY_LOADED,
    FUNCTION_SELECTED,
    FUNCTIONS_DISCOVERED,
)
from eightypwner.engines.cfg import CfgResult, build_cfg
from eightypwner.modules.builtin.common import Relay, copy_text, elide, mono_font, parse_int
from eightypwner.modules.interface import Plugin

log = logging.getLogger(__name__)

NODE_WIDTH = 300.0
NODE_HEADER = 20.0
LINE_HEIGHT = 13.0
MAX_NODE_INSNS = 5
COLUMN_GAP = 90.0
ROW_GAP = 24.0
MAX_COMBO_FUNCTIONS = 4000


class CfgView(QGraphicsView):
    """Zoomable/pannable graph view; emits the block address on click."""

    block_clicked = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setBackgroundBrush(QBrush(QColor("#0F1418")))
        self._scale = 1.0

    # ------------------------------------------------------------------ input
    def wheelEvent(self, event: Any) -> None:  # noqa: N802
        factor = 1.18 if event.angleDelta().y() > 0 else 1 / 1.18
        new_scale = self._scale * factor
        if 0.2 <= new_scale <= 5.0:
            self._scale = new_scale
            self.scale(factor, factor)

    def mousePressEvent(self, event: Any) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            item = self.itemAt(event.pos())
            while item is not None:
                address = item.data(0)
                if isinstance(address, int):
                    self.block_clicked.emit(address)
                    break
                item = item.parentItem()
        super().mousePressEvent(event)

    def fit_graph(self) -> None:
        scene = self.scene()
        if scene is None or not scene.items():
            return
        rect = scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)
        self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
        self._scale = self.transform().m11()

    # ------------------------------------------------------------------ paint
    def set_graph(self, result: CfgResult, tokens: dict[str, str]) -> None:
        scene = self.scene()
        if scene is None:
            return
        scene.clear()
        self.resetTransform()
        self._scale = 1.0
        self.setBackgroundBrush(QBrush(QColor(tokens.get("bg", "#0F1418"))))
        blocks = result.sorted_blocks()
        if not blocks:
            return

        adjacency: dict[int, list[int]] = {block.start: [] for block in blocks}
        for edge in result.edges:
            if edge.src in adjacency and edge.dst in adjacency:
                adjacency[edge.src].append(edge.dst)
        depth: dict[int, int] = {result.entry: 0}
        queue = [result.entry]
        while queue:
            current = queue.pop(0)
            for target in adjacency.get(current, ()):
                if target not in depth or depth[target] > depth[current] + 1:
                    depth[target] = depth[current] + 1
                    queue.append(target)
        for block in blocks:
            depth.setdefault(block.start, 0)

        columns: dict[int, list[Any]] = {}
        for block in blocks:
            columns.setdefault(depth[block.start], []).append(block)
        positions: dict[int, QRectF] = {}
        for column, column_blocks in columns.items():
            y = 0.0
            x = column * (NODE_WIDTH + COLUMN_GAP)
            for block in sorted(column_blocks, key=lambda b: b.start):
                lines = min(len(block.insns), MAX_NODE_INSNS)
                height = NODE_HEADER + max(lines, 1) * LINE_HEIGHT + 8
                positions[block.start] = QRectF(x, y, NODE_WIDTH, height)
                y += height + ROW_GAP

        # edges first so nodes paint above them
        for edge in result.edges:
            if edge.src not in positions or edge.dst not in positions:
                continue
            self._draw_edge(positions[edge.src], positions[edge.dst], edge.kind, tokens)

        entry = result.entry
        for block in blocks:
            self._draw_node(block, positions[block.start], tokens, is_entry=block.start == entry)

        rect = scene.itemsBoundingRect()
        scene.setSceneRect(rect.adjusted(-40, -40, 40, 40))
        self.fit_graph()

    def _draw_node(self, block: Any, rect: QRectF, tokens: dict[str, str], is_entry: bool) -> None:
        scene = self.scene()
        if scene is None:
            return
        fill = {
            "ret": tokens.get("warn_bg", "#33230C"),
            "indirect": tokens.get("warn_bg", "#33230C"),
            "trunc": tokens.get("panel_alt", "#1C2429"),
            "cond": tokens.get("panel_alt", "#1C2429"),
        }.get(block.terminal, tokens.get("panel", "#161B20"))
        border = tokens.get("accent", "#FF2D3D") if is_entry else tokens.get("border", "#2A333A")
        item = QGraphicsRectItem(rect)
        item.setBrush(QBrush(QColor(fill)))
        item.setPen(QPen(QColor(border), 2.0 if is_entry else 1.0))
        item.setData(0, int(block.start))
        item.setToolTip(
            f"{block.start:#x}-{block.end:#x} ({block.size} bytes, {len(block.insns)} insns)\n"
            f"exit: {block.terminal}"
        )
        scene.addItem(item)

        title = QGraphicsSimpleTextItem(
            f"{block.start:#x}  ·  {block.terminal}  ·  {len(block.insns)} insns",
            item,
        )
        title_font = QFont("Monospace")
        title_font.setPointSize(8)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setBrush(QBrush(QColor(tokens.get("accent", "#FF2D3D") if is_entry else tokens.get("fg", "#E8F0EC"))))
        title.setPos(rect.left() + 8, rect.top() + 4)
        title.setAcceptedMouseButtons(Qt.MouseButton.NoButton)

        body_font = QFont("Monospace")
        body_font.setPointSize(7)
        for index, insn in enumerate(block.insns[:MAX_NODE_INSNS]):
            line = QGraphicsSimpleTextItem(
                elide(f"{insn.address:#x}  {insn.text()}", 42),
                item,
            )
            line.setFont(body_font)
            line.setBrush(QBrush(QColor(tokens.get("dim", "#9AA8A2"))))
            line.setPos(rect.left() + 8, rect.top() + NODE_HEADER + index * LINE_HEIGHT)
            line.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
        if len(block.insns) > MAX_NODE_INSNS:
            more = QGraphicsSimpleTextItem(f"… {len(block.insns) - MAX_NODE_INSNS} more", item)
            more.setFont(body_font)
            more.setBrush(QBrush(QColor(tokens.get("dim", "#9AA8A2"))))
            more.setPos(rect.left() + 8, rect.bottom() - LINE_HEIGHT - 2)
            more.setAcceptedMouseButtons(Qt.MouseButton.NoButton)

    def _draw_edge(self, src: QRectF, dst: QRectF, kind: str, tokens: dict[str, str]) -> None:
        scene = self.scene()
        if scene is None:
            return
        color = {
            "true": tokens.get("ok", "#34D399"),
            "false": tokens.get("error", "#9E1B26"),
            "external": tokens.get("warn", "#FFB454"),
            "jump": tokens.get("dim", "#9AA8A2"),
        }.get(kind, tokens.get("border", "#2A333A"))
        pen = QPen(QColor(color), 1.4)
        if kind == "fallthrough":
            pen.setStyle(Qt.PenStyle.DashLine)
        path = QPainterPath()
        if dst.left() > src.right() + 8:
            start = QPointF(src.right(), src.center().y())
            end = QPointF(dst.left(), dst.center().y())
            mid = (start.x() + end.x()) / 2
            path.moveTo(start)
            path.cubicTo(QPointF(mid, start.y()), QPointF(mid, end.y()), end)
            direction = QPointF(1, 0)
        elif dst.center().y() > src.center().y():
            start = QPointF(src.center().x(), src.bottom())
            end = QPointF(dst.center().x(), dst.top())
            path.moveTo(start)
            path.cubicTo(
                QPointF(start.x(), start.y() + 40),
                QPointF(end.x(), end.y() - 40),
                end,
            )
            direction = QPointF(0, 1)
        else:
            start = QPointF(src.center().x(), src.top())
            end = QPointF(dst.center().x(), dst.bottom())
            path.moveTo(start)
            path.cubicTo(
                QPointF(start.x() - 60, start.y() - 40),
                QPointF(end.x() - 60, end.y() + 40),
                end,
            )
            direction = QPointF(0, -1)
        arrow = QGraphicsPathItem(path)
        arrow.setPen(pen)
        scene.addItem(arrow)

        tip = end
        size = 7.0
        if direction.x():
            points = [
                tip,
                QPointF(tip.x() - size, tip.y() - size / 1.6),
                QPointF(tip.x() - size, tip.y() + size / 1.6),
            ]
        else:
            points = [
                tip,
                QPointF(tip.x() - size / 1.6, tip.y() - size * (1 if direction.y() > 0 else -1)),
                QPointF(tip.x() + size / 1.6, tip.y() - size * (1 if direction.y() > 0 else -1)),
            ]
        head = QGraphicsPolygonItem(QPolygonF(points))
        head.setBrush(QBrush(QColor(color)))
        head.setPen(QPen(QColor(color)))
        scene.addItem(head)


class CfgPlugin(Plugin):
    name = "Control Flow"
    description = "Interactive basic-block CFG for any function, with DOT export."
    icon = "🕸"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._panel: QWidget | None = None
        self._view: CfgView | None = None
        self._model: Any = None
        self._index: Any = None
        self._result: CfgResult | None = None
        self._request = 0
        self._last_build: int | None = None
        self._build_thread: threading.Thread | None = None
        self._closing = False
        self._block_text: QPlainTextEdit | None = None

    # ------------------------------------------------------------------ widget
    def widget(self) -> QWidget:
        if self._panel is not None:
            return self._panel
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(4)

        bar = QHBoxLayout()
        bar.addWidget(QLabel("Function:"))
        self._func_combo = QComboBox()
        self._func_combo.setEditable(True)
        self._func_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self._func_combo.setMinimumWidth(180)
        completer = QCompleter(self._func_combo.model(), self._func_combo)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self._func_combo.setCompleter(completer)
        self._func_combo.activated.connect(self._on_combo_activated)
        bar.addWidget(self._func_combo, 2)

        self._addr_edit = QLineEdit()
        self._addr_edit.setPlaceholderText("address 0x…")
        self._addr_edit.setMaximumWidth(150)
        self._addr_edit.returnPressed.connect(self._build_from_edit)
        bar.addWidget(self._addr_edit)
        go = QPushButton("Go")
        go.clicked.connect(self._build_from_edit)
        bar.addWidget(go)
        rebuild = QPushButton("Rebuild")
        rebuild.clicked.connect(lambda: self._build_for(self._last_build))
        bar.addWidget(rebuild)
        fit = QPushButton("Fit")
        fit.clicked.connect(lambda: self._view.fit_graph() if self._view else None)
        bar.addWidget(fit)
        copy_dot = QPushButton("Copy DOT")
        copy_dot.setToolTip("Copy the graph as Graphviz DOT")
        copy_dot.clicked.connect(self._copy_dot)
        bar.addWidget(copy_dot)
        outer.addLayout(bar)

        self._status = QLabel("Load a binary to build its control-flow graph.")
        self._status.setWordWrap(True)
        outer.addWidget(self._status)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self._view = CfgView(splitter)
        self._view.block_clicked.connect(self._on_block_clicked)
        splitter.addWidget(self._view)

        self._block_text = QPlainTextEdit()
        self._block_text.setReadOnly(True)
        self._block_text.setFont(mono_font(self.ctx.settings))
        self._block_text.setPlaceholderText("Click a block to inspect its instructions.")
        splitter.addWidget(self._block_text)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        outer.addWidget(splitter, 1)
        return panel

    # --------------------------------------------------------------- lifecycle
    def initialize(self, parent: Any = None) -> None:
        self._relay = Relay()
        self._relay.route.connect(self._on_build_done)
        subscribe = (
            self.ctx.ui_bus.subscribe if self.ctx.ui_bus is not None else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_event)
        theme = getattr(self.ctx, "theme", None)
        if theme is not None:
            with suppress(Exception):
                theme.theme_changed.connect(self._on_theme_changed)

    def shutdown(self) -> None:
        self._closing = True
        with suppress(Exception):
            self._unsub()

    def _tokens(self) -> dict[str, str]:
        theme = getattr(self.ctx, "theme", None)
        if theme is not None:
            with suppress(Exception):
                return dict(theme.theme().tokens)
        from eightypwner.ui.theme import DARK_TOKENS

        return dict(DARK_TOKENS)

    def _on_theme_changed(self, _theme: Any) -> None:
        if self._result is not None and self._view is not None:
            self._view.set_graph(self._result, self._tokens())

    # ------------------------------------------------------------------ events
    def on_event(self, topic: str, payload: Any) -> None:
        if topic == BINARY_LOADED and isinstance(payload, dict):
            self._model = payload.get("model")
            self._index = None
            self._result = None
            self._last_build = None
            if self._view is not None:
                scene = self._view.scene()
                if scene is not None:
                    scene.clear()
            self._status.setText(
                f"{getattr(self._model, 'name', 'binary')}: building function index…"
            )
            return
        if topic == BINARY_CLOSED:
            self._model = None
            self._index = None
            self._result = None
            self._last_build = None
            if self._func_combo is not None:
                self._func_combo.clear()
            if self._view is not None and self._view.scene() is not None:
                self._view.scene().clear()
            self._status.setText("Binary closed.")
            return
        if topic == FUNCTIONS_DISCOVERED and isinstance(payload, dict):
            if payload.get("error"):
                self._status.setText(f"⚠ {payload['error']}")
                return
            if payload.get("model") is not self._model:
                return
            self._index = payload.get("index")
            self._populate_functions()
            return
        if topic == FUNCTION_SELECTED and isinstance(payload, dict):
            address = parse_int(payload.get("address"))
            if address:
                self._addr_edit.setText(hex(address))
                self._build_for(address)
            return
        if topic == ADDRESS_SELECTED and isinstance(payload, dict):
            address = parse_int(payload.get("address"))
            if address and self._addr_edit.text().strip() in ("", self._addr_edit.text()):
                self._addr_edit.setText(hex(address))

    def _populate_functions(self) -> None:
        combo = self._func_combo
        if combo is None or self._index is None:
            return
        functions = list(getattr(self._index, "functions", []) or [])
        combo.blockSignals(True)
        combo.clear()
        for function in functions[:MAX_COMBO_FUNCTIONS]:
            combo.addItem(f"{function.name}  ({function.address:#x})", int(function.address))
        combo.blockSignals(False)
        if not functions:
            self._status.setText("No functions discovered.")
            return
        preferred = next((f for f in functions if f.name == "main"), functions[0])
        self._func_combo.setCurrentIndex(0)
        self._status.setText(
            f"{len(functions)} functions — CFG opens for {preferred.name}. "
            "Pick another from the list."
        )
        self._build_for(int(preferred.address))

    def _on_combo_activated(self, index: int) -> None:
        if self._func_combo is None:
            return
        address = self._func_combo.itemData(index)
        if address:
            self._addr_edit.setText(hex(int(address)))
            self._build_for(int(address))

    def _build_from_edit(self) -> None:
        address = parse_int(self._addr_edit.text())
        if not address:
            self._status.setText("Enter an address like 0x401126.")
            return
        self._build_for(address)

    # ------------------------------------------------------------------ build
    def _build_for(self, address: int | None) -> None:
        if not address or self._model is None:
            self._status.setText("Load a binary first.")
            return
        if self._closing:
            return
        self._last_build = int(address)
        self._request += 1
        request = self._request
        model = self._model
        self._status.setText(f"Building CFG for {address:#x}…")

        def work() -> None:
            try:
                result = build_cfg(model, int(address))
                payload = {"request": request, "result": result}
            except Exception as exc:
                log.exception("CFG build failed at %#x", address)
                payload = {"request": request, "error": str(exc)}
            with suppress(Exception):
                self._relay.route.emit(payload)

        self._build_thread = threading.Thread(target=work, name="80pwner-cfg", daemon=True)
        self._build_thread.start()

    def _on_build_done(self, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        if payload.get("request") != self._request:
            return
        if payload.get("error"):
            self._status.setText(f"⚠ {payload['error']}")
            return
        result = payload.get("result")
        if not isinstance(result, CfgResult):
            return
        self._result = result
        if self._view is not None:
            self._view.set_graph(result, self._tokens())
        note = f" — {result.note.strip()}" if result.note.strip() else ""
        self._status.setText(
            f"CFG @ {result.entry:#x}: {len(result.blocks)} blocks, "
            f"{result.instruction_count} instructions, {len(result.calls)} calls{note}"
        )

    # ------------------------------------------------------------------ actions
    def _on_block_clicked(self, address: int) -> None:
        if self._result is None or self._block_text is None:
            return
        block = self._result.blocks.get(address)
        if block is None:
            return
        self._block_text.setPlainText(
            f"block {block.start:#x}-{block.end:#x}  ({block.size} bytes)\n"
            f"exit: {block.terminal}"
            + (f" → {block.external_target:#x}" if block.external_target else "")
            + "\n\n"
            + block.text
        )
        self.ctx.bus.publish(ADDRESS_SELECTED, {"address": int(address)})

    def _copy_dot(self) -> None:
        if self._result is None:
            self._status.setText("Nothing to export — build a CFG first.")
            return
        name = getattr(self._model, "name", "cfg")
        copy_text(self._result.to_dot(f"{name} @ {self._result.entry:#x}"))
        self._status.setText("DOT graph copied to the clipboard.")
