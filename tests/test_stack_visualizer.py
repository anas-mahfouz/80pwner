# 80PWNER — by Anas Mahfouz (The80)

"""Stack Visualizer tests (Step 5): the widget reacts to the debugger's
``debugger_*`` bus events and renders the frame diagram the layout engine
produces.

Layers covered:
- `StackFrameView` widget: rows, distances strip, clicks (address_selected),
  pointer follow (memory_goto_request), frame combo, empty states,
  both-themes offscreen rendering + never-clipping column geometry,
  docs screenshots.
- the plugin's worker `_analyze()` on synthetic runtime snapshots and one
  real polled worker-thread run.
- a real-gdb end-to-end session (skipped when gdb is missing) asserting the
  actual frame of ``vuln_none.elf``.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from PySide6.QtCore import QObject, QPoint, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication

from eightypwner.core.event_bus import ADDRESS_SELECTED, EventBus
from eightypwner.core.settings import Settings
from eightypwner.engines.gdb_mi import (
    T_BACKTRACE,
    T_EXITED,
    T_REGISTERS,
    T_STACK_WORDS,
    T_STOPPED,
)
from eightypwner.engines.stack_frame import (
    analyze_frame,
    dwarf_frame_variables,
    frame_distances,
    hints_from_instructions,
)
from eightypwner.modules.builtin.stack_visualizer import (
    FRAME_WINDOW_BYTES,
    STACK_FRAME_READY,
    StackVisualizerPlugin,
    _hexint,
)
from eightypwner.modules.interface import PluginContext
from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

SAMPLE_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = SAMPLE_ROOT / "tests" / "samples" / "vuln_none.elf"
DOCS = SAMPLE_ROOT / "docs"

GDB_PRESENT = shutil.which("gdb") is not None
GDB_SKIP_REASON = "gdb is not installed on this machine"


def wait_events(
    events: list[tuple[str, Any]], topic: str, timeout: float = 20.0, count: int = 1
) -> list[Any] | None:
    """*count* payloads with *topic*, else None after *timeout* (mirrors gdb tests)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hits = [payload for name, payload in events if name == topic]
        if len(hits) >= count:
            return hits
        time.sleep(0.05)
    return None

VULN_NONE_MAIN = 0x4011BF

# a solid fake stack snapshot: locals 0x50 below rbp, buf at rbp-0x40
RBP = 0x7FFD00000100
RSP = RBP - 0x70
WINDOW_BASE = RSP
RET_VALUE = 0x401234
SAVED_RBP_VALUE = 0x7FFD00000210


class FakeTheme(QObject):
    theme_changed = Signal(object)

    def __init__(self, tokens: dict[str, str]):
        super().__init__()
        self._tokens = tokens

    def theme(self) -> Any:
        return SimpleNamespace(tokens=self._tokens)


class FakeInsn:
    def __init__(self, mnemonic: str, operands: str):
        self.mnemonic, self.operands = mnemonic, operands


def sample_window() -> bytes:
    """Whole-word window [rsp, rbp+16) with realistic values."""
    data = bytearray(0x80)

    def put(addr: int, val: int) -> None:
        offset = addr - WINDOW_BASE
        data[offset : offset + 8] = val.to_bytes(8, "little")

    put(RBP, SAVED_RBP_VALUE)
    put(RBP + 8, RET_VALUE)
    put(RBP - 8, 0xAABBCCDD9A3F2D00)
    return bytes(data)


@pytest.fixture()
def bus_capture():
    """(EventBus, recorded [(topic, payload), ...]) with a wildcard sub."""
    bus = EventBus()
    events: list[tuple[str, Any]] = []
    bus.subscribe("*", lambda topic, payload: events.append((topic, payload)))
    return bus, events


@pytest.fixture()
def plugin(qtbot, bus_capture):
    """Visualizer plugin wired to a live bus with the dark theme."""
    bus, _events = bus_capture
    plugin = StackVisualizerPlugin(
        PluginContext(
            bus=bus,
            settings=Settings(),
            app_version="0.1.0",
            ui_bus=None,
            theme=FakeTheme(DARK_TOKENS),
        )
    )
    qtbot.addWidget(plugin.widget())
    plugin.widget().show()
    plugin.initialize()
    yield plugin
    plugin.shutdown()


def real_layout() -> Any:
    """A realistic FrameLayout for vuln_none.elf's main, via the engine."""
    pytest.importorskip("elftools", reason="DWARF parsing needs pyelftools")
    hints = hints_from_instructions(
        [
            FakeInsn("push", "rbp"),
            FakeInsn("mov", "rbp, rsp"),
            FakeInsn("sub", "rsp, 0x50"),
            FakeInsn("lea", "rax, [rbp-0x40]"),
            FakeInsn("mov", "rax, qword ptr fs:0x28"),
            FakeInsn("mov", "qword ptr [rbp-0x8], rax"),
        ],
        64,
    )
    return analyze_frame(
        arch="x86_64",
        frame_level=0,
        func_name="main",
        pc=0x4011D2,
        rbp=RBP,
        rsp=RSP,
        window_base=WINDOW_BASE,
        window_bytes=sample_window(),
        hints=hints,
        dwarf_vars=dwarf_frame_variables(SAMPLE, VULN_NONE_MAIN),
        canary_enabled=True,
        symbols=[(0x401000, "main", 0x300)],
    )


def publish_frame(plugin: StackVisualizerPlugin, layout, changed=()) -> None:
    plugin.ctx.bus.publish(
        STACK_FRAME_READY, {"layout": layout, "changed": list(changed), "error": None}
    )


def index_y(index: int) -> int:
    """Viewport Y of the horizontal center of row *index*."""
    from eightypwner.modules.builtin.stack_visualizer import _INFO_H, _MARGIN, _ROW_H

    return _MARGIN + _INFO_H + index * _ROW_H + 10


# ------------------------------------------------------------------ helpers
def test_hexint_parses_hex_strings():
    assert _hexint("0x4011d2") == 0x4011D2
    assert _hexint("0x4011d2 <main+19>") == 0x4011D2
    assert _hexint("4660") == 0x1234
    assert _hexint("") is None
    assert _hexint(None) is None
    assert _hexint("not a number") is None


# ------------------------------------------------------------ widget states
def test_empty_state_before_any_data(plugin):
    assert plugin._view._layout is None
    # painting the empty state must not crash
    plugin.widget().repaint()
    plugin.widget().grab()


def test_frame_ready_event_renders_rows(plugin):
    layout = real_layout()
    publish_frame(plugin, layout)
    plugin.widget().repaint()

    assert plugin._view._layout is layout
    kinds = {row.kind for row in layout.rows}
    assert {"ret_addr", "saved_rbp", "buffer"} <= kinds

    # distances strip: one copy button per distance
    widgets = [
        plugin._distances_row.itemAt(i).widget()
        for i in range(plugin._distances_row.count())
    ]
    texts = [b.text() for b in widgets if hasattr(b, "text")]
    listed = [name for name, _ in frame_distances(layout)]
    assert any("buffer -> return address" in name for name in listed)
    assert len(texts) == len(listed)
    assert all(text.startswith("⧉") for text in texts)


def test_distance_button_copies(plugin, qtbot, monkeypatch):
    clipboard: list[str] = []
    from PySide6.QtWidgets import QApplication

    class FakeClipboard:
        def setText(self, text: str) -> None:  # noqa: N802 (Qt API name)
            clipboard.append(text)

    monkeypatch.setattr(QApplication.instance(), "clipboard", lambda: FakeClipboard())
    publish_frame(plugin, real_layout())
    buttons = [
        plugin._distances_row.itemAt(i).widget()
        for i in range(plugin._distances_row.count())
    ]
    qpbuttons = [b for b in buttons if hasattr(b, "click")]
    assert qpbuttons
    qpbuttons[-1].click()
    assert clipboard and "return address" in clipboard[-1]


def test_row_click_publishes_address_selected(plugin, qtbot, bus_capture):
    _, events = bus_capture
    layout = real_layout()
    publish_frame(plugin, layout)
    plugin.widget().repaint()
    ret = next(row for row in layout.rows if row.kind == "ret_addr")
    y = index_y(list(layout.rows).index(ret))
    plugin._view._emit_row_selection(y)
    qtbot.wait(10)
    hits = [payload for topic, payload in events if topic == ADDRESS_SELECTED]
    assert hits and hits[-1]["address"] == RBP + 8


def test_row_at_maps_y_to_row(plugin):
    layout = real_layout()
    publish_frame(plugin, layout)
    view = plugin._view
    view.verticalScrollBar().setValue(0)
    assert view.row_at(index_y(0) - 10, 500) is layout.rows[0]
    assert view.row_at(4, 500) is None  # the info header area


def test_pointer_doubleclick_requests_memory_goto(plugin, qtbot, bus_capture, monkeypatch):
    _, events = bus_capture
    layout = real_layout()
    publish_frame(plugin, layout)
    plugin.widget().repaint()
    ret = next(row for row in layout.rows if row.kind == "ret_addr")
    assert ret.is_pointer  # frozen dataclass: the engine already flagged it
    y = index_y(list(layout.rows).index(ret))

    class FakeEvent:
        @staticmethod
        def position() -> Any:
            return SimpleNamespace(toPoint=lambda: QPoint(0, y))

    # the fake event cannot reach Qt's C++ implementation — stub the base
    from PySide6.QtWidgets import QAbstractScrollArea

    monkeypatch.setattr(
        QAbstractScrollArea, "mouseDoubleClickEvent", lambda self, event: None
    )
    plugin._view.mouseDoubleClickEvent(FakeEvent())
    qtbot.wait(10)
    gotos = [p for topic, p in events if topic == "memory_goto_request"]
    assert gotos and gotos[-1]["address"] == RET_VALUE


def test_frame_combo_from_backtrace(plugin, bus_capture):
    bus, _ = bus_capture
    bus.publish(
        T_BACKTRACE,
        {
            "frames": [
                {"level": "0", "address": "0x4011d2", "func": "main", "file": "", "line": "8"},
                {"level": "1", "address": "0x401234", "func": "__libc_start", "file": "", "line": ""},
            ]
        },
    )
    combo = plugin._frame_combo
    assert combo.count() == 2
    assert "main" in combo.itemText(0)
    assert "__libc_start" in combo.itemText(1)
    # switching frames publishes a stack_context_request with the new level
    cleared: list[Any] = []
    bus.subscribe("stack_context_request", lambda t, p: cleared.append(p))
    combo.setCurrentIndex(1)
    for _ in range(20):
        if cleared:
            break
        time.sleep(0.02)
    assert cleared and cleared[-1] == {"level": 1, "window": FRAME_WINDOW_BYTES}


def test_exit_clears_view(plugin, bus_capture):
    bus, _ = bus_capture
    publish_frame(plugin, real_layout())
    assert plugin._view._layout is not None
    plugin.widget().repaint()
    bus.publish(T_EXITED, {})
    assert plugin._view._layout is None
    assert plugin._view._empty_text  # a graceful "the debuggee exited" note


def test_stopped_event_requests_context(plugin, bus_capture):
    _, events = bus_capture
    regs = {"$rip": "0x4011d2", "$rsp": hex(RSP), "$rbp": hex(RBP)}
    plugin.ctx.bus.publish(T_STOPPED, {"reason": "breakpoint-hit", "regs": regs})
    requests = [p for topic, p in events if topic == "stack_context_request"]
    assert requests, "a stop must immediately request registers + stack window"
    assert requests[-1]["window"] == FRAME_WINDOW_BYTES


# --------------------------------------------------------------- worker flow
def stuff_snapshots(plugin: StackVisualizerPlugin, window: bytes = b""):
    """Push stops/registers/stack-window through the plugin's own handlers."""
    plugin._running_state = "stopped"
    plugin.on_event(
        T_REGISTERS,
        {"values": {"$rip": "0x4011d2", "$rsp": hex(RSP), "$rbp": hex(RBP)}, "changed": []},
    )
    bytes_window = window or sample_window()
    plugin.on_event(
        T_STACK_WORDS,
        {
            "sp": hex(RSP),
            "base": hex(WINDOW_BASE),
            "address": hex(WINDOW_BASE),
            "size": len(bytes_window),
            "words": [],
            "hex": bytes_window.hex(),
        },
    )


def test_analyze_with_synthetic_snapshots(plugin, monkeypatch):
    pytest.importorskip("capstone", reason="disassembly hints need capstone")
    pytest.importorskip("elftools", reason="DWARF needs pyelftools")
    from eightypwner.engines.binary_parser import parse_binary

    plugin._model = parse_binary(SAMPLE)
    stuff_snapshots(plugin)
    layout, _changed, note = plugin._analyze()
    assert note == ""
    assert layout is not None and layout.error is None
    rows = {row.kind: row for row in layout.rows}
    assert rows["saved_rbp"].address == RBP
    assert rows["ret_addr"].address == RBP + 8
    assert rows["ret_addr"].value == RET_VALUE


def test_worker_thread_publishes_layout(plugin, bus_capture, qtbot):
    """Latest-wins worker: snapshots → STACK_FRAME_READY → view updates."""
    pytest.importorskip("capstone", reason="disassembly hints need capstone")
    pytest.importorskip("elftools", reason="DWARF needs pyelftools")
    from eightypwner.engines.binary_parser import parse_binary

    plugin._model = parse_binary(SAMPLE)
    stuff_snapshots(plugin)
    plugin.wake_worker()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ready = [p for topic, p in bus_capture[1] if topic == STACK_FRAME_READY]
        if ready and ready[-1].get("layout") is not None:
            break
        time.sleep(0.05)
    ready = [p for topic, p in bus_capture[1] if topic == STACK_FRAME_READY]
    assert ready and ready[-1]["layout"] is not None, "worker never published a layout"
    rows = {row.kind: row for row in ready[-1]["layout"].rows}
    assert rows["ret_addr"].address == RBP + 8
    # the view swaps the layout in on the bus thread
    assert plugin._view._layout is not None
    plugin._running_state = "idle"
    plugin.shutdown()
    time.sleep(0.3)


def test_diff_values_marks_changed(plugin):
    pytest.importorskip("elftools", reason="DWARF needs pyelftools")
    pytest.importorskip("capstone", reason="hints go through the engine path")
    from eightypwner.engines.binary_parser import parse_binary

    plugin._model = parse_binary(SAMPLE)
    stuff_snapshots(plugin)
    _layout, changed, _note = plugin._analyze()
    assert not changed  # first snapshot: everything is baseline

    # second snapshot: the buffer's first word changed
    window = bytearray(sample_window())
    offset = (RBP - 0x40) - WINDOW_BASE  # buf starts at rbp-0x40
    window[offset : offset + 8] = (0x4141414141414141).to_bytes(8, "little")
    with plugin._lock:
        plugin._window = (WINDOW_BASE, bytes(window))
    _layout, changed, _note = plugin._analyze()
    assert (RBP - 0x40) in changed


def test_empty_states_when_not_running(plugin):
    plugin._model = None
    layout, _changed, note = plugin._analyze()
    assert layout is None
    assert note  # graceful message, no crash


def test_unsupported_arch_clear_error_not_crash(plugin, monkeypatch):
    class BrokenModel:
        arch = "arm64"
        path = SAMPLE
        bits = 64
        symbols: tuple = ()  # iterable, immutable
        checksec: tuple = ()

    import eightypwner.modules.builtin.stack_visualizer as sv

    monkeypatch.setattr(sv.StackVisualizerPlugin, "_function_hints", lambda self, m, a: None)
    monkeypatch.setattr(sv.StackVisualizerPlugin, "_dwarf_vars", lambda self, m, a: [])
    plugin._model = BrokenModel()
    plugin._running_state = "stopped"
    stuff_snapshots(plugin)
    layout, _changed, note = plugin._analyze()
    assert layout is not None and layout.error is not None
    assert layout.rows == ()
    assert note  # a human-readable note is surfaced


# --------------------------------------------------- widget rendering/clip
@pytest.mark.parametrize("width", [420, 460, 520, 540, 560, 640, 700, 760, 900, 1200])
def test_columns_never_overlap_or_clip(plugin, width):
    view = plugin._view
    cols = view._columns(width)
    value, annot, label, offsets = cols["value"], cols["annot"], cols["label"], cols["offsets"]
    right_edge = max(width - 2, 40)
    # the raw value column always stays inside the viewport
    assert value.left() >= 4 and value.right() <= right_edge
    if offsets.width():
        assert offsets.left() >= 4
        if cols["bar_x1"] > cols["bar_x"]:
            assert cols["bar_x"] >= offsets.right() + 2
    if annot.width():
        assert annot.right() + 2 <= value.left()
    if label.width():
        neighbor = annot.left() if annot.width() else value.left()
        assert label.right() + 2 <= neighbor
    if cols["bar_x1"] > cols["bar_x"]:
        limit = label.left() if label.width() else (annot.left() if annot.width() else value.left())
        assert cols["bar_x1"] <= limit - 2
        assert cols["bar_x1"] - cols["bar_x"] >= 24


def _margin_pixels_are_bg(image, tokens) -> bool:
    """True when the outermost 2px hold only background ink (no clipping)."""
    bg = QColor(tokens["bg"])
    width, height = image.width(), image.height()
    checked = 0
    for x in (0, 1, width - 2, width - 1):
        for y in range(0, height, 7):
            px = QColor(image.pixel(x, y))
            delta = abs(px.red() - bg.red()) + abs(px.green() - bg.green()) + abs(px.blue() - bg.blue())
            if delta > 40:
                return False
            checked += 1
    return checked > 0


@pytest.mark.parametrize("mode, tokens", [("dark", DARK_TOKENS), ("light", LIGHT_TOKENS)])
def test_render_both_themes_no_clip(plugin, mode, tokens):
    plugin.ctx = PluginContext(
        bus=plugin.ctx.bus,
        settings=Settings(),
        app_version="x",
        ui_bus=None,
        theme=FakeTheme(tokens),
    )
    plugin._view._plugin = plugin
    publish_frame(plugin, real_layout(), changed=[RBP + 8])
    plugin.widget().resize(900, 540)
    plugin.widget().repaint()
    image = plugin._view.viewport().grab().toImage()
    assert image.width() > 400 and image.height() > 200
    assert _margin_pixels_are_bg(image, tokens), f"{mode} theme: ink reached the edge"
    # accent ink is actually on screen (rows/bars/borders rendered)
    accent = QColor(tokens["accent"]).name().lower()
    hits = sum(
        1
        for x in range(0, image.width(), 4)
        for y in range(0, image.height(), 4)
        if QColor(image.pixel(x, y)).name().lower() == accent
    )
    assert hits > 4, f"{mode} theme: accent-colored rows missing from the render"


@pytest.mark.skipif(not SAMPLE.is_file(), reason="samples not built")
def test_docs_screenshots_dark_and_light(plugin):
    """Regenerate the docs screenshots; they must exist and actually differ."""
    pytest.importorskip("elftools", reason="DWARF needs pyelftools")
    DOCS.mkdir(exist_ok=True)
    publish_frame(plugin, real_layout(), changed=[RBP + 8])
    plugin.widget().resize(900, 540)
    plugin.widget().repaint()

    dark_path = DOCS / "stack-dark.png"
    for _ in range(3):
        plugin.widget().repaint()
        QApplication.instance().processEvents()  # let layout activate after resize
    assert plugin.widget().grab().save(str(dark_path))

    plugin.ctx = PluginContext(
        bus=plugin.ctx.bus,
        settings=Settings(),
        app_version="x",
        ui_bus=None,
        theme=FakeTheme(LIGHT_TOKENS),
    )
    plugin._view._plugin = plugin
    plugin._view.viewport().update()
    plugin.widget().repaint()
    light_path = DOCS / "stack-light.png"
    for _ in range(3):
        plugin.widget().repaint()
        QApplication.instance().processEvents()  # let layout activate
    assert plugin.widget().grab().save(str(light_path))

    assert dark_path.exists() and light_path.exists()
    assert dark_path.read_bytes() != light_path.read_bytes()


# --------------------------------------------------- real gdb integration
@pytest.mark.skipif(not GDB_PRESENT, reason=GDB_SKIP_REASON)
@pytest.mark.skipif(not SAMPLE.is_file(), reason="sample binary missing")
class TestRealGdbFrame:
    """End-to-end: gdb stops inside vuln_none.elf's buf frame at gets()."""

    def test_saved_rbp_ret_buf_distances(self, tmp_path, qtbot):
        pytest.importorskip("elftools", reason="DWARF needs pyelftools")
        from eightypwner.engines.binary_parser import parse_binary
        from eightypwner.engines.gdb_mi import (
            T_BP_ADDED,
            T_MEMORY_READ,
            T_STARTED,
            T_STOPPED,
            GdbEngine,
        )

        events: list[tuple[str, Any]] = []
        engine = GdbEngine(lambda topic, payload: events.append((topic, payload)))
        try:
            stdin_file = tmp_path / "in.txt"
            stdin_file.write_text("AAAAAAAA\n")
            engine.start_program(str(SAMPLE), stdin_file=str(stdin_file))
            assert wait_events(events, T_STARTED, 30) is not None
            # main+19 (0x4011d2) lands right after the prologue: rbp set,
            # buf exists per DWARF but is not yet filled by gets
            engine.set_breakpoint(0x4011D2)
            assert wait_events(events, T_BP_ADDED, 15) is not None
            engine.run()
            stops = wait_events(events, T_STOPPED, 30)
            assert stops is not None, "did not hit the main+19 breakpoint"
            regs = stops[-1]["regs"]
            rbp = int(str(regs["$rbp"]), 16)

            bus = EventBus()
            plugin = StackVisualizerPlugin(
                PluginContext(
                    bus=bus, settings=Settings(), app_version="x",
                    ui_bus=None, theme=FakeTheme(DARK_TOKENS),
                )
            )
            plugin.widget()
            plugin._model = parse_binary(SAMPLE)
            plugin._running_state = "stopped"
            plugin.on_event(T_REGISTERS, {"values": regs, "changed": []})
            # pull the announced stack-window bytes through the plugin handler
            reads = wait_events(events, T_MEMORY_READ, 20)
            assert reads, "stack_context must announce a debugger_memory_read"
            plugin.on_event(T_MEMORY_READ, reads[-1])

            layout, _changed, note = plugin._analyze()
            assert note == "", f"frame analysis failed: {note}"
            assert layout is not None and layout.error is None
            rows = {row.kind: row for row in layout.rows}
            # DWARF ground truth for vuln_none.elf's main: buf[64] at rbp-0x40
            assert rows["saved_rbp"].address == rbp
            assert rows["ret_addr"].address == rbp + 8
            buf_row = rows["buffer"]
            assert buf_row.address == rbp - 0x40
            assert buf_row.size == 64
            listed = frame_distances(layout)
            buf_to_ra = next(d for name, d in listed if "return address" in name)
            assert buf_to_ra == 0x48
        finally:
            plugin._closing = True
            plugin._wake.set()
            engine.shutdown()
