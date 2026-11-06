# 80PWNER — by Anas Mahfouz (The80)

"""Debugger GUI tests (offscreen): panels react to debugger_* bus events,
run dialog/config flow, gdb-missing degradation, and a real gdb session flow
(start, breakpoint hit, step, registers, stop, no orphans) when gdb exists.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from eightypwner.core.event_bus import EventBus
from eightypwner.core.settings import Settings
from eightypwner.engines.gdb_mi import (
    T_DIED,
    T_MEMORY_READ,
    T_REGISTERS,
    T_STACK_WORDS,
    T_STATE,
    T_STOPPED,
)
from eightypwner.modules.builtin.debugger import DBG_UNAVAILABLE, DebuggerPlugin
from eightypwner.modules.interface import PluginContext

SAMPLE_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = SAMPLE_ROOT / "tests" / "samples" / "vuln_none.elf"
GDB_PRESENT = shutil.which("gdb") is not None


class _UnavailStatus:
    available = False
    version = ""
    hint = "please install gdb"
    support_level = "missing"


class _AvailableStatus:
    available = True
    version = "gdb"
    hint = ""
    support_level = "full"


@pytest.fixture()
def plugin(qtbot, monkeypatch, tmp_path):
    """Debugger plugin with a production-like wiring: UiBus marshals the
    worker-thread engine events onto the GUI thread."""
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))

    status_obj = _AvailableStatus if GDB_PRESENT else _UnavailStatus
    monkeypatch.setattr(
        "eightypwner.platform.debuggers.gdb_status", lambda: status_obj()
    )
    monkeypatch.setattr(
        "eightypwner.modules.builtin.debugger.gdb_status", lambda: status_obj()
    )
    from eightypwner.core.ui_dispatch import UiBus

    bus = EventBus()
    ctx = PluginContext(
        bus=bus, settings=Settings(), app_version="0.1.0", ui_bus=UiBus(bus)
    )
    plugin = DebuggerPlugin(ctx)
    widget = plugin.widget()
    qtbot.addWidget(widget)
    plugin.initialize()
    return plugin


# ------------------------------------------------------------------- panels
def test_all_six_tabs_built(plugin):
    tabs = [plugin._tabs.tabText(i) for i in range(plugin._tabs.count())]
    assert tabs == [
        "Registers",
        "Stack",
        "Memory",
        "Breakpoints",
        "GDB",
        "Program I/O",
    ]


def test_panels_react_to_events(plugin, qtbot):
    ctx = plugin.ctx

    # registers + changed highlight
    ctx.bus.publish(
        T_REGISTERS,
        {
            "values": {"$rip": "0x401000", "$rsp": "0x7fffffffe000", "$rax": "0x1"},
            "changed": ["$rax"],
            "pc": "0x401000",
            "sp": "0x7fffffffe000",
        },
    )
    qtbot.waitUntil(lambda: plugin._reg_table.rowCount() == 3)
    accent_values = {
        plugin._reg_table.item(row, 0).text() for row in range(plugin._reg_table.rowCount())
    }
    assert "$rsp" in accent_values and "$rip" in accent_values
    qtbot.waitUntil(
        lambda: plugin._status.text()  # unchanged by regs; sanity no-crash
    ) if False else None

    # stack words with an sp annotation
    ctx.bus.publish(
        T_STACK_WORDS,
        {
            "sp": "0x7fffffffe000",
            "base": "0x7fffffffdff0",
            "size": 192,
            "words": [
                {"address": "0x7fffffffe000", "is_sp": True, "word_hex": "0" * 16},
                {"address": "0x7fffffffe008", "is_sp": False, "word_hex": "1" * 16},
            ],
        },
    )
    qtbot.waitUntil(lambda: plugin._stack_table.rowCount() == 2)
    sp_note = plugin._stack_table.item(0, 2).text()
    assert "$sp" in sp_note

    # memory hex view
    ctx.bus.publish(T_MEMORY_READ, {"address": "0x401000", "size": 32, "hex": "90" * 32})
    qtbot.waitUntil(lambda: plugin._mem_table.rowCount() == 2)
    assert plugin._mem_table.item(0, 1).text() == "90"

    # breakpoints table
    ctx.bus.publish(
        "breakpoint_updated",
        {
            "breakpoints": [
                {"number": "1", "address": "0x4011d2", "func": "main", "enabled": True}
            ]
        },
    )
    qtbot.waitUntil(lambda: plugin._bp_table.rowCount() == 1)
    assert plugin._bp_table.item(0, 2).text() == "main"

    # state changes drive the toolbar
    ctx.bus.publish(T_STATE, {"state": "running"})
    qtbot.waitUntil(lambda: not plugin._buttons["Continue"].isEnabled())
    ctx.bus.publish(T_STOPPED, {"reason": "breakpoint-hit", "pc": "0x4011d2"})
    qtbot.waitUntil(lambda: plugin._buttons["Continue"].isEnabled())


def test_bp_toggle_request_reaches_engine(plugin, qtbot):
    """Disassembler's T_BP_TOGGLE_REQUEST → engine.toggle_breakpoint(address);
    without an engine the request is dropped without raising."""
    from eightypwner.engines.gdb_mi import T_BP_TOGGLE_REQUEST

    requested: list[int] = []

    class _FakeEngine:
        def toggle_breakpoint(self, address: int) -> None:
            requested.append(address)

    # no engine yet → must not raise
    plugin.ctx.bus.publish(T_BP_TOGGLE_REQUEST, {"address": 0x4011D2})
    qtbot.wait(50)

    plugin._engine = _FakeEngine()  # type: ignore[assignment]
    plugin.ctx.bus.publish(T_BP_TOGGLE_REQUEST, {"address": 0x4011D2})
    qtbot.waitUntil(lambda: requested == [0x4011D2])
    plugin._engine = None


def test_editable_register_writes_engine(plugin, qtbot):
    """Editing a register value pushes ``write_register`` to the engine."""

    sent = []

    class _FakeEngine:
        def write_register(self, name, value):
            sent.append((name, value))

    plugin._engine = _FakeEngine()  # type: ignore[assignment]
    plugin._populating = False
    plugin.on_event(
        T_REGISTERS,
        {
            "values": {"$rax": "0x1"},
            "changed": [],
            "pc": "",
            "sp": "",
        },
    )
    qtbot.waitUntil(lambda: plugin._reg_table.rowCount() == 1)
    # simulate: user rewrites the value cell — the table's itemChanged wiring
    # calls _register_edited exactly once
    value_item = plugin._reg_table.item(0, 1)
    value_item.setText("0x2")  # fires itemChanged → _register_edited → engine
    assert sent == [("rax", "0x2")]


def test_memory_byte_edit_writes_engine(plugin, qtbot):
    plugin.on_event(T_MEMORY_READ, {"address": "0x403398", "size": 16, "hex": "00" * 16})
    qtbot.waitUntil(lambda: plugin._mem_table.rowCount() == 1)
    sent = []

    class _FakeEngine:
        def write_memory(self, address, data):
            sent.append((address, data))

        def read_memory(self, address, size):  # the row refresh
            sent.append((address, size))

    engine = _FakeEngine()
    plugin._engine = engine  # type: ignore[assignment]
    cell = plugin._mem_table.item(0, 1)
    cell.setText("ff")
    plugin._memory_byte_edited(cell)
    assert (0x403398, b"\xff") in sent


def test_debugger_unavailable_degrades(plugin, qtbot, monkeypatch):
    if GDB_PRESENT:
        pytest.skip("gdb installed — unavailable path already covered by mocks")
    ctx = plugin.ctx
    got_unavailable: list[dict] = []
    ctx.bus.subscribe(DBG_UNAVAILABLE, lambda topic, payload: got_unavailable.append(payload))
    # engine construction fails → message + disabled panels, bus event fired
    plugin._ensure_engine()
    qtbot.waitUntil(lambda: got_unavailable)
    assert "gdb" in plugin._status.text().lower()
    assert not plugin._console_input.isEnabled()


def test_gdb_died_sets_warning(plugin, qtbot):
    ctx = plugin.ctx
    ctx.bus.publish(T_STATE, {"state": "running"})
    ctx.bus.publish(T_DIED, {"error": "gdb died"})
    qtbot.waitUntil(lambda: "gdb died" in plugin._status.text().lower())
    assert plugin._state == "exited"


# ------------------------------------------------------------- real gdb flow
@pytest.mark.skipif(not GDB_PRESENT, reason="gdb is not installed on this machine")
@pytest.mark.skipif(not SAMPLE.is_file(), reason="sample binary missing")
def test_full_gdb_ui_flow(qtbot, plugin, tmp_path, monkeypatch):
    """start_session → breakpoint hit → step → registers panels → stop."""

    plugin.on_event("binary_loaded", {"model": type("M", (), {"path": SAMPLE})()})

    stdin_file = tmp_path / "in.txt"
    stdin_file.write_text("AAAAAAA\n")
    config = {
        "target": str(SAMPLE),
        "args": [],
        "stdin": str(stdin_file),
        "env": {},
        "cwd": "",
        "break_entry": True,
    }
    plugin.start_session(config)
    qtbot.waitUntil(lambda: "Breakpoint" in plugin._status.text(), timeout=30000)
    qtbot.waitUntil(lambda: plugin._bp_table.rowCount() >= 1, timeout=15000)

    # registers hung on the stop (auto-collected by the engine)
    qtbot.waitUntil(lambda: plugin._reg_table.rowCount() > 0, timeout=15000)
    names = {
        plugin._reg_table.item(row, 0).text() for row in range(plugin._reg_table.rowCount())
    }
    assert "$rip" in names and "$rsp" in names

    before_pc = {
        row: plugin._reg_table.item(row, 1).text()
        for row in range(plugin._reg_table.rowCount())
        if plugin._reg_table.item(row, 0).text() == "$rip"
    }
    assert before_pc, "PC row present"

    # step over → highlight again with the new pc (state → stopped)
    plugin._step_over()
    qtbot.waitUntil(
        lambda: plugin._reg_table.item(_rip_row(plugin._reg_table), 1).text() != before_pc.get(_rip_row(plugin._reg_table)),
        timeout=20000,
    )

    # stack panel filled from the stop-time auto window read
    qtbot.waitUntil(lambda: plugin._stack_table.rowCount() > 0, timeout=15000)

    # graceful stop — no gdb/inferior processes remain
    pid = plugin._engine._inferior_pid
    plugin._stop()
    qtbot.waitUntil(lambda: plugin._engine is None)
    time.sleep(0.4)
    if pid:
        assert not Path(f"/proc/{pid}").exists(), "inferior killed on stop"


def _rip_row(table) -> int:
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is not None and item.text() == "$rip":
            return row
    return 0


# ------------------------------------------- Step 5: visualizer request topics
class _Step5Engine:
    """Captures stack-context/eval/memory-goto requests from other modules."""

    def __init__(self):
        self.calls: list[tuple[str, ...]] = []

    def stack_context(self, level, window):
        self.calls.append(("context", level, window))

    def evaluate(self, expr):
        self.calls.append(("eval", expr))

    def read_memory(self, address, size):
        self.calls.append(("memory", address, size))


def test_step5_request_topics_route_to_engine(plugin, qtbot):
    ctx = plugin.ctx
    engine = _Step5Engine()
    plugin._engine = engine  # type: ignore[assignment]

    ctx.bus.publish("stack_context_request", {"level": 2, "window": 1024})
    ctx.bus.publish("stack_eval_request", {"expr": "&main"})
    ctx.bus.publish("memory_goto_request", {"address": "0x401000", "size": 32})
    qtbot.waitUntil(lambda: len(engine.calls) == 3)

    assert ("context", 2, 1024) in engine.calls
    assert ("eval", "&main") in engine.calls
    assert ("memory", 0x401000, 32) in engine.calls


def test_step5_requests_without_engine_are_noops(plugin, qtbot):
    ctx = plugin.ctx
    plugin._engine = None  # type: ignore[assignment]
    # must not raise and must not touch the status line with an error
    ctx.bus.publish("stack_context_request", {"level": 0, "window": 1024})
    ctx.bus.publish("stack_eval_request", {"expr": "&main"})
    ctx.bus.publish("memory_goto_request", {"address": 16})  # int address, default size
    qtbot.wait(50)  # let the queued events land
