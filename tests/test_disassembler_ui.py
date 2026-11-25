# 80PWNER — by Anas Mahfouz (The 80)
#
"""Step-3 UI flow tests: disassembler panel reacts via the bus (offscreen)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("capstone", reason="disassembler needs capstone")
pytest.importorskip("lief", reason="Sample UI flow needs LIEF for parsing")

SAMPLE = Path(__file__).resolve().parent / "samples" / "vuln_none.elf"


@pytest.fixture()
def parts(tmp_path, monkeypatch, qtbot):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    del app

    from eightypwner.core.event_bus import EventBus
    from eightypwner.core.session import SessionState
    from eightypwner.core.settings import Settings
    from eightypwner.core.ui_dispatch import UiBus
    from eightypwner.modules.builtin.disassembler import DisassemblerPlugin
    from eightypwner.modules.interface import PluginContext

    bus = EventBus()
    ui_bus = UiBus(bus)
    session = SessionState()
    ctx = PluginContext(
        bus=bus, settings=Settings(), app_version="test", ui_bus=ui_bus, session=session
    )
    plugin = DisassemblerPlugin(ctx)
    plugin.initialize()
    panel = plugin.widget()
    qtbot.addWidget(panel)
    return plugin, bus, session


def _load_sample(plugin, bus, qtbot):
    if not SAMPLE.exists():
        pytest.skip("sample binary missing")
    bus.publish("binary_dropped", {"path": str(SAMPLE)})
    qtbot.waitUntil(lambda: plugin._index is not None, timeout=15_000)
    qtbot.waitUntil(lambda: plugin._disasm_table.rowCount() > 0, timeout=15_000)


def test_load_populates_function_list_and_view(qtbot, parts):
    plugin, bus, _session = parts
    _load_sample(plugin, bus, qtbot)
    assert plugin._model is not None
    assert plugin._func_table.rowCount() >= 10, "functions discovered"
    assert plugin._disasm_table.rowCount() > 0, "entry-point view decoded"
    assert plugin._xref_table.rowCount() > 0, "xrefs panel filled"
    # instruction columns carry real content
    assert plugin._disasm_table.item(0, 0).text().startswith("0x")
    assert plugin._disasm_table.item(0, 2).text() != ""


def test_function_selection_navigates(qtbot, parts):
    plugin, bus, _session = parts
    _load_sample(plugin, bus, qtbot)
    row = None
    for r in range(plugin._func_table.rowCount()):
        if plugin._func_table.item(r, 0).text().startswith("main"):
            row = r
            break
    assert row is not None, "main in function list"
    published: list[tuple[str, object]] = []
    plugin.ctx.bus.subscribe("function_selected", lambda t, p: published.append((t, p)))

    plugin._func_table.selectRow(row)
    qtbot.waitUntil(lambda: plugin._view_name == "main", timeout=15_000)
    assert any(topic == "function_selected" for topic, _p in published)


def test_navigate_back_after_double_jump(qtbot, parts):
    plugin, bus, _session = parts
    _load_sample(plugin, bus, qtbot)
    start_view = plugin._view_start  # auto-jumped view (main)
    other = start_view + 16
    plugin.navigate(other)
    qtbot.waitUntil(lambda: plugin._view_start == other, timeout=15_000)
    back, fwd = plugin._nav_buttons
    assert back.isEnabled()
    assert not fwd.isEnabled(), "nothing to forward yet"
    plugin._go_back()
    qtbot.waitUntil(lambda: plugin._view_start == start_view, timeout=15_000)
    assert fwd.isEnabled()


def test_comments_and_renames_stored_in_session(qtbot, parts):
    plugin, bus, session = parts
    _load_sample(plugin, bus, qtbot)
    first = plugin._disasm_table.item(0, 4)
    address = int(first.text(), 16)
    session.set_comment(address, "pwn here")
    session.rename_symbol(address, "pwner_main")
    assert session.comment_at(address) == "pwn here"
    assert session.display_name(address, "main") == "pwner_main"
    plugin._refill_functions()  # the rename dialog triggers exactly this
    rows = {
        plugin._func_table.item(r, 0).text() for r in range(plugin._func_table.rowCount())
    }
    assert any("pwner_main" in text for text in rows), "renamed function visible in list"


def test_filter_functions_narrows_list(qtbot, parts):
    plugin, bus, _session = parts
    _load_sample(plugin, bus, qtbot)
    full = plugin._func_table.rowCount()
    plugin._filter_edit.setText("main")
    qtbot.waitUntil(lambda: plugin._func_table.rowCount() < full, timeout=5_000)
    names = [
        plugin._func_table.item(r, 0).text() for r in range(plugin._func_table.rowCount())
    ]
    assert all("main" in name for name in names)


def test_close_clears_tables(qtbot, parts):
    plugin, bus, _session = parts
    _load_sample(plugin, bus, qtbot)
    bus.publish("binary_closed")
    qtbot.waitUntil(lambda: plugin._disasm_table.rowCount() == 0, timeout=5_000)
    assert plugin._func_table.rowCount() == 0
    assert plugin._xref_table.rowCount() == 0
    assert plugin._model is None
