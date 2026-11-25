# 80PWNER — by Anas Mahfouz (The 80)
#
"""End-to-end UI tests: the overview plugin loads a sample through the bus."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("lief", reason="Sample UI flow needs LIEF for parsing")


@pytest.fixture()
def app_parts(tmp_path, monkeypatch, qtbot):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    del app

    from eightypwner.core.event_bus import EventBus
    from eightypwner.core.settings import Settings
    from eightypwner.core.ui_dispatch import UiBus
    from eightypwner.modules.builtin.binary_overview import BinaryOverviewPlugin
    from eightypwner.modules.interface import PluginContext

    bus = EventBus()
    ui_bus = UiBus(bus)
    settings = Settings()
    ctx = PluginContext(bus=bus, settings=settings, app_version="test", ui_bus=ui_bus)
    plugin = BinaryOverviewPlugin(ctx)
    plugin.initialize()
    panel = plugin.widget()
    qtbot.addWidget(panel)
    return plugin, bus, ui_bus


def test_full_load_flow_through_bus(qtbot, app_parts):
    plugin, bus, _ui = app_parts
    sample = Path(__file__).resolve().parent / "samples" / "vuln_none.elf"
    if not sample.exists():
        pytest.skip("sample binary missing")

    bus.publish("binary_dropped", {"path": str(sample), "icon": "x"})
    qtbot.waitUntil(lambda: plugin._model is not None, timeout=10_000)

    model = plugin._model
    assert model.name == "vuln_none.elf"
    assert plugin._info_values["arch"].text() == "x86_64"
    assert plugin._sections_table.rowCount() > 0
    assert plugin._imports_table.rowCount() >= 1
    # checksec badge present with the right role for a disabled mitigation
    badges = plugin._checksec_grid
    texts = [badges.itemAt(i).widget().text() for i in range(badges.count()) if isinstance(badges.itemAt(i).widget(), __import__("PySide6.QtWidgets", fromlist=["QLabel"]).QLabel)]
    assert any("NX" in t and "DISABLED" in t for t in texts)


def test_failed_parse_shows_message(qtbot, app_parts):
    plugin, bus, _ui = app_parts
    bad = Path(__file__).resolve().parent / "samples" / "not_a_binary.txt"
    bad.write_text("plain text", encoding="utf-8")
    bus.publish("binary_dropped", {"path": str(bad), "icon": "x"})
    qtbot.waitUntil(lambda: "not" in plugin._status_label.text() or "error" in plugin._status_label.text().lower() or "⚠" in plugin._status_label.text(), timeout=10_000)
    assert plugin._model is None


def test_close_clears_state(qtbot, app_parts):
    plugin, bus, _ui = app_parts
    sample = Path(__file__).resolve().parent / "samples" / "vuln_full.elf"
    if sample.exists():
        bus.publish("binary_dropped", {"path": str(sample), "icon": "x"})
        qtbot.waitUntil(lambda: plugin._model is not None, timeout=10_000)
    bus.publish("binary_closed")
    qtbot.waitUntil(lambda: plugin._model is None)
    assert plugin._path_label.text() == "No binary loaded"
