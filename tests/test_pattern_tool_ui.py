# 80PWNER — by Anas Mahfouz (The80)

"""UI tests for the Pattern Tool dock (Step 6 B)."""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QDockWidget

from eightypwner.core.event_bus import EventBus
from eightypwner.core.settings import Settings
from eightypwner.modules.builtin.pattern_tool import (
    GENERATED_PREVIEW,
    MAX_LENGTH,
    PATTERN_GENERATED,
    PATTERN_LOOKUP_RESULT,
    PatternToolPlugin,
)
from eightypwner.modules.interface import PluginContext
from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS, render_theme

SAMPLE_ROOT = Path(__file__).resolve().parents[1]


class FakeTheme(QObject):
    theme_changed = Signal(object)

    def __init__(self, tokens: dict[str, str]):
        super().__init__()
        self._tokens = tokens

    def theme(self) -> Any:
        return SimpleNamespace(tokens=self._tokens)


@pytest.fixture()
def plugin(qtbot):
    bus = EventBus()
    events: list[tuple[str, Any]] = []
    bus.subscribe("*", lambda topic, payload: events.append((topic, payload)))
    plugin = PatternToolPlugin(
        PluginContext(
            bus=bus, settings=Settings(), app_version="test",
            ui_bus=None, theme=FakeTheme(DARK_TOKENS),
        )
    )
    panel = plugin.widget()
    qtbot.addWidget(panel)
    panel.resize(900, 480)
    panel.show()
    plugin.initialize()
    yield plugin, events
    plugin.shutdown()


def wait_for(events: list, topic: str, timeout: float = 10.0) -> list[dict]:
    """Wait for one publication of *topic* and drain the UI-thread relay."""
    deadline = time.monotonic() + timeout
    hits: list[dict] = []
    while time.monotonic() < deadline:
        hits = [p for t, p in events if t == topic]
        if hits:
            break
        QApplication.instance().processEvents()
        time.sleep(0.02)
    for _ in range(6):
        QApplication.instance().processEvents()
        time.sleep(0.02)
    return [p for t, p in events if t == topic]


# ------------------------------------------------------------------ basics
def test_panel_cached(plugin) -> None:
    plugin, _ = plugin
    panel = plugin.widget()
    assert panel is plugin.widget()


def test_generate_publishes_and_shows(plugin) -> None:
    plugin, events = plugin
    plugin._len_spin.setValue(20)
    plugin._n_spin_gen.setValue(4)
    plugin._on_generate()
    wait_for(events, PATTERN_GENERATED)
    assert plugin._pattern_view.toPlainText().startswith("aaaabaaacaaadaaaeaaa")
    assert plugin._copy_pat_btn.isEnabled()
    assert "n=4" in plugin._search_note.text()


def test_generate_then_copy_copies_full_pattern(plugin, monkeypatch) -> None:
    plugin, events = plugin
    plugin._len_spin.setValue(8)  # 'aaaaaaaabaaaaaaacaaa' — n=4 length 8
    plugin._on_generate()
    wait_for(events, PATTERN_GENERATED)
    harness: list[str] = []
    from eightypwner.modules.builtin import pattern_tool as mod

    monkeypatch.setattr(mod, "_copy", harness.append)
    plugin._on_copy_pattern()
    assert harness == ["aaaabaaa"]  # cyclic(8, n=4) head


def test_generate_n2_matches_pwntools(plugin) -> None:
    plugin, events = plugin
    plugin._len_spin.setValue(20)
    plugin._n_spin_gen.setValue(2)
    plugin._on_generate()
    wait_for(events, PATTERN_GENERATED)
    assert plugin._pattern_view.toPlainText().startswith("aabacadaeafagahaiaja")


def test_generate_error_note(plugin) -> None:
    """length > 26^n degrades to a status note, never a crash."""
    plugin, events = plugin
    plugin._len_spin.setValue(1000)
    plugin._n_spin_gen.setValue(2)  # period 676 < length 1000
    plugin._on_generate()
    wait_for(events, PATTERN_GENERATED)
    assert "failed" in plugin._search_note.text().lower()


def test_lookup_finds_baaa(plugin) -> None:
    plugin, events = plugin
    plugin._query_edit.setText("baaa")
    plugin._on_find_clicked()
    wait_for(events, PATTERN_LOOKUP_RESULT)
    assert "offset 4" in plugin._result.text()


def test_lookup_hex_and_bytes_forms(plugin) -> None:
    plugin, events = plugin
    plugin._query_edit.setText("0x61616162")
    plugin._on_find_clicked()
    wait_for(events, PATTERN_LOOKUP_RESULT)
    assert "offset 4" in plugin._result.text()

    plugin._query_edit.setText("61 61 61 62")  # bytes 'aaab'
    plugin._on_find_clicked()
    wait_for(events, PATTERN_LOOKUP_RESULT)
    assert "offset 1" in plugin._result.text()


def test_lookup_not_found(plugin) -> None:
    plugin, events = plugin
    plugin._query_edit.setText("0xdeadbeef")
    plugin._on_find_clicked()
    wait_for(events, PATTERN_LOOKUP_RESULT)
    text = plugin._result.text().lower()
    assert "no offset found" in text


def test_lookup_unparseable_hint(plugin) -> None:
    plugin, events = plugin
    plugin._query_edit.setText("!!! ???")
    plugin._on_find_clicked()
    wait_for(events, PATTERN_LOOKUP_RESULT)
    assert "no offset found" in plugin._result.text().lower()
    assert "parseable" in plugin._result.text().lower()


def test_empty_query_is_rejected_locally(plugin) -> None:
    plugin, events = plugin
    plugin._query_edit.setText("")
    plugin._on_find_clicked()
    assert "type a value first" in plugin._result.text().lower()
    assert not [1 for t, _ in events if t == PATTERN_LOOKUP_RESULT]


# ------------------------------------------------------------------ debugger
def test_registers_populate_combo(plugin) -> None:
    plugin, _ = plugin
    plugin._handle_event(
        "debugger_registers",
        {"values": {"$rip": "0x4011bf", "$rsp": "0x3ffffff0", "$rax": "0x0"}, "changed": []},
    )
    names = [plugin._reg_combo.itemText(i) for i in range(plugin._reg_combo.count())]
    assert "$rax" in names and "$rsp" in names


def test_use_register_fills_query(plugin) -> None:
    plugin, _ = plugin
    plugin._handle_event(
        "debugger_registers", {"values": {"$rdi": "0x61616162"}, "changed": []}
    )
    plugin._reg_combo.setCurrentText("$rdi")
    plugin._on_use_register()
    assert plugin._query_edit.text() == "0x61616162"


def test_use_register_without_debugger_message(plugin) -> None:
    plugin, _ = plugin
    plugin._on_use_register()  # empty registers
    assert "debugger must be stopped" in plugin._result.text().lower()


def test_crash_stop_auto_suggests_offset(plugin) -> None:
    plugin, events = plugin
    payload = {
        "reason": "sigsegv",
        "signal": "SIGSEGV",
        "pc": "0x4011bf",
        "sp": "0x3ffffff0",
        "regs": {"$rip": "0x4011bf", "$rbp": "0x6161616261616161"},
        "changed": [],
    }
    plugin._handle_event("debugger_state", {"state": "stopped"})
    plugin._handle_event("debugger_stopped", payload)
    wait_for(events, PATTERN_LOOKUP_RESULT)
    text = plugin._result.text().lower()
    assert "auto" in text and "offset" in text


def test_non_crash_stop_does_not_suggest(plugin) -> None:
    plugin, events = plugin
    plugin._handle_event("debugger_state", {"state": "stopped"})
    plugin._handle_event(
        "debugger_stopped",
        {"reason": "breakpoint-hit", "signal": "", "regs": {"$rbp": "0x6161616261616161"}},
    )
    app = QApplication.instance()
    for _ in range(10):
        app.processEvents()
        time.sleep(0.02)
    assert not [p for t, p in events if t == PATTERN_LOOKUP_RESULT and p.get("origin") == "auto"]
    assert "crash detected" not in plugin._result.text().lower()


def test_crash_suggestion_uses_pattern_chunk_offset(plugin) -> None:
    """rbp holding 'aaaa…' suggests offset 0 — the smallest window wins."""
    plugin, events = plugin
    plugin._handle_event("debugger_state", {"state": "stopped"})
    plugin._handle_event(
        "debugger_stopped",
        {
            "reason": "signal-received",
            "signal": "SIGSEGV",
            "regs": {"$rbp": "0x6161616261616161"},
        },
    )
    results = [
        p for p in wait_for(events, PATTERN_LOOKUP_RESULT) if p.get("origin") == "auto"
    ]
    assert results and results[-1]["offset"] == 0
    assert "chunk" in results[-1]["why"]


# ------------------------------------------------------------------ limits
def test_max_length_cap_is_enforced_by_spin(plugin) -> None:
    plugin, _ = plugin
    plugin._len_spin.setValue(MAX_LENGTH + 10)
    assert plugin._len_spin.value() == MAX_LENGTH


def test_preview_truncates_long_generation(plugin) -> None:
    plugin, events = plugin
    plugin._len_spin.setValue(GENERATED_PREVIEW + 1000)
    plugin._on_generate()
    wait_for(events, PATTERN_GENERATED)
    text = plugin._pattern_view.toPlainText()
    assert len(text) <= GENERATED_PREVIEW + 100  # box keeps only the preview
    assert "truncated" in plugin._search_note.text().lower()


# ------------------------------------------------------------------ themes
def test_renders_both_themes_no_clip(qtbot) -> None:
    from PySide6.QtGui import QColor

    for tokens in (DARK_TOKENS, LIGHT_TOKENS):
        app = QApplication.instance()
        previous = app.styleSheet()
        app.setStyleSheet(render_theme("dark" if tokens is DARK_TOKENS else "light").qss)
        try:
            plugin = PatternToolPlugin(
                PluginContext(
                    bus=EventBus(), settings=Settings(), app_version="t",
                    ui_bus=None, theme=FakeTheme(tokens),
                )
            )
            panel = plugin.widget()
            qtbot.addWidget(panel)
            panel.resize(760, 420)
            panel.show()
            plugin.initialize()
            for _ in range(4):
                panel.repaint()
                app.processEvents()
            image = panel.grab().toImage()
            assert image.width() == 760 and image.height() == 420
            # every child's layout box fits inside the viewport (no clipping)
            for child in panel.findChildren(QObject):
                if hasattr(child, "geometry") and child.parent() is panel:
                    geo = child.geometry()
                    assert geo.right() <= panel.width()
                    assert geo.bottom() <= panel.height()
            # the visible path: label text is styled (not default-black on dark)
            region = QColor(image.pixel(20, 40)).name()
            assert region != "#000000"
            plugin.shutdown()
        finally:
            app.setStyleSheet(previous)


def test_narrow_dock_usable(plugin) -> None:
    plugin, _ = plugin
    panel = plugin.widget()
    panel.resize(360, 300)
    for _ in range(4):
        panel.repaint()
        QApplication.instance().processEvents()
    # controls stay clickable: generate still produces text
    plugin._len_spin.setValue(6)
    plugin._on_generate()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if plugin._pattern_view.toPlainText():
            break
        QApplication.instance().processEvents()
        time.sleep(0.02)
    assert plugin._pattern_view.toPlainText().startswith("aaaaba")


def test_docs_screenshots_dark_and_light(qtbot) -> None:
    """Regenerate docs screenshots with the real QSS; both modes differ."""
    app = QApplication.instance()
    app.setStyle("Fusion")
    screenshots: dict[str, bytes] = {}
    for mode, tokens in (("dark", DARK_TOKENS), ("light", LIGHT_TOKENS)):
        previous = app.styleSheet()
        app.setStyleSheet(render_theme(mode).qss)
        try:
            plugin = PatternToolPlugin(
                PluginContext(
                    bus=EventBus(), settings=Settings(), app_version="t",
                    ui_bus=None, theme=FakeTheme(tokens),
                )
            )
            panel = plugin.widget()
            dock = QDockWidget(f"{plugin.icon} {plugin.name}")
            dock.setWidget(panel)
            dock.setParent(None)
            dock.resize(760, 420)
            dock.show()
            plugin.initialize()
            # a generated pattern + one lookup: both halves populated
            plugin._len_spin.setValue(120)
            plugin._n_spin_gen.setValue(4)
            plugin._on_generate()
            wait_for_plugin(plugin, PATTERN_GENERATED)
            plugin._query_edit.setText("0x61616162")
            plugin._on_find_clicked()
            wait_for_plugin(plugin, PATTERN_LOOKUP_RESULT)
            for _ in range(4):
                dock.repaint()
                app.processEvents()
            docs = SAMPLE_ROOT / "docs"
            docs.mkdir(exist_ok=True)
            path = docs / f"pattern-{mode}.png"
            assert dock.grab().save(str(path))
            screenshots[mode] = path.read_bytes()
            plugin.shutdown()
            dock.close()
            dock.deleteLater()
        finally:
            app.setStyleSheet(previous)
    assert screenshots["dark"] != screenshots["light"]


def wait_for_plugin(plugin: PatternToolPlugin, topic: str, timeout: float = 10.0) -> None:
    """Pump until the plugin's UI-thread handler has consumed *topic*."""
    app = QApplication.instance()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if topic == PATTERN_GENERATED and plugin._copy_pat_btn.isEnabled():
            break
        if topic == PATTERN_LOOKUP_RESULT and "offset" in plugin._result.text().lower():
            break
        app.processEvents()
        time.sleep(0.02)
    for _ in range(6):
        app.processEvents()
        time.sleep(0.02)
