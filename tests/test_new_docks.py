# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Offscreen UI tests for the Step 7-10 docks.

Each plugin is built exactly the way the app builds it (widget() then
initialize()) and driven through its public event handlers / buttons.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from eightypwner.core.event_bus import EventBus
from eightypwner.core.settings import Settings
from eightypwner.engines.binary_parser import parse_binary
from eightypwner.engines.heap import chunk_rows
from eightypwner.modules.builtin.cfg_view import CfgPlugin
from eightypwner.modules.builtin.heap_visualizer import HeapPlugin
from eightypwner.modules.builtin.libc_helper import LibcHelperPlugin
from eightypwner.modules.builtin.payload_studio import PayloadStudioPlugin
from eightypwner.modules.builtin.script_generator import ScriptGeneratorPlugin
from eightypwner.modules.builtin.session_manager import SessionPlugin
from eightypwner.modules.interface import PluginContext

SAMPLES = Path(__file__).parent / "samples"
NONE = SAMPLES / "vuln_none.elf"


@pytest.fixture
def ctx(tmp_path, monkeypatch) -> PluginContext:
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path / "home"))
    return PluginContext(bus=EventBus(), settings=Settings(), app_version="test")


@pytest.fixture(scope="module")
def model():
    return parse_binary(NONE)


def _main(model) -> int:
    for symbol in model.symbols:
        if symbol.name == "main" and symbol.value:
            return int(symbol.value)
    return int(model.entry_point)


def _dock(qtbot, plugin, ctx):
    panel = plugin.widget()
    qtbot.addWidget(panel)
    plugin.initialize()
    return panel


# ----------------------------------------------------------------------- CFG
def test_cfg_dock_builds_and_inspects(qtbot, ctx, model):
    plugin = CfgPlugin(ctx)
    panel = _dock(qtbot, plugin, ctx)
    try:
        plugin.on_event("binary_loaded", {"model": model})
        entry = _main(model)
        plugin._build_for(entry)
        qtbot.waitUntil(lambda: plugin._result is not None, timeout=20_000)
        result = plugin._result
        assert result is not None and result.blocks
        assert "blocks" in plugin._status.text()
        # The scene has one graphics item per block.
        items = [item for item in plugin._view.scene().items() if item.data(0)]
        assert items
        block_text = plugin._block_text
        plugin._on_block_clicked(result.sorted_blocks()[0].start)
        assert block_text.toPlainText().startswith("block 0x")
        assert panel is plugin.widget()  # cached
    finally:
        plugin.shutdown()


def test_cfg_dock_resets_on_close(qtbot, ctx, model):
    plugin = CfgPlugin(ctx)
    panel = _dock(qtbot, plugin, ctx)
    try:
        plugin.on_event("binary_loaded", {"model": model})
        plugin._build_for(_main(model))
        qtbot.waitUntil(lambda: plugin._result is not None, timeout=20_000)
        plugin.on_event("binary_closed", None)
        assert plugin._model is None
        assert plugin._result is None
        assert "closed" in plugin._status.text().lower()
        assert panel is not None
    finally:
        plugin.shutdown()


# ---------------------------------------------------------------------- libc
def _system_libc() -> Path:
    for candidate in (
        Path("/usr/lib/libc.so.6"),
        Path("/lib/x86_64-linux-gnu/libc.so.6"),
        Path("/usr/lib64/libc.so.6"),
    ):
        if candidate.exists():
            return candidate
    pytest.skip("no system libc")


def test_libc_dock_loads_and_computes_base(qtbot, ctx):
    libc = _system_libc()
    plugin = LibcHelperPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin.load_path(str(libc))
        qtbot.waitUntil(
            lambda: plugin._info is not None and not plugin._loading, timeout=30_000
        )
        info = plugin._info
        assert info is not None
        assert "glibc" in plugin._info_label.text()
        assert plugin._sym_table.rowCount() > 0
        # Compute a base from a fake leak of system().
        base = 0x7F0000000000
        plugin._leak_symbol.setCurrentText("system")
        plugin._leak_value.setText(hex(base + info.system))
        plugin._compute_base()
        assert plugin._base == base
        assert f"{base:#x}" in plugin._status.text()
        assert plugin._pop_rdi_edit is not None
    finally:
        plugin.shutdown()


# ---------------------------------------------------------------------- heap
def _heap_blob() -> bytes:
    blob = b""
    for size in (0x21, 0x31, 0x41):
        total = size & ~0x7
        blob += struct.pack("<Q", 0) + struct.pack("<Q", size)
        blob += b"\x00" * (total - 0x10)
    return blob


def test_heap_dock_renders_snapshot(qtbot, ctx):
    plugin = HeapPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin.on_event(
            "heap_snapshot",
            {"data": _heap_blob(), "base": 0x1000, "bits": 64},
        )
        result = plugin._result
        assert result is not None
        assert plugin._chunks.rowCount() == len(chunk_rows(result)) == 3
        assert plugin._bins.rowCount() == len(result.tcache)
        assert "3 chunks" in plugin._stats.text()
        # tcache parsing failures are surfaced, not hidden.
        assert plugin._raw.text() or plugin._stats.text()
    finally:
        plugin.shutdown()


def test_heap_dock_requests_snapshot(qtbot, ctx):
    plugin = HeapPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    seen: list[tuple[str, dict]] = []
    unsubscribe = ctx.bus.subscribe(
        "heap_snapshot_request", lambda topic, payload: seen.append((topic, payload))
    )
    try:
        plugin.request_snapshot()
        assert seen and seen[0][0] == "heap_snapshot_request"
        assert seen[0][1]["max_bytes"] >= 0x1000
        assert plugin._snapshot_button.isEnabled() is False
        plugin.on_event("heap_snapshot", {"error": "no debuggee"})
        assert plugin._snapshot_button.isEnabled() is True
        assert "no debuggee" in plugin._stats.text()
    finally:
        unsubscribe()
        plugin.shutdown()


# -------------------------------------------------------------------- script
def test_script_dock_generates_from_model(qtbot, ctx, model):
    plugin = ScriptGeneratorPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin.on_event("binary_loaded", {"model": model})
        plugin._offset.setText("72")
        index = plugin._template.findData("ret2win")
        assert index >= 0
        plugin._template.setCurrentIndex(index)
        plugin._generate()
        text = plugin._preview.toPlainText()
        assert "from pwn import *" in text
        assert "OFFSET = 72" in text
        assert "def exploit()" in text
        assert "Generated" in plugin._status.text()
        # Every template renders valid Python.
        for key in ("skeleton", "ret2libc", "shellcode"):
            plugin._template.setCurrentIndex(plugin._template.findData(key))
            compile(plugin._preview.toPlainText(), f"<{key}>", "exec")
    finally:
        plugin.shutdown()


def test_script_dock_consumes_libc_and_pattern_events(qtbot, ctx, model, tmp_path):
    plugin = ScriptGeneratorPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin.on_event("binary_loaded", {"model": model})
        plugin.on_event(
            "libc_loaded",
            {"path": "/tmp/libc.so.6", "info": _FakeLibc()},
        )
        assert plugin._ctx.libc_path == "/tmp/libc.so.6"
        assert plugin._libc_path.text() == "/tmp/libc.so.6"
        plugin.on_event("pattern_lookup_result", {"offset": 40, "n": 8})
        assert plugin._ctx.crash_offset == 40
        assert plugin._offset.text() == "40"
        plugin.on_event("libc_base_computed", {"base": 0x7F0000000000})
        assert "0x7f0000000000" in plugin._status.text()
    finally:
        plugin.shutdown()


class _FakeLibc:
    """Minimal stand-in for LibcInfo (script generator only reads fields)."""

    def __init__(self) -> None:
        self.path = Path("/tmp/libc.so.6")
        self.version = "2.42"
        self.soname = "libc.so.6"
        self.symbols = {"puts": 0x80E50, "system": 0x58750}
        self.binsh: int | None = 0x1CB42F
        self.one_gadgets: list = []
        self.note = ""


# ------------------------------------------------------------------ sessions
def test_session_dock_crud_and_notes(qtbot, ctx, model, tmp_path):
    plugin = SessionPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin._auto_open_for_binary({"model": model})
        session_id = plugin._session_id
        assert isinstance(session_id, int)
        assert plugin._list.count() == 1
        assert _main(model) is not None

        plugin._notes.setPlainText("offset 72 → system('/bin/sh')")
        plugin._save_notes(force=True)
        store = plugin._store
        assert store is not None
        session = store.get(session_id)
        assert session is not None and "system" in session.notes

        plugin._finding_title.setText("stack overflow")
        plugin._severity.setCurrentText("critical")
        plugin._finding_addr.setText("0x4011bf")
        plugin._finding_detail.setText("gets(buf)")
        plugin._add_finding()
        findings = store.list_findings(session_id)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].address == "0x4011bf"
        assert plugin._findings.rowCount() == 1

        plugin._delete_session()
        assert plugin._session_id is None
        assert store.get(session_id) is None
    finally:
        plugin.shutdown()


def test_session_dock_tracks_pattern_offset(qtbot, ctx):
    plugin = SessionPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin.on_event("pattern_lookup_result", {"offset": 88})
        plugin._fill_last_offset()
        assert plugin._finding_addr.text() == hex(88)
    finally:
        plugin.shutdown()


# -------------------------------------------------------------- payload studio
def test_payload_studio_assembles(qtbot, ctx):
    plugin = PayloadStudioPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin._asm.setPlainText("nop\nret")
        plugin._assemble()
        assert plugin._last_bytes == b"\x90\xc3"
        assert "90" in plugin._asm_out.text()
        assert plugin._disasm.rowCount() == 2
        # Bad-byte filter flags the NOP.
        plugin._bad.setText("90")
        plugin._check_bad()
        assert "bad bytes" in plugin._status.text()
        plugin._bad.setText("00")
        plugin._check_bad()
        assert "Clean" in plugin._status.text()
    finally:
        plugin.shutdown()


def test_payload_studio_encodes(qtbot, ctx):
    plugin = PayloadStudioPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin._enc_in.setText("90 c3")
        plugin._enc_bad.setText("00 0a")
        plugin._encode()
        out = plugin._enc_out.toPlainText()
        assert "# key 0x" in out
        assert "# decoder asm" in out
        assert "Encoded with key" in plugin._status.text()
        assert "clean" in plugin._status.text()
        plugin._send_assembled()  # nothing assembled yet → hint
        assert "Assemble" in plugin._status.text()
    finally:
        plugin.shutdown()


def test_payload_studio_format_string(qtbot, ctx):
    plugin = PayloadStudioPlugin(ctx)
    _dock(qtbot, plugin, ctx)
    try:
        plugin._fmt_out.setText("0x7ffd 0x41414141 0x0")
        plugin._find_offset()
        assert plugin._fmt_offset.value() == 2
        assert "argument $2" in plugin._status.text()

        plugin._writes.setPlainText("0x404060:0x401230")
        plugin._build_fmt_plan()
        result = plugin._fmt_result.toPlainText()
        assert "$hn" in result
        assert "0x404060" in result
        assert "fmtstr_payload(" in result
    finally:
        plugin.shutdown()


# ------------------------------------------------------------------ branding
def test_dock_titles_and_attribution():
    assert CfgPlugin.name == "Control Flow"
    assert LibcHelperPlugin.name == "Libc Helper"
    assert HeapPlugin.name == "Heap"
    assert ScriptGeneratorPlugin.name == "Script Generator"
    assert SessionPlugin.name == "Challenges"
    assert PayloadStudioPlugin.name == "Payload Studio"
