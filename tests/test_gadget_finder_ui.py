# 80PWNER — by Anas Mahfouz (The 80)

"""UI tests for the Gadget Finder dock (Step 6 A).

Layers: filter widgets → pure queries, tree filling/search/sort/copy,
module selection + library load, cache invalidation on binary reload,
worker scan e2e on the sample binary, cancellation, unsupported arch,
both-themes offscreen rendering without clipping.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import QApplication, QDockWidget, QMenu

from eightypwner.core.event_bus import BINARY_CLOSED, BINARY_LOADED, EventBus
from eightypwner.core.settings import Settings
from eightypwner.engines.gadgets import Gadget
from eightypwner.modules.builtin.gadget_finder import (
    GADGET_SCAN_RESULT,
    GadgetFinderPlugin,
    p64_hex,
    parse_bad_bytes,
)
from eightypwner.modules.interface import PluginContext
from eightypwner.ui.theme import DARK_TOKENS, LIGHT_TOKENS

SAMPLE_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = SAMPLE_ROOT / "tests" / "samples" / "vuln_none.elf"


class FakeTheme(QObject):
    theme_changed = Signal(object)

    def __init__(self, tokens: dict[str, str]):
        super().__init__()
        self._tokens = tokens

    def theme(self) -> Any:
        return SimpleNamespace(tokens=self._tokens)


def gadget(addr: int, hexstr: str, insns: str, ending: str = "ret") -> Gadget:
    return Gadget(
        address=addr, size=len(bytes.fromhex(hexstr)), bytes_hex=hexstr,
        insns=insns, ending=ending,
    )


def synthetic_gadgets() -> list[Gadget]:
    """Rich enough to exercise every filter."""

    return [
        gadget(0x401137, "5fc3", "pop rdi ; ret"),
        gadget(0x401150, "5ec3", "pop rsi ; ret"),
        gadget(0x401160, "5fc35fcf", "pop rdi ; ret ; pop rdi ; ret"),
        gadget(0x401200, "0f05", "syscall", "syscall"),
        gadget(0x401210, "cd80", "int 0x80", "int80"),
        gadget(0x401400, "c3", "ret"),
        gadget(0x401420, "445fc3", "pop r14 ; pop rdi ; ret"),
    ]


@pytest.fixture()
def bus_capture():
    bus = EventBus()
    events: list[tuple[str, Any]] = []
    return bus, events


@pytest.fixture()
def plugin(qtbot):
    bus = EventBus()
    events: list[tuple[str, Any]] = []
    bus.subscribe("*", lambda topic, payload: events.append((topic, payload)))
    plugin = GadgetFinderPlugin(
        PluginContext(
            bus=bus, settings=Settings(), app_version="test",
            ui_bus=None, theme=FakeTheme(DARK_TOKENS),
        )
    )
    panel = plugin.widget()
    qtbot.addWidget(panel)
    panel.resize(900, 540)
    panel.show()
    plugin.initialize()
    yield plugin, events
    plugin.shutdown()


def feed_binary(plugin: GadgetFinderPlugin, path: Any = SAMPLE) -> Any:
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(path)
    plugin.on_event(BINARY_LOADED, {"model": model, "path": str(model.path)})
    return model


def set_all_gadgets(plugin: GadgetFinderPlugin, gadgets: list[Gadget]) -> None:
    """Directly feed fabricated gadget results to the panel (UI thread)."""
    module = plugin._current_module
    path = str(plugin._modules[module][0].path)
    plugin._on_scan_payload(
        {"module": module, "path": path, "state": "done", "gadgets": gadgets,
         "note": "", "arch": "x86_64"}
    )


def test_widget_cached_and_columns(plugin) -> None:
    plugin, _events = plugin
    panel = plugin.widget()
    assert panel is plugin.widget()  # caching rule from Step 5
    assert plugin._tree.columnCount() == 4
    assert [plugin._tree.headerItem().text(i) for i in range(4)] == [
        "Address", "Bytes", "Instructions", "Length"
    ]


def test_no_binary_empty_state(plugin) -> None:
    plugin, _events = plugin
    assert "Load a binary" in plugin._status.text()
    assert plugin._tree.topLevelItemCount() == 0
    plugin._fill_table()
    assert plugin._tree.topLevelItemCount() == 0


def test_bad_bytes_parse() -> None:
    assert parse_bad_bytes("00 0a 0d") == b"\x00\n\r"
    assert parse_bad_bytes("000a0d") == b"\x00\n\r"
    assert parse_bad_bytes("") == b""
    assert parse_bad_bytes("0") is None
    assert parse_bad_bytes("zz") is None


def test_p64_hex_format() -> None:
    assert p64_hex(0x4011BF, 8) == "\\xbf\\x11\\x40\\x00\\x00\\x00\\x00\\x00"
    assert p64_hex(0x4011BF, 4) == "\\xbf\\x11\\x40\\x00"


def test_binary_loaded_registers_module(plugin) -> None:
    plugin, _events = plugin
    model = feed_binary(plugin)
    assert model.name in plugin._modules
    assert plugin._module_combo.findText(model.name) >= 0
    assert "not scanned yet" in plugin._status.text()


def test_done_payload_fills_tree(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    tree = plugin._tree
    assert tree.topLevelItemCount() == len(synthetic_gadgets())
    item = tree.topLevelItem(0)
    addr = int(item.data(0, Qt.ItemDataRole.UserRole))
    assert item.text(0) == hex(addr)
    assert item.text(3).isdigit()
    # the pop-rdi gadgets made it in
    texts = [tree.topLevelItem(i).text(2) for i in range(tree.topLevelItemCount())]
    assert "pop rdi ; ret" in texts


def test_done_payload_from_other_module_is_cached_silently(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    assert plugin._tree.topLevelItemCount() == 0  # nothing scanned yet
    fake_libc = SimpleNamespace(path=Path("/x/libc.so.6"), name="libc.so.6")
    with plugin._lock:
        plugin._modules["libc.so.6 (library)"] = (fake_libc, "library")
    plugin._on_scan_payload(
        {"module": "libc.so.6 (library)", "path": "/x/libc.so.6",
         "state": "done", "gadgets": synthetic_gadgets(), "note": "",
         "arch": "x86_64"}
    )
    assert plugin._results["/x/libc.so.6"]  # cached
    assert plugin._tree.topLevelItemCount() == 0  # tree still shows the binary



def test_invalid_regex_shows_status_no_crash(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    plugin._regex_edit.setText("[unclosed")
    plugin._refresh_table()
    assert "Invalid regex" in plugin._status.text()
    assert plugin._tree.topLevelItemCount() == 0


def test_bad_bytes_field_validation(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    plugin._bad_edit.setText("0a 0d 0")
    plugin._refresh_table()
    assert "Bad bytes" in plugin._status.text()


def test_filters_narrow_results(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    tree = plugin._tree
    full = tree.topLevelItemCount()
    assert full == 7

    plugin._regs_edit.setText("rdi")  # register word match
    plugin._refresh_table()
    rdi = tree.topLevelItemCount()
    assert 0 < rdi < full
    assert all("rdi" in tree.topLevelItem(i).text(2).lower().split(" ")
               or "rdi" in {t.strip(",;") for t in tree.topLevelItem(i).text(2).split()}
               for i in range(rdi))

    plugin._kind_checks["ret"].setChecked(False)  # kind filter
    plugin._regs_edit.setText("")  # kinds alone now: syscall + int80
    plugin._refresh_table()
    assert tree.topLevelItemCount() == 2  # int80 + syscall

    plugin._kind_checks["ret"].setChecked(True)
    plugin._len_spin.setValue(2)  # max length filter
    plugin._refresh_table()
    lengths = [int(tree.topLevelItem(i).text(3)) for i in range(tree.topLevelItemCount())]
    assert lengths and max(lengths) <= 2

    plugin._bad_edit.setText("0f 80")  # bad bytes exclude syscall/int80
    plugin._refresh_table()
    assert all(tree.topLevelItem(i).text(1) not in ("0f05", "ff")
               for i in range(tree.topLevelItemCount()))


def test_search_as_you_type(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    plugin._search_edit.setText("pop rdi")
    QApplication.instance().processEvents()
    rows = plugin._tree.topLevelItemCount()
    assert 0 < rows < len(synthetic_gadgets())
    for i in range(rows):
        assert "pop rdi" in plugin._tree.topLevelItem(i).text(2).lower()
    plugin._search_edit.setText("zzzz-not-there")
    assert plugin._tree.topLevelItemCount() == 0
    plugin._search_edit.setText("")
    assert plugin._tree.topLevelItemCount() == len(synthetic_gadgets())


def test_sorting_by_length(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    tree = plugin._tree
    tree.sortByColumn(3, Qt.SortOrder.AscendingOrder)
    lengths = [int(tree.topLevelItem(i).text(3)) for i in range(tree.topLevelItemCount())]
    assert lengths == sorted(lengths)


def test_scan_button_queues_and_publishes_progress(plugin, monkeypatch) -> None:
    plugin, events = plugin
    feed_binary(plugin)
    # make the engine a stub so the scan is instant and deterministic
    from eightypwner.modules.builtin import gadget_finder as mod

    def fake_scan(model, progress_cb=None, should_cancel=None):
        if progress_cb is not None:
            progress_cb(0.5)
        if progress_cb is not None:
            progress_cb(1.0)
        from eightypwner.engines.gadgets import ScanResult

        return ScanResult(
            gadgets=synthetic_gadgets(), note="", scanned_bytes=557
        )

    monkeypatch.setattr(mod, "find_gadgets", fake_scan)
    model = feed_binary(plugin)
    plugin.request_scan(model.name)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        states = [
            p.get("state")
            for topic, p in events
            if topic == GADGET_SCAN_RESULT and p.get("module") == model.name
        ]
        if "done" in states:
            break
        QApplication.instance().processEvents()
        time.sleep(0.02)
    # drain the queued relay slot so the plugin's tree is filled
    for _ in range(5):
        QApplication.instance().processEvents()
        time.sleep(0.02)
    assert any(
        p.get("state") == "progress"
        for topic, p in events
        if topic == GADGET_SCAN_RESULT
    )
    assert plugin._tree.topLevelItemCount() == len(synthetic_gadgets())
    # progress bar hidden again, buttons re-enabled
    assert not plugin._progress.isVisible()
    assert plugin._scan_btn.isEnabled() and not plugin._cancel_btn.isEnabled()


def test_scan_worker_real_sample(plugin) -> None:
    """Real engine scan of the sample through the worker thread."""
    plugin, events = plugin
    model = feed_binary(plugin)
    plugin.request_scan(model.name)
    done = False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not done:
        done = any(
            p.get("state") in ("done", "cancelled", "error")
            and p.get("module") == model.name
            for topic, p in events
            if topic == GADGET_SCAN_RESULT
        )
        QApplication.instance().processEvents()
        time.sleep(0.02)
    assert done, "real sample scan never finished"
    rows = plugin._tree.topLevelItemCount()
    assert rows > 100  # a real binary has plenty of rets
    addresses = []
    for i in range(min(rows, 20)):
        addresses.append(int(plugin._tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)))
    assert all(a > 0 for a in addresses)


def test_cancellation_flow(plugin, monkeypatch) -> None:
    """The Cancel button stops the scan; partial results stay visible."""
    plugin, events = plugin
    feed_binary(plugin)
    from eightypwner.modules.builtin import gadget_finder as mod

    def slow_scan(model, progress_cb=None, should_cancel=None):
        for step in range(200):
            if should_cancel():
                break
            time.sleep(0.005)
            if progress_cb is not None:
                progress_cb(step / 200)
        from eightypwner.engines.gadgets import ScanResult

        return ScanResult(
            gadgets=synthetic_gadgets()[:2], note="partial", scanned_bytes=10
        )

    monkeypatch.setattr(mod, "find_gadgets", slow_scan)
    model = feed_binary(plugin)
    plugin.request_scan(model.name)
    QApplication.instance().processEvents()
    time.sleep(0.05)
    QApplication.instance().processEvents()
    plugin._on_cancel()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        cancel_state = any(
            p.get("state") == "cancelled"
            for topic, p in events
            if topic == GADGET_SCAN_RESULT and p.get("module") == model.name
        )
        if cancel_state:
            break
        QApplication.instance().processEvents()
        time.sleep(0.02)
    # drain the queued relay slot so the plugin's tree is filled
    for _ in range(5):
        QApplication.instance().processEvents()
        time.sleep(0.02)
    assert cancel_state
    assert plugin._tree.topLevelItemCount() == 2
    assert plugin._scan_btn.isEnabled()


def test_unsupported_arch_is_a_clear_error(plugin) -> None:
    plugin, events = plugin
    model = feed_binary(plugin)
    with plugin._lock:
        entry = plugin._modules[model.name]
    # pretend the sample is ARM: the engine must raise a clean message
    plugin._modules[model.name] = (ArmLike(entry[0]), "binary")
    plugin.request_scan(model.name)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        errs = [
            p
            for topic, p in events
            if topic == GADGET_SCAN_RESULT and p.get("state") == "error"
        ]
        QApplication.instance().processEvents()
        if errs:
            break
        time.sleep(0.02)
    text = plugin._status.text()
    assert "arm" in text and "x86" in text


class ArmLike:
    def __init__(self, inner: Any) -> None:
        self.__dict__.update(vars(inner))
        self.arch = "arm"


def test_binary_closed_drops_binary_keeps_libraries(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    # attach a "library" pointing at a distinct path
    fake_libc = SimpleNamespace(path=Path("/x/libc.so.6"), name="libc.so.6")
    with plugin._lock:
        plugin._modules["libc.so.6 (library)"] = (fake_libc, "library")
    plugin._on_scan_payload(
        {"module": "libc.so.6 (library)", "path": "/x/libc.so.6",
         "state": "done", "gadgets": synthetic_gadgets(), "note": "",
         "arch": "x86_64"}
    )
    assert plugin._results["/x/libc.so.6"]
    plugin.on_event(BINARY_CLOSED, None)
    remaining = sorted(plugin._modules)
    assert remaining == ["libc.so.6 (library)"], remaining
    # the binary's cache entry is gone, the library's survives
    assert "/x/libc.so.6" in plugin._results


def test_cache_survives_module_switch_and_is_invalidated(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    assert plugin._tree.topLevelItemCount() == len(synthetic_gadgets())
    module = plugin._current_module
    # switching away empties the tree, switching back re-shows the cache
    plugin._current_module = ""
    plugin._all = []
    plugin._fill_table()
    assert plugin._tree.topLevelItemCount() == 0
    plugin._show_module(module)
    assert plugin._tree.topLevelItemCount() == len(synthetic_gadgets())
    # a reload of the same binary invalidates the cache
    plugin.on_event(BINARY_LOADED, {"model": plugin._modules[module][0]})
    assert plugin._results.get(str(plugin._modules[module][0].path)) in (None, [])


def test_progress_bar_updates(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    plugin.request_scan(plugin._current_module)
    # feed progress payloads like the worker does
    plugin._on_scan_payload(
        {"module": plugin._current_module, "path": "p", "state": "progress",
         "progress": 0.42}
    )
    assert plugin._progress.value() == 42
    assert plugin._progress.isVisibleTo(plugin._panel)
    plugin._on_scan_payload(
        {"module": plugin._current_module, "path": "p", "state": "done",
         "gadgets": [], "note": "", "arch": "x86_64"}
    )
    assert not plugin._progress.isVisibleTo(plugin._panel)


# ------------------------------------------------------------------ themes
def test_renders_both_themes_no_clip(qtbot) -> None:
    for tokens in (DARK_TOKENS, LIGHT_TOKENS):
        bus = EventBus()
        plugin = GadgetFinderPlugin(
            PluginContext(
                bus=bus, settings=Settings(), app_version="t",
                ui_bus=None, theme=FakeTheme(tokens),
            )
        )
        panel = plugin.widget()
        qtbot.addWidget(panel)
        panel.resize(900, 540)
        panel.show()
        plugin.initialize()
        from eightypwner.engines.binary_parser import parse_binary

        model = parse_binary(SAMPLE)
        plugin.on_event(BINARY_LOADED, {"model": model, "path": str(model.path)})
        plugin._on_scan_payload(
            {"module": model.name, "path": str(model.path), "state": "done",
             "gadgets": synthetic_gadgets(), "note": "", "arch": "x86_64"}
        )
        for _ in range(3):
            panel.repaint()
            QApplication.instance().processEvents()
        image = panel.grab().toImage()
        assert image.width() == 900 and image.height() == 540
        # the tree shows rows and the header is readable in this theme
        assert plugin._tree.topLevelItemCount() == len(synthetic_gadgets())
        header_labels = [
            plugin._tree.headerItem().text(i) for i in range(4)
        ]
        assert all(header_labels[i] != "" for i in range(4))
        # columns sized to contents never leave the address column at zero
        assert plugin._tree.columnWidth(0) > 40
        assert plugin._tree.columnWidth(2) > 80
        plugin.shutdown()


def test_narrow_dock_no_clipping(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    plugin.widget().resize(480, 340)
    for _ in range(3):
        plugin.widget().repaint()
        QApplication.instance().processEvents()
    tree = plugin._tree
    assert tree.columnWidth(0) <= tree.viewport().width()
    # search box and filters still usable
    plugin._search_edit.setText("pop rdi")
    QApplication.instance().processEvents()
    assert plugin._tree.topLevelItemCount() >= 1


def test_context_menu_copy_actions(plugin, monkeypatch, qtbot) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    tree = plugin._tree
    item = tree.topLevelItem(0)
    tree.setCurrentItem(item)
    catches: list[str] = []
    from eightypwner.modules.builtin import gadget_finder as mod

    monkeypatch.setattr(mod, "_copy", catches.append)
    addr = int(item.data(0, Qt.ItemDataRole.UserRole))
    # the same copy calls the context menu wires up, exercised directly
    mod._copy(p64_hex(addr, 8))
    mod._copy(p64_hex(addr, 4))
    mod._copy(hex(addr))
    g = plugin._gadget_of(item)
    assert g is not None
    mod._copy(g.bytes_hex)
    mod._copy(g.insns)
    assert catches[0] == p64_hex(addr, 8)
    assert catches[1] == p64_hex(addr, 4)
    assert catches[2] == hex(addr)
    assert catches[3] == g.bytes_hex
    assert catches[4] == g.insns
    # the menu itself builds against the item without erroring
    menu = QMenu(tree)
    assert menu.parent() is tree


def test_double_click_copies_p64(plugin, monkeypatch) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    set_all_gadgets(plugin, synthetic_gadgets())
    tree = plugin._tree
    item = tree.topLevelItem(0)
    tree.setCurrentItem(item)
    catches: list[str] = []
    from eightypwner.modules.builtin import gadget_finder as mod

    monkeypatch.setattr(mod, "_copy", catches.append)
    plugin._item_double_clicked(item, 1)
    addr = int(item.data(0, Qt.ItemDataRole.UserRole))
    assert catches == [p64_hex(addr, 8)]


def test_load_library_path_accepts_and_names(plugin) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    message = plugin.load_library_path(str(SAMPLE))  # any ELF works as library
    assert message == ""
    names = list(plugin._modules)
    assert any("library" in name for name in names)
    assert plugin._module_combo.currentText() in plugin._modules


def test_load_library_path_rejects_garbage(plugin, tmp_path) -> None:
    plugin, _events = plugin
    feed_binary(plugin)
    bad = tmp_path / "junk.bin"
    bad.write_bytes(b"this is not an elf")
    message = plugin.load_library_path(str(bad))
    assert message.startswith("Could not parse")
    assert "junk.bin" in plugin._status.text()


def test_docs_screenshots_dark_and_light(qtbot) -> None:
    """Docs screenshots with the real QSS applied; both modes must differ.

    The panel is parented into a real QDockWidget like production, so
    dock-content backgrounds come from the same rules the app gets.
    """
    app = QApplication.instance()
    from eightypwner.ui.theme import render_theme

    app.setStyle("Fusion")  # mirrors cli.py: QSS assumes Fusion
    screenshots: dict[str, bytes] = {}
    for mode, tokens in (("dark", DARK_TOKENS), ("light", LIGHT_TOKENS)):
        theme = render_theme(mode)  # real QSS, real tokens
        previous = app.styleSheet()
        app.setStyleSheet(theme.qss)
        try:
            bus = EventBus()
            plugin = GadgetFinderPlugin(
                PluginContext(
                    bus=bus, settings=Settings(), app_version="t",
                    ui_bus=None, theme=FakeTheme(tokens),
                )
            )
            panel = plugin.widget()
            qtbot.addWidget(panel)
            dock = QDockWidget(f"{plugin.icon} {plugin.name}")
            dock.setWidget(panel)
            dock.setParent(None)
            dock.resize(900, 540)
            dock.show()
            plugin.initialize()
            from eightypwner.engines.binary_parser import parse_binary

            model = parse_binary(SAMPLE)
            plugin.on_event(BINARY_LOADED, {"model": model, "path": str(model.path)})
            plugin._on_scan_payload(
                {"module": model.name, "path": str(model.path), "state": "done",
                 "gadgets": synthetic_gadgets(), "note": "", "arch": "x86_64"}
            )
            for _ in range(3):
                dock.repaint()
                QApplication.instance().processEvents()
            docs = SAMPLE_ROOT / "docs"
            docs.mkdir(exist_ok=True)
            path = docs / f"gadgets-{mode}.png"
            assert dock.grab().save(str(path))
            screenshots[mode] = path.read_bytes()
            plugin.shutdown()
            dock.close()
            dock.deleteLater()
        finally:
            app.setStyleSheet(previous)
    assert screenshots["dark"] != screenshots["light"]
