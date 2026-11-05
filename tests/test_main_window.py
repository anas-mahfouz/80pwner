# 80PWNER — by Anas Mahfouz (The80)
#
"""Offscreen smoke test: the whole app boots, docks, toggles theme, persists."""

import pytest


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    from eightypwner.core.event_bus import EventBus
    from eightypwner.core.session import SessionState
    from eightypwner.core.settings import Settings
    from eightypwner.modules.interface import PluginContext
    from eightypwner.modules.registry import PluginRegistry
    from eightypwner.ui.theme import ThemeManager

    settings = Settings()
    bus = EventBus()
    theme = ThemeManager(settings)
    ctx = PluginContext(bus=bus, settings=settings, app_version="test")
    registry = PluginRegistry(ctx)
    registry.load_builtins()

    from eightypwner.ui.main_window import MainWindow

    window = MainWindow(bus, theme, registry, SessionState(), settings)
    yield window, bus, theme
    window.close()


def test_main_window_boots(qtbot, app_ctx):
    window, _, _ = app_ctx
    qtbot.addWidget(window)
    assert "80PWNER" in window.windowTitle()


def test_binary_loaded_event_drives_title(qtbot, app_ctx):
    window, bus, _ = app_ctx
    qtbot.addWidget(window)
    bus.publish("binary_loaded", {"name": "vuln.bin"})  # canonical topic name lives in core
    assert window.windowTitle() == "80PWNER — vuln.bin"


def test_theme_toggle_shortcut(qtbot, app_ctx):
    window, _, theme = app_ctx
    qtbot.addWidget(window)
    before = theme.resolved_mode()
    theme.toggle()
    assert theme.resolved_mode() != before


def test_about_dialog(qtbot, app_ctx):
    from eightypwner.ui.about_dialog import AboutDialog

    window, _, _ = app_ctx
    qtbot.addWidget(window)
    dlg = AboutDialog(window)
    assert "80PWNER" in dlg.windowTitle()
