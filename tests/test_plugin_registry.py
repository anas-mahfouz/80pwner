# 80PWNER — by Anas Mahfouz (The 80)

from PySide6.QtWidgets import QLabel, QWidget

from eightypwner.core.event_bus import EventBus
from eightypwner.core.settings import Settings
from eightypwner.modules.interface import Plugin, PluginContext
from eightypwner.modules.registry import PluginRegistry


class FakePlugin(Plugin):
    name = "Fake"
    description = "test plugin"

    def widget(self) -> QWidget:
        return QLabel(self.name)


def make_registry() -> tuple[PluginRegistry, Settings, EventBus]:
    bus = EventBus()
    settings = Settings()
    ctx = PluginContext(bus=bus, settings=settings, app_version="test")
    return PluginRegistry(ctx), settings, bus


def test_builtin_welcome_plugin_loads():
    registry, _, _ = make_registry()
    registry.load_builtins()
    names = [p.name for p in registry.plugins]
    assert "Welcome" in names


def test_register_rejects_non_plugin():
    registry, _, _ = make_registry()
    try:
        registry.register("not a plugin")  # type: ignore[arg-type]
    except TypeError:
        return
    raise AssertionError("Expected TypeError")


def test_duplicate_names_ignored():
    registry, _, _ = make_registry()
    a, b = FakePlugin(registry.ctx), FakePlugin(registry.ctx)
    registry.register(a)
    registry.register(b)
    assert [p.name for p in registry.plugins] == ["Fake"]


def test_widgets_generated(tmp_path, monkeypatch):
    monkeypatch.setenv("eightypwner_HOME", str(tmp_path))
    registry, _, _ = make_registry()
    registry.load_builtins()
    for p in registry.plugins:
        assert p.widget() is not None


def test_pending_cleanup_on_shutdown():
    registry, _, _ = make_registry()
    p = FakePlugin(registry.ctx)
    registry.register(p)
    registry.shutdown_all()  # must not raise
