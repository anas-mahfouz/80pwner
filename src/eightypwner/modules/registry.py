# 80PWNER — by Anas Mahfouz (The80)

"""Plugin registry: creation of built-in modules + external entry-point loading.

Third-party distributions expose ``80pwner.plugins`` entry points pointing at
:class:`~eightypwner.modules.interface.Plugin` subclasses.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

from eightypwner.modules import builtin
from eightypwner.modules.interface import Plugin, PluginContext

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "80pwner.plugins"


class PluginRegistry:
    def __init__(self, ctx: PluginContext) -> None:
        self.ctx = ctx
        self.plugins: list[Plugin] = []

    def register(self, plugin: Plugin) -> None:
        if not isinstance(plugin, Plugin):
            raise TypeError(f"Not a Plugin: {plugin!r}")
        if any(p.name == plugin.name for p in self.plugins):
            log.warning("Duplicate plugin name %r ignored", plugin.name)
            return
        plugin.initialize()
        self.plugins.append(plugin)
        log.info("Plugin registered: %s", plugin.name)

    def load_builtins(self) -> None:
        for cls in _builtin_classes():
            try:
                self.register(cls(self.ctx))
            except Exception:
                log.exception("Failed to load builtin plugin %r", cls)

    def load_external(self, group: str = ENTRY_POINT_GROUP) -> None:
        for ep in entry_points(group=group):
            try:
                cls = ep.load()
                self.register(cls(self.ctx))
            except Exception:
                log.exception("Failed to load external plugin %r", ep.value)

    def shutdown_all(self) -> None:
        for plugin in self.plugins:
            try:
                plugin.shutdown()
            except Exception:
                log.exception("Plugin %r failed to shut down", plugin.name)


def _builtin_classes() -> list[type[Plugin]]:
    """Discover Plugin subclasses inside the builtins package (per-module scan)."""
    import importlib
    import pkgutil

    classes: list[type[Plugin]] = []
    for info in pkgutil.walk_packages(builtin.__path__, prefix=builtin.__name__ + "."):
        module = importlib.import_module(info.name)
        for attr in vars(module).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, Plugin)
                and attr.__module__ == module.__name__
                and attr is not Plugin
            ):
                classes.append(attr)
    classes.sort(key=lambda c: c.name)
    return classes
