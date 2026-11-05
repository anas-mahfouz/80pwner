# 80PWNER — by Anas Mahfouz (The80)

"""Plugin interface and per-plugin service context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from PySide6.QtCore import QObject
    from PySide6.QtWidgets import QWidget

    from eightypwner.core.event_bus import EventBus
    from eightypwner.core.settings import Settings


@dataclass(frozen=True)
class PluginContext:
    """Services handed to every plugin; keeps plugins decoupled from the app.

    ``ui_bus`` is optional; plugins whose widgets react to events should
    subscribe through it so worker-thread events arrive on the UI thread.
    """

    bus: EventBus
    settings: Settings
    app_version: str
    ui_bus: Any | None = None


class Plugin(ABC):
    """Base class for every 80PWNER module.

    Subclasses set ``name``/``description``/``icon`` as class attributes and
    implement :meth:`widget`. Plugins publish/subscribe on the event bus only —
    they must not reach into other plugins' widgets.
    """

    name: str = "plugin"
    description: str = ""
    icon: str = ""  # emoji or asset path, used as the dock title

    def __init__(self, ctx: PluginContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def widget(self) -> QWidget:
        """Build and return this plugin's panel widget."""

    def on_binary_loaded(self, binary: dict[str, Any]) -> None:  # noqa: B027
        """Called when a new binary is loaded via the ``binary_loaded`` event."""

    def on_event(self, topic: str, payload: Any) -> None:  # noqa: B027
        """Receive every bus event the plugin subscribed to."""

    def initialize(self, parent: QObject | None = None) -> None:  # noqa: B027
        """Optional hook after construction — wire subscriptions here."""

    def shutdown(self) -> None:  # noqa: B027
        """Release resources (threads, processes) before the app exits."""
