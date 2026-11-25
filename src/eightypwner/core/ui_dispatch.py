# 80PWNER — by Anas Mahfouz (The 80)

"""Cross-thread event marshalling (spec §4: the UI never blocks).

The raw bus is a plain synchronous publisher — callbacks run on the caller's
thread. Workers publish ``binary_loaded`` from a worker thread, so any widget
touching code must receive those events on the UI thread. :class:`UiBus`
bridges that gap: it subscribes to the raw bus and re-dispatches each event
through a Qt signal, which Qt queues onto the UI event loop.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, Signal

log = logging.getLogger(__name__)


class UiBus(QObject):
    """Subscribe-with-callbacks, always delivered on the creating thread."""

    event = Signal(str, object)

    def __init__(self, bus: Any, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._bus = bus
        self._subs: list[tuple[str, Callable[[str, Any], None]]] = []
        self.event.connect(self._route)
        bus.subscribe("*", self._emit_from_bus)

    def _emit_from_bus(self, topic: str, payload: Any) -> None:
        # runs on the publisher's thread; the signal hops threads safely
        self.event.emit(topic, payload)

    def _route(self, topic: str, payload: Any) -> None:
        # runs on the UI thread (queued connection)
        for want, callback in list(self._subs):
            if want == "*" or want == topic:
                try:
                    callback(topic, payload)
                except Exception:
                    log.exception("UI event handler failed on %s", topic)

    def subscribe(self, topic: str, callback: Callable[[str, Any], None]) -> Callable[[], None]:
        """Register a UI-thread callback for *topic* (or "*" for everything)."""
        self._subs.append((topic, callback))
        return lambda: self.unsubscribe(topic, callback)

    def unsubscribe(self, topic: str, callback: Callable[[str, Any], None]) -> None:
        with contextlib.suppress(ValueError):
            self._subs.remove((topic, callback))

    # ---------------------------------------------------------------- publish
    def publish(self, topic: str, payload: Any = None) -> None:
        """Forward-caller transparency: publish on the raw bus.

        Useful when components hold the UiBus but need to emit a new event —
        the emission happens on the caller's thread and UI subscribers receive
        it on this object's thread (the UI thread).
        """
        self._bus.publish(topic, payload)
