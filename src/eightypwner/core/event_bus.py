# 80PWNER — by Anas Mahfouz (The80)

"""Central pub/sub event bus.

Modules communicate ONLY through this bus (spec §4), so they can be added or
removed without breaking others. Subscribers must return quickly; heavy work
(disassembly, gadget search, GDB I/O) belongs in worker threads, never on the
publisher's thread.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)

# Canonical topics (spec §4). Modules may publish new topics, but keystone
# events used by the core UI live here to keep names consistent.
BINARY_DROPPED = "binary_dropped"
BINARY_LOADED = "binary_loaded"
BINARY_CLOSED = "binary_closed"
BINARY_LOAD_FAILED = "binary_load_failed"
OPEN_BINARY_REQUESTED = "open_binary_requested"
DEBUGGER_STOPPED = "debugger_stopped"
ADDRESS_SELECTED = "address_selected"
FUNCTION_SELECTED = "function_selected"
FUNCTIONS_DISCOVERED = "functions_discovered"  # worker→UI: index + ready disassembler
DISASSEMBLY_READY = "disassembly_ready"  # worker→UI: one view (address, instructions)


class EventBus:
    """Simple synchronous pub/sub with wildcard ("*") subscriptions.

    Callbacks receive ``(topic, payload)``. A failing callback is logged and
    skipped — one broken module can never take down the app (spec §8).
    """

    def __init__(self) -> None:
        self._subs: dict[str, list[Callable[[str, Any], None]]] = defaultdict(list)

    def subscribe(self, topic: str, callback: Callable[[str, Any], None]) -> Callable[[], None]:
        """Register *callback* for *topic* (or "*" for all). Returns an unsubscribe fn."""
        self._subs[topic].append(callback)
        return lambda: self.unsubscribe(topic, callback)

    def unsubscribe(self, topic: str, callback: Callable[[str, Any], None]) -> None:
        try:
            self._subs[topic].remove(callback)
        except ValueError:
            log.debug("Unsubscribe ignored: %r not subscribed to %r", callback, topic)

    def publish(self, topic: str, payload: Any = None) -> None:
        """Dispatch synchronously to topic watchers, then wildcard watchers."""
        log.debug("Event %s: %r", topic, payload)
        for callback in list(self._subs.get(topic, [])) + list(self._subs.get("*", [])):
            try:
                callback(topic, payload)
            except Exception:
                log.exception("Event subscriber failed on %s", topic)

    # Alias for readability at call sites.
    emit = publish
