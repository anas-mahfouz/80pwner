# 80PWNER — by Anas Mahfouz (The 80)

"""Plugin system for 80PWNER modules (spec §4).

Every module is an independent :class:`Plugin` with a common interface and
communicates only through the event bus, so modules can be added or removed
without breaking others.
"""

from __future__ import annotations
