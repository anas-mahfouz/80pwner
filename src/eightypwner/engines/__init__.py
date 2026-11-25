# 80PWNER — by Anas Mahfouz (The 80)

"""Engine wrappers (GDB/MI, Capstone, LIEF, gadgets) — placeholders for Steps 3-9.

Engines are imported lazily at the call sites that need them so the app stays
usable when a dependency (or GDB itself) is missing, with clear install hints.
"""
