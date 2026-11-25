# 80PWNER — by Anas Mahfouz (The 80)

"""Function discovery + xrefs (Step 3).

Sources for the function list: symbols (FUNC type or named code addresses),
the entry point, and call targets found by scanning each executable range
with capstone (in bounded chunks — big binaries stay lazy: discovery caps at
MAX_DISCOVERY_BYTES and decode remains per-function).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from eightypwner.engines.addrmap import AddrMap
from eightypwner.engines.binary_parser import BinaryModel

log = logging.getLogger(__name__)

@dataclass(frozen=True)
class FunctionInfo:
    address: int
    name: str
    size: int = 0
    origin: str = "unknown"  # symbol | entry | call-target


@dataclass(frozen=True)
class Xref:
    from_address: int
    to_address: int
    kind: str  # call | jmp | cond | data


@dataclass
class FunctionIndex:
    functions: list[FunctionInfo] = field(default_factory=list)
    xrefs: list[Xref] = field(default_factory=list)
    scanned_addresses: int = 0
    truncated: bool = False


class FunctionFinder:
    """Builds a FunctionIndex for a binary; address→name lookups afterwards."""

    def __init__(self, model: BinaryModel, addrmap: AddrMap | None = None) -> None:
        self.model = model
        self.addrmap = addrmap or AddrMap(model)

    # -------------------------------------------------------------- Discover
    def discover(self, max_scan: int = 8 * 1024 * 1024) -> FunctionIndex:
        dex = FunctionIndex()
        seen: set[int] = set()
        by_name: dict[str, FunctionInfo] = {}

        # 1. symbols (named, in mapped code ranges)
        for symbol in self.model.symbols:
            address = symbol.value
            if address <= 0 or not self._looks_executable(address):
                continue
            if symbol.size == 0 and symbol.origin == "dynsym":
                continue  # import shims have no body here
            entry = FunctionInfo(address, symbol.name, symbol.size, "symbol")
            if entry.address not in seen:
                seen.add(entry.address)
                dex.functions.append(entry)
                by_name.setdefault(entry.name, entry)

        # 2. entry point
        if self.model.entry_point and self.model.entry_point not in seen:
            dex.functions.append(
                FunctionInfo(
                    self.model.entry_point,
                    "_entry",
                    0,
                    "entry",
                )
            )
            seen.add(self.model.entry_point)

        # 3. call targets from linear scan of executable ranges (bounded)
        from eightypwner.engines.disassembler import Disassembler

        d = Disassembler(self.model)
        total = 0
        for start, size in self._executable_ranges():
            take = min(size, max_scan - total)
            if take <= 0:
                dex.truncated = True
                break
            chunk = d.decode(start, take)
            for insn in chunk:
                total += insn.size or 1
                dex.scanned_addresses = total
                for target in d.branch_targets([insn]):
                    if not self._looks_executable(target.address):
                        continue
                    entry = FunctionInfo(
                        target.address,
                        f"sub_{target.address:x}",
                        0,
                        "call-target",
                    )
                    if entry.address not in seen:
                        seen.add(entry.address)
                        dex.functions.append(entry)
                    dex.xrefs.append(
                        Xref(
                            from_address=insn.address,
                            to_address=target.address,
                            kind=target.kind,
                        )
                    )
            if total >= max_scan:
                dex.truncated = True
                break

        dex.functions.sort(key=lambda fi: fi.address)
        dex.xrefs.sort(key=lambda x: (x.to_address, x.from_address))
        self._names_override(dex)
        return dex

    # ------------------------------------------------------------ utilities
    def _names_override(self, dex: FunctionIndex) -> None:
        """Replace sub_· names when a symbol shares the address."""
        symbol_names = {}
        for fi in dex.functions:
            if fi.origin == "symbol":
                symbol_names[fi.address] = fi.name
        if not symbol_names:
            return
        renamed: list[FunctionInfo] = []
        for fi in dex.functions:
            if fi.origin != "symbol" and fi.address in symbol_names:
                renamed.append(FunctionInfo(fi.address, symbol_names[fi.address], fi.size, "symbol"))
            else:
                renamed.append(fi)
        dedup: dict[int, FunctionInfo] = {}
        for fi in renamed:
            dedup.setdefault(fi.address, fi)
        dex.functions = sorted(dedup.values(), key=lambda f: f.address)

    def _looks_executable(self, vaddr: int) -> bool:
        for section in self.model.sections:
            flags_valid = section.name != ""
            if section.vaddr <= vaddr < section.vaddr + max(section.size, 1) and flags_valid:
                return True
        for seg in self.model.segments:
            if seg.vaddr <= vaddr < seg.vaddr + max(seg.size, 1) and "x" in seg.flags:
                return True
        return False

    def _executable_ranges(self) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        seen_addrs = set()
        for section in self.model.sections:
            is_code = ".text" in section.name or (
                section.type.endswith("PROGBITS") and section.vaddr > 0 and section.size > 0
                and section.name not in (".rodata", ".data") and not re.search(r"data|rodata|debug|note", section.name, re.I)
            )
            if is_code and section.vaddr not in seen_addrs:
                seen_addrs.add(section.vaddr)
                out.append((section.vaddr, min(section.size, 2 * 1024 * 1024)))
        for seg in self.model.segments:
            if "x" in seg.flags and seg.size > 0 and seg.vaddr not in seen_addrs:
                seen_addrs.add(seg.vaddr)
                out.append((seg.vaddr, min(seg.size, 2 * 1024 * 1024)))
        if not out:
            for section in self.model.sections:
                if section.name == ".text":
                    out.append((section.vaddr, min(section.size, 2 * 1024 * 1024)))
        return out


def filter_functions(functions: list, needle: str) -> list:
    """Substring/case-insensitive filter used by the function list panel."""
    if not needle:
        return list(functions)
    needle = needle.lower()
    return [
        fi
        for fi in functions
        if needle in fi.name.lower() or needle in hex(fi.address) or needle in hex(fi.address)[2:]
    ]
