# 80PWNER — by Anas Mahfouz (The 80)

"""vaddr → file-offset mapping and byte reading for ELF/PE/Mach-O.

Baseline for the disassembler: everything addresses by *virtual address*,
reading bytes through the loader mappings of the parsed binary. Works purely
on the BinaryModel produced by the parser (with its file_offset data).
"""

from __future__ import annotations

import logging
from pathlib import Path

from eightypwner.engines.binary_parser import BinaryModel

log = logging.getLogger(__name__)


class ReadError(Exception):
    """vaddr cannot be mapped or read — user-facing, never a crash."""


class Mapped:
    """One address→file translation found for a binary."""

    __slots__ = ("file_offset", "size", "source", "vaddr")

    def __init__(self, vaddr: int, size: int, file_offset: int, source: str) -> None:
        self.vaddr = vaddr
        self.size = size
        self.file_offset = file_offset
        self.source = source  # "segment" | "section"


def build_mappings(model: BinaryModel) -> list[Mapped]:
    """All file-backed mappings, executable segments/sections first."""
    out: list[Mapped] = []
    for seg in model.segments:
        fo = getattr(seg, "file_offset", 0)
        if seg.size > 0 and fo > 0:
            out.append(Mapped(seg.vaddr, seg.size, fo, "segment"))
    for section in model.sections:
        fo = getattr(section, "file_offset", 0)
        if section.size > 0 and fo > 0:
            out.append(Mapped(section.vaddr, section.size, fo, "section"))
    return sorted(out, key=lambda m: m.vaddr, reverse=True)  # last mapping wins


def _load_bytes(path: Path) -> bytes:
    limit = 32 * 1024 * 1024
    try:
        if path.stat().st_size <= limit:
            return path.read_bytes()
        log.info("Reading first %d bytes of huge file %s for disassembly", limit, path)
        return path.read(limit)
    except OSError as exc:
        raise ReadError(f"Cannot read {path}: {exc}") from exc


class AddrMap:
    """Read bytes at virtual addresses, resolved through the mappings."""

    def __init__(self, model: BinaryModel, data: bytes | None = None) -> None:
        self.model = model
        self._data = data if data is not None else _load_bytes(model.path)
        self._mappings = build_mappings(model)

    def read(self, vaddr: int, size: int) -> bytes:
        """Read *size* bytes at *vaddr*; raises ReadError with a clean message."""
        offset = self.to_offset(vaddr)
        if offset is None:
            raise ReadError(f"Address {hex(vaddr)} is not mapped in {self.model.name}.")
        end = offset + size
        if end > len(self._data):
            # clamp to file end but keep what is readable (trailing bss etc.)
            if offset >= len(self._data):
                raise ReadError(f"Address {hex(vaddr)} maps past end of file.")
            return self._data[offset:]
        return self._data[offset:end]

    def to_offset(self, vaddr: int) -> int | None:
        for m in self._mappings:
            if m.vaddr <= vaddr < m.vaddr + m.size:
                delta = vaddr - m.vaddr
                if 0 <= m.file_offset + delta <= len(self._data):
                    return m.file_offset + delta
        return None

    def section_of(self, vaddr: int) -> str:
        """Name of the section containing vaddr, for display."""
        for section in self.model.sections:
            if section.vaddr <= vaddr < section.vaddr + max(section.size, 1):
                return section.name
        return ""
