# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""glibc heap parser (Step 8).

Turns a raw memory snapshot of the main heap into structured chunks and
tcache bins — the two things you actually reason about while exploiting a
heap bug (overflow into the next chunk's size field, tcache poisoning,
double-free, unsorted-bin leaks).

Input is deliberately plain bytes plus the heap base, so the exact same
parser serves the live debugger snapshot and an imported core/heap dump.
Pure engine: no Qt, no processes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MINSIZE = 0x20
ALIGN = 0x10
TCACHE_BINS = 64
TCACHE_MAX = 7  # glibc tcache_count default

PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4
FLAG_MASK = 0x7

MAX_CHUNKS = 8192


@dataclass(frozen=True)
class HeapChunk:
    """One malloc_chunk as seen in memory (header at *addr*)."""

    addr: int
    size: int  # total chunk size, flags stripped
    prev_size: int
    flags: int
    inuse: bool
    top: bool = False

    @property
    def prev_inuse(self) -> bool:
        return bool(self.flags & PREV_INUSE)

    @property
    def mmapped(self) -> bool:
        return bool(self.flags & IS_MMAPPED)

    @property
    def non_main_arena(self) -> bool:
        return bool(self.flags & NON_MAIN_ARENA)

    @property
    def user(self) -> int:
        return self.addr + 2 * 8  # 64-bit; UI overrides with the real header size

    @property
    def user_size(self) -> int:
        return max(self.size - 0x10, 0)

    def flags_text(self) -> str:
        bits = []
        if self.flags & PREV_INUSE:
            bits.append("PREV_INUSE")
        if self.flags & IS_MMAPPED:
            bits.append("IS_MMAPPED")
        if self.flags & NON_MAIN_ARENA:
            bits.append("NON_MAIN_ARENA")
        return "|".join(bits) if bits else "0"


@dataclass(frozen=True)
class TcacheBin:
    index: int
    chunk_size: int
    count: int
    entries: tuple[int, ...] = ()

    @property
    def empty(self) -> bool:
        return self.count == 0


@dataclass
class HeapResult:
    base: int = 0
    end: int = 0
    chunks: list[HeapChunk] = field(default_factory=list)
    tcache: list[TcacheBin] = field(default_factory=list)
    tcache_struct: int | None = None
    tcache_layout: str = ""
    note: str = ""
    truncated: bool = False

    @property
    def total_chunks(self) -> int:
        return len(self.chunks)

    @property
    def in_use(self) -> int:
        return sum(1 for c in self.chunks if c.inuse)

    @property
    def free_chunks(self) -> list[HeapChunk]:
        return [c for c in self.chunks if not c.inuse]

    @property
    def top_chunk(self) -> HeapChunk | None:
        for chunk in reversed(self.chunks):
            if chunk.top:
                return chunk
        return None

    @property
    def tcache_total(self) -> int:
        return sum(bin_.count for bin_ in self.tcache)

    def bin_for_chunk(self, chunk: HeapChunk) -> TcacheBin | None:
        for bin_ in self.tcache:
            if chunk.addr in bin_.entries:
                return bin_
            if bin_.chunk_size == chunk.size and chunk.addr in bin_.entries:
                return bin_
        return None


def _u(data: bytes, offset: int, width: int) -> int | None:
    if offset < 0 or offset + width > len(data):
        return None
    return int.from_bytes(data[offset : offset + width], "little")


def tcache_chunk_size(index: int, bits: int = 64) -> int:
    """glibc tcache index → chunk size (idx = (size - MINSIZE) / ALIGN)."""
    minimum = 0x20 if bits == 64 else 0x10
    align = 0x10 if bits == 64 else 0x8
    return minimum + index * align


def _parse_tcache_layout(
    data: bytes,
    struct_offset: int,
    count_size: int,
    bits: int,
) -> tuple[list[TcacheBin], int] | None:
    """Try one tcache_perthread_struct layout; return (bins, score) or None.

    Counts above ``TCACHE_MAX`` are kept (a corrupt tcache count is exactly the
    kind of thing you want to see); they only lower the layout score. The
    layout is rejected when the entry array runs past the snapshot.
    """
    ptr = bits // 8
    counts_len = TCACHE_BINS * count_size
    entries_off = struct_offset + counts_len
    if entries_off + TCACHE_BINS * TCACHE_MAX * ptr > len(data):
        return None
    bins: list[TcacheBin] = []
    score = 0
    for index in range(TCACHE_BINS):
        count = _u(data, struct_offset + index * count_size, count_size)
        if count is None:
            return None
        entries: list[int] = []
        for slot in range(count):
            entry = _u(data, entries_off + (index * TCACHE_MAX + slot) * ptr, ptr)
            if entry is None:
                # count claims more entries than the struct can hold → corrupt
                # or wrong layout; the caller still sees the count.
                break
            entries.append(entry)
        if 0 < count <= TCACHE_MAX:
            score += 2 + count
        elif count > TCACHE_MAX:
            score -= 1
        bins.append(
            TcacheBin(
                index=index,
                chunk_size=tcache_chunk_size(index, bits),
                count=count,
                entries=tuple(entries),
            )
        )
    return bins, score


def parse_tcache(data: bytes, base: int = 0, bits: int = 64) -> tuple[list[TcacheBin], int | None, str]:
    """Parse tcache_perthread_struct from a heap snapshot.

    glibc ≥ 2.30 uses ``uint16_t counts[64]``; older releases use
    ``char counts[64]``. The modern layout is preferred whenever its high
    count bytes are zero (the normal case), so no glibc version detection is
    required; otherwise both layouts are scored and the plausible one wins.
    Returns ``(bins, struct_address, layout_name)``.
    """
    if not data:
        return [], None, ""
    header = 0x10 if bits == 64 else 0x8
    struct_offset = header  # user area of the first heap chunk
    min_len = struct_offset + TCACHE_BINS * 2 + TCACHE_BINS * TCACHE_MAX * (bits // 8)
    if min_len > len(data) and (
        struct_offset + TCACHE_BINS + TCACHE_BINS * TCACHE_MAX * (bits // 8) > len(data)
    ):
        # Still try the older (smaller) layout on short snapshots.
        return [], None, ""
    candidates: list[tuple[int, list[TcacheBin], str]] = []
    for count_size, name in ((2, "uint16 counts (glibc ≥ 2.30)"), (1, "char counts (glibc < 2.30)")):
        parsed = _parse_tcache_layout(data, struct_offset, count_size, bits)
        if parsed is None:
            continue
        bins, score = parsed
        if count_size == 2 and all(
            _u(data, struct_offset + index * 2 + 1, 1) == 0 for index in range(TCACHE_BINS)
        ):
            score += 100  # counts that fit in one byte: modern glibc layout
        candidates.append((score, bins, name))
    if not candidates:
        return [], None, ""
    candidates.sort(key=lambda item: item[0], reverse=True)
    _score, bins, name = candidates[0]
    return bins, base + struct_offset, name


def parse_chunks(
    data: bytes,
    base: int = 0,
    bits: int = 64,
    max_chunks: int = MAX_CHUNKS,
) -> list[HeapChunk]:
    """Walk the malloc chunk chain from the heap base."""
    header = 0x10 if bits == 64 else 0x8
    ptr = bits // 8
    align = 0x10 if bits == 64 else 0x8
    minimum = 0x20 if bits == 64 else 0x10
    chunks: list[HeapChunk] = []
    offset = 0
    while offset + header <= len(data) and len(chunks) < max_chunks:
        prev_size = _u(data, offset, ptr)
        size_field = _u(data, offset + ptr, ptr)
        if prev_size is None or size_field is None:
            break
        size = size_field & ~FLAG_MASK
        flags = size_field & FLAG_MASK
        if size < minimum or size % align:
            break
        remaining = len(data) - offset
        top = False
        if size > remaining:
            # The top chunk usually runs past a bounded snapshot: still show it.
            top = True
            size = remaining
            chunks.append(
                HeapChunk(
                    addr=base + offset,
                    size=size,
                    prev_size=prev_size,
                    flags=flags,
                    inuse=True,  # wilderness is never free-list material
                    top=True,
                )
            )
            break
        # Top chunk: the next header would start beyond the arena (or is the
        # last chunk with the wilderness size). Mark it when its size is the
        # unsigned remainder of the heap.
        if offset + size == len(data) and size >= minimum:
            top = True
        chunks.append(
            HeapChunk(
                addr=base + offset,
                size=size,
                prev_size=prev_size,
                flags=flags,
                inuse=True,  # corrected below from the *next* chunk's bit
                top=top,
            )
        )
        if top:
            break
        offset += size

    # PREV_INUSE in a chunk header describes the chunk *before* it. A chunk is
    # in use iff the following chunk says so; the top/wilderness chunk always is.
    corrected: list[HeapChunk] = []
    for index, chunk in enumerate(chunks):
        if chunk.top or index + 1 >= len(chunks):
            inuse = True
        else:
            inuse = bool(chunks[index + 1].flags & PREV_INUSE)
        corrected.append(
            HeapChunk(
                addr=chunk.addr,
                size=chunk.size,
                prev_size=chunk.prev_size,
                flags=chunk.flags,
                inuse=inuse,
                top=chunk.top,
            )
        )
    return corrected


def analyze_heap(
    data: bytes,
    base: int = 0,
    bits: int = 64,
    end: int | None = None,
    max_chunks: int = MAX_CHUNKS,
) -> HeapResult:
    """Full snapshot analysis: chunk chain + tcache + notes."""
    result = HeapResult(base=base, end=end if end is not None else base + len(data))
    if not data:
        result.note = "Empty heap snapshot."
        return result
    result.chunks = parse_chunks(data, base, bits, max_chunks=max_chunks)
    result.tcache, result.tcache_struct, result.tcache_layout = parse_tcache(data, base, bits)

    if not result.chunks:
        result.note = (
            "No valid malloc chunks at this base — the snapshot may start after "
            "the heap header, or this is not a glibc heap."
        )
        return result
    if len(result.chunks) >= max_chunks:
        result.truncated = True
        result.note = f"Stopped after {max_chunks} chunks."
    last = result.chunks[-1]
    if last.addr + last.size >= result.end and not last.top:
        # Reached the end of a bounded read: the wilderness continues.
        last = HeapChunk(
            addr=last.addr,
            size=last.size,
            prev_size=last.prev_size,
            flags=last.flags,
            inuse=last.inuse,
            top=True,
        )
        result.chunks[-1] = last
    return result


def chunk_rows(result: HeapResult) -> list[tuple[str, str, str, str, str]]:
    """UI-ready rows: (address, size, flags, state, note)."""
    rows: list[tuple[str, str, str, str, str]] = []
    tcache_addrs = {entry for bin_ in result.tcache for entry in bin_.entries}
    for chunk in result.chunks:
        state = "top" if chunk.top else ("in-use" if chunk.inuse else "free")
        note_bits = []
        if chunk.top:
            note_bits.append("wilderness")
        if chunk.addr in tcache_addrs:
            bin_ = next((b for b in result.tcache if chunk.addr in b.entries), None)
            if bin_ is not None:
                note_bits.append(f"tcache[{bin_.index}]")
        if chunk.non_main_arena:
            note_bits.append("non-main-arena")
        if chunk.mmapped:
            note_bits.append("mmapped")
        rows.append(
            (
                f"{chunk.addr:#x}",
                f"{chunk.size:#x}",
                chunk.flags_text(),
                state,
                ", ".join(note_bits),
            )
        )
    return rows
