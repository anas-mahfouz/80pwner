# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Heap engine tests: chunk-chain walk, tcache parsing, UI rows."""

from __future__ import annotations

import struct

from eightypwner.engines.heap import (
    MINSIZE,
    TcacheBin,
    analyze_heap,
    chunk_rows,
    parse_chunks,
    parse_tcache,
    tcache_chunk_size,
)


def qword(value: int) -> bytes:
    return struct.pack("<Q", value)


def build_chain(*sizes: int) -> bytes:
    """Chunk headers only: prev_size/size per chunk, size includes flags."""
    blob = b""
    for size in sizes:
        total = size & ~0x7
        blob += qword(0) + qword(size)
        blob += b"\x00" * (total - 0x10)
    return blob


def test_simple_chunk_walk():
    # three chunks: 0x20, 0x30, 0x40 — the last one is the wilderness.
    data = build_chain(0x21, 0x31, 0x41)
    chunks = parse_chunks(data, base=0x1000)
    assert [c.size for c in chunks] == [0x20, 0x30, 0x40]
    assert [c.addr for c in chunks] == [0x1000, 0x1020, 0x1050]
    assert chunks[0].inuse is True
    assert chunks[1].inuse is True
    assert chunks[-1].top is True
    assert chunks[0].user == 0x1010
    assert chunks[0].user_size == 0x10


def test_free_chunk_prev_inuse_bit():
    # Mark the middle chunk free by clearing the next chunk's PREV_INUSE bit.
    data = build_chain(0x21, 0x31, 0x40)
    chunks = parse_chunks(data, base=0)
    assert chunks[1].inuse is False
    assert chunks[1].prev_inuse is True  # describes chunk 0
    assert chunks[0].inuse is True


def test_unaligned_size_stops_walk():
    bad = qword(0) + qword(0x28)
    assert parse_chunks(bad + b"\x00" * 0x100, base=0) == []


def test_snapshot_cut_marks_top():
    data = build_chain(0x21, 0x31)
    # chop the second chunk short: its size runs past the snapshot.
    chopped = data[: 0x20 + 0x18]
    chunks = parse_chunks(chopped, base=0)
    assert len(chunks) == 2
    assert chunks[-1].top is True
    assert chunks[-1].size == 0x18


def test_tcache_layout_uint16():
    counts = 64 * 2
    entries = 64 * 7 * 8
    blob = bytearray(0x10 + counts + entries)
    struct.pack_into("<H", blob, 0x10 + 0 * 2, 2)
    struct.pack_into("<H", blob, 0x10 + 3 * 2, 1)
    base_entries = 0x10 + counts
    struct.pack_into("<Q", blob, base_entries + 0 * 7 * 8 + 0, 0xDEAD0)
    struct.pack_into("<Q", blob, base_entries + 0 * 7 * 8 + 8, 0xBEEF0)
    struct.pack_into("<Q", blob, base_entries + 3 * 7 * 8 + 0, 0xCAFE0)
    bins, struct_addr, layout = parse_tcache(bytes(blob), base=0x4000)
    assert struct_addr == 0x4010
    assert "uint16" in layout
    by_index = {bin_.index: bin_ for bin_ in bins}
    assert by_index[0].count == 2
    assert by_index[0].entries == (0xDEAD0, 0xBEEF0)
    assert by_index[0].chunk_size == tcache_chunk_size(0) == MINSIZE
    assert by_index[3].count == 1
    assert by_index[3].entries == (0xCAFE0,)


def test_tcache_keeps_corrupt_counts():
    blob = bytearray(0x10 + 64 * 2 + 64 * 7 * 8)
    struct.pack_into("<H", blob, 0x10, 99)  # impossible but must be visible
    bins, struct_addr, layout = parse_tcache(bytes(blob), base=0)
    assert struct_addr == 0x10
    assert "uint16" in layout
    assert bins[0].count == 99
    assert all(bin_.count == 0 for bin_ in bins[1:])


def test_tcache_needs_full_struct():
    bins, struct_addr, layout = parse_tcache(b"\x00" * 0x100, base=0)
    assert bins == []
    assert struct_addr is None
    assert layout == ""


def test_empty_snapshot():
    result = analyze_heap(b"")
    assert result.note == "Empty heap snapshot."
    assert result.chunks == []


def test_analyze_full_heap():
    data = build_chain(0x21, 0x31, 0x41)
    result = analyze_heap(data, base=0x1000)
    assert result.total_chunks == 3
    assert result.in_use == 3
    assert result.top_chunk is not None
    rows = chunk_rows(result)
    assert rows[0][0] == "0x1000"
    assert rows[-1][3] == "top"


def test_tcache_bin_helpers():
    bin_ = TcacheBin(index=2, chunk_size=0x40, count=0, entries=())
    assert bin_.empty
    known = TcacheBin(index=2, chunk_size=0x40, count=2, entries=(0x10, 0x20))
    assert not known.empty
