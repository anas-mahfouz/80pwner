# 80PWNER — by Anas Mahfouz (The 80)

"""Unit tests for the stack frame layout engine (Step 5).

The layout math is exercised on *fabricated* register/stack snapshots so the
expected addresses are exact, plus the real ``tests/samples`` ELFs for the
DWARF and disassembly-inference paths. The real-gdb end-to-end assertions
live in ``test_stack_visualizer.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from eightypwner.engines.stack_frame import (
    DEFAULT_CANARY_OFFSET,
    KIND_LABEL,
    analyze_frame,
    annotate_value,
    dwarf_frame_variables,
    frame_distances,
    hints_from_instructions,
    value_word_at,
    window_covers,
    word_size_for_arch,
)

SAMPLES = Path(__file__).resolve().parent / "samples"

VULN_NONE_MAIN = 0x4011BF  # verified via DWARF low_pc; kept as a stable anchor


@dataclass
class FakeInsn:
    """Stand-in for engines.disassembler.Instruction (Intel syntax text)."""

    mnemonic: str
    operands: str


# --------------------------------------------------------------- small units
def test_word_size_map():
    assert word_size_for_arch("x86_64") == 8
    assert word_size_for_arch("x86") == 4
    assert word_size_for_arch("X86_64") == 8  # case-insensitive
    assert word_size_for_arch("arm64") is None


def test_value_word_at_and_window_covers():
    data = bytes(range(0x10))
    assert value_word_at(0x1000, data, 0x1000, 4) == int.from_bytes(data[:4], "little")
    assert value_word_at(0x1000, data, 0x100C, 4) == int.from_bytes(data[12:16], "little")
    assert value_word_at(0x1000, data, 0x100D, 4) is None  # partial word
    assert value_word_at(0x1000, data, 0xFF0, 4) is None  # before window
    assert window_covers(0x1000, data, 0x1008, 4)
    assert not window_covers(0x1000, data, 0x1010, 4)


def test_annotate_value_symbol_offset():
    symbols = [(0x401000, "main", 0x400)]
    assert annotate_value(0x401234, word=8, rsp=0x1000, symbols=symbols) == "main+0x234"


def test_annotate_value_stack_pointer():
    assert annotate_value(0x7FFF0100, word=8, rsp=0x7FFF0000) == "stack"


def test_annotate_value_ascii_and_null():
    word = int.from_bytes(b"PWN!", "little")  # 4 printable bytes
    assert annotate_value(word, word=4, rsp=0) == "'PWN!'"
    assert annotate_value(0, word=8, rsp=0) == "<null>"
    assert annotate_value(0xDEADBEEF, word=8, rsp=0) == ""


def test_annotate_value_text_delta_pie():
    # runtime address = static + delta (PIE base)
    symbols = [(0x1150, "main", 0x40)]
    # runtime main = 0x1150 + 0x555555554000 (PIE base); value = main+0x30
    assert (
        annotate_value(0x555555555180, word=8, rsp=0, text_delta=0x555555554000, symbols=symbols)
        == "main+0x30"
    )


def test_hints_frame_pointer_and_locals():
    insns = [
        FakeInsn("endbr64", ""),
        FakeInsn("push", "rbp"),
        FakeInsn("mov", "rbp, rsp"),
        FakeInsn("sub", "rsp, 0x50"),
        FakeInsn("lea", "rax, [rbp-0x40]"),
        FakeInsn("mov", "dword ptr [rbp-0x44], edi"),
    ]
    hints = hints_from_instructions(insns, bits=64)
    assert hints.have_frame_pointer
    assert hints.locals_bytes == 0x50
    assert sorted(set(hints.rbp_refs)) == [-0x44, -0x40]  # sorted ascending (negative)


def test_hints_canary_pattern_fs_0x28():
    insns = [
        FakeInsn("push", "rbp"),
        FakeInsn("mov", "rbp, rsp"),
        FakeInsn("sub", "rsp, 0x20"),
        FakeInsn("mov", "rax, qword ptr fs:0x28"),
        FakeInsn("mov", "qword ptr [rbp-0x8], rax"),
    ]
    hints = hints_from_instructions(insns, bits=64)
    assert hints.canary_offset == -8 == DEFAULT_CANARY_OFFSET


def test_hints_canary_pattern_gs_0x14_32bit():
    insns = [
        FakeInsn("push", "ebp"),
        FakeInsn("mov", "ebp, esp"),
        FakeInsn("sub", "esp, 0x10"),
        FakeInsn("mov", "eax, dword ptr gs:0x14"),
        FakeInsn("mov", "dword ptr [ebp-0xc], eax"),
    ]
    hints = hints_from_instructions(insns, bits=32)
    assert hints.have_frame_pointer
    assert hints.canary_offset == -0xC


def test_hints_no_frame_pointer_when_omitted():
    insns = [
        FakeInsn("sub", "rsp, 0x18"),
        FakeInsn("lea", "rax, [rsp+0x8]"),
    ]
    hints = hints_from_instructions(insns, bits=64)
    assert not hints.have_frame_pointer
    assert hints.locals_bytes == 0x18


# ------------------------------------------------------------ DWARF variables
@pytest.mark.skipif(
    not Path(SAMPLES / "vuln_none.elf").exists(), reason="samples not built"
)
def test_dwarf_frame_variables_vuln_none():
    pytest.importorskip("elftools", reason="DWARF parsing needs pyelftools")
    variables = {v.name: v for v in dwarf_frame_variables(
        SAMPLES / "vuln_none.elf", VULN_NONE_MAIN
    )}
    assert set(variables) == {"argc", "argv", "buf"}
    buf = variables["buf"]
    assert buf.fbreg == -80  # CFA-relative: CFA-80 == rbp-0x40
    assert buf.size == 64  # char[64]
    assert not buf.is_param
    argc = variables["argc"]
    assert argc.fbreg == -84 and argc.size == 4 and argc.is_param
    argv = variables["argv"]
    assert argv.fbreg == -96 and argv.size == 8 and argv.is_param


@pytest.mark.skipif(
    not Path(SAMPLES / "vuln_none.elf").exists(), reason="samples not built"
)
def test_dwarf_frame_variables_other_function_is_empty():
    pytest.importorskip("elftools", reason="DWARF parsing needs pyelftools")
    # an address inside main only — a different symbol gets nothing
    assert dwarf_frame_variables(SAMPLES / "vuln_none.elf", 0x401000) == []


# --------------------------------------------------------- frame analysis core
def make_layout(dwarf_vars=(), *, rbp=0x7FFD0000_0100, canary_enabled=False,
                canary_value: int | None = None, hints_canary=False):
    """Snapshot of a typical vuln_none-style frame: locals 0x50 below rbp."""
    rsp = rbp - 0x70
    window_base = rsp
    data = bytearray(0x70)

    def put(addr: int, val: int) -> None:
        offset = addr - window_base
        data[offset : offset + 8] = val.to_bytes(8, "little")
    # saved rbp (a caller stack address) and return address (into .text)
    put(rbp, 0x7FFD0000_0210)
    put(rbp + 8, 0x401234)
    if canary_value is not None:
        put(rbp - 8, canary_value)
    hints_text = hints_from_instructions(
        [
            FakeInsn("push", "rbp"),
            FakeInsn("mov", "rbp, rsp"),
            FakeInsn("sub", "rsp, 0x50"),
            FakeInsn("lea", "rax, [rbp-0x40]"),
            *( [FakeInsn("mov", "rax, qword ptr fs:0x28"),
               FakeInsn("mov", "qword ptr [rbp-0x8], rax")] if hints_canary else [] ),
        ],
        bits=64,
    )
    return analyze_frame(
        arch="x86_64",
        frame_level=0,
        func_name="main",
        pc=0x4011D2,
        rbp=rbp,
        rsp=rsp,
        window_base=window_base,
        window_bytes=bytes(data),
        hints=hints_text,
        dwarf_vars=dwarf_vars,
        canary_enabled=canary_enabled,
        text_delta=0,
        symbols=[(0x401000, "main", 0x300)],
    )


def rows_by_kind(layout):
    return {row.kind: row for row in layout.rows}


def test_unsupported_arch_clear_error_not_crash():
    layout = analyze_frame(
        arch="arm64",
        frame_level=0,
        func_name="main",
        pc=0,
        rbp=0,
        rsp=0,
        window_base=0,
        window_bytes=b"",
        hints=None,
    )
    assert layout.error is not None
    assert layout.rows == ()
    assert "not supported" in " ".join(layout.notes).lower()


def test_analyze_frame_full_layout_vuln_none_style():
    pytest.importorskip("elftools", reason="DWARF parsing needs pyelftools")
    dwarf_vars = dwarf_frame_variables(SAMPLES / "vuln_none.elf", VULN_NONE_MAIN)
    layout = make_layout(dwarf_vars)
    assert layout.error is None and layout.has_frame_pointer()
    assert layout.source == "dwarf"

    rows = rows_by_kind(layout)
    rbp = 0x7FFD0000_0100
    # return address sits at rbp+word, saved frame pointer at rbp
    assert rows["ret_addr"].address == rbp + 8
    assert rows["ret_addr"].value == 0x401234
    assert rows["saved_rbp"].address == rbp
    assert rows["saved_rbp"].marker == "rbp"
    assert rows["ret_addr"].annotation == "main+0x234"
    # buf: DWARF fbreg -80 → CFA-80 == rbp-0x40, 64 bytes wide
    assert rows["buffer"].address == rbp - 0x40
    assert rows["buffer"].size == 64
    assert rows["buffer"].label.startswith("buffer buf")

    # rsp marker chip on the lowest row
    lowest = layout.rows[-1]
    assert lowest.address == layout.rsp and lowest.marker == "rsp"


def test_buffer_to_return_address_distance():
    pytest.importorskip("elftools", reason="DWARF parsing needs pyelftools")
    dwarf_vars = dwarf_frame_variables(SAMPLES / "vuln_none.elf", VULN_NONE_MAIN)
    layout = make_layout(dwarf_vars)
    listed = frame_distances(layout)
    assert any("buffer -> saved RBP" in name for name, _ in listed)
    assert any("buffer -> return address" in name for name, _ in listed)
    # buf at rbp-0x40; saved RBP at rbp → 64 bytes; return address at rbp+8 → 72
    saved = next(dist for name, dist in listed if "saved RBP" in name)
    ra = next(dist for name, dist in listed if "return address" in name)
    assert saved == 64 == 0x40
    assert ra == 72 == 0x48


def test_rows_are_disjoint_and_cover_rsp_to_top():
    pytest.importorskip("elftools", reason="DWARF parsing needs pyelftools")
    dwarf_vars = dwarf_frame_variables(SAMPLES / "vuln_none.elf", VULN_NONE_MAIN)
    layout = make_layout(dwarf_vars)
    spans = sorted((row.address, row.address + row.size) for row in layout.rows)
    cursor = layout.rsp
    for start, end in spans:
        assert start == cursor, f"gap/overlap at {start:#x} (expected {cursor:#x})"
        cursor = end
    assert cursor == layout.rbp + 16  # the CFA: saved arg area is empty here


def test_offsets_from_rbp_and_rsp():
    pytest.importorskip("elftools", reason="DWARF parsing needs pyelftools")
    dwarf_vars = dwarf_frame_variables(SAMPLES / "vuln_none.elf", VULN_NONE_MAIN)
    layout = make_layout(dwarf_vars)
    rows = rows_by_kind(layout)
    assert rows["saved_rbp"].offset_rbp == 0
    assert rows["saved_rbp"].offset_rsp == 0x70
    assert rows["ret_addr"].offset_rbp == 8
    assert rows["ret_addr"].offset_rsp == 0x78
    assert rows["buffer"].offset_rbp == -0x40
    assert rows["buffer"].offset_rsp == 0x30


def test_inference_fallback_without_dwarf():
    layout = make_layout()  # dwarf_vars=() → disassembly-only
    assert layout.error is None
    assert layout.source == "disassembly"
    rows = rows_by_kind(layout)
    rbp = 0x7FFD0000_0100
    assert rows["ret_addr"].address == rbp + 8
    assert rows["saved_rbp"].address == rbp
    # local inferred from `lea rax, [rbp-0x40]`, spanning up to the canary slot
    assert any(
        row.address == rbp - 0x40 and row.kind == "local" for row in layout.rows
    )


def test_canary_found_from_disassembly_pattern():
    canary = 0x9C5A3F2D11BB00  # typical glibc canary shape: ends in 0x00
    layout = make_layout(hints_canary=True, canary_value=canary)
    rows = rows_by_kind(layout)
    assert rows["canary"].address == 0x7FFD0000_0100 - 8  # rbp-8
    assert rows["canary"].value == canary
    assert rows["canary"].offset_rbp == -8


def test_canary_fallback_from_checksec_and_value_shape():
    canary = 0xAABBCCDD11223300  # LSB zero → canary-like
    layout = make_layout(canary_enabled=True, canary_value=canary)
    rows = rows_by_kind(layout)
    # no disassembly canary pattern → checksec + shaped fallback at rbp-8
    assert rows["canary"].address == 0x7FFD0000_0100 - 8
    assert rows["canary"].offset_rbp == -8


def test_canary_not_misplaced_when_shape_absent():
    layout = make_layout(canary_enabled=True, canary_value=0xDEADBEEF12345678)
    assert "canary" not in rows_by_kind(layout)
    assert any("canary" in note for note in layout.notes)


def test_no_frame_pointer_window_layout():
    layout = analyze_frame(
        arch="x86_64",
        frame_level=0,
        func_name="f",
        pc=0x401000,
        rbp=None,
        rsp=0x2000,
        window_base=0x1F80,
        window_bytes=bytes(0x90),
        hints=None,
    )
    assert layout.error is None
    assert layout.source == "window"
    assert layout.rbp is None
    assert layout.rows  # word dump around SP
    assert all(row.size == 8 for row in layout.rows)
    assert all(row.offset_rsp >= 0 for row in layout.rows)
    assert any("-fno-omit-frame-pointer" in note for note in layout.notes)


def test_no_frame_pointer_when_hints_lack_prologue():
    # rbp passed but prologue has no push rbp/mov rbp,rsp → do not trust rbp
    layout = make_layout_with_hints()
    # helper below ensures the same behavior
    assert layout.source in ("window",)


def make_layout_with_hints():
    hints = hints_from_instructions([FakeInsn("sub", "rsp, 0x20")], 64)
    return analyze_frame(
        arch="x86_64",
        frame_level=0,
        func_name="f",
        pc=0,
        rbp=0x1000,  # rbp <= rsp → window mode
        rsp=0x2000,
        window_base=0x1F80,
        window_bytes=bytes(0x90),
        hints=hints,
    )


def test_frame_distances_empty_without_frame_pointer():
    layout = analyze_frame(
        arch="x86_64",
        frame_level=0,
        func_name="f",
        pc=0,
        rbp=None,
        rsp=0x2000,
        window_base=0x1F80,
        window_bytes=bytes(0x90),
        hints=None,
    )
    assert frame_distances(layout) == []


def test_frame_distances_include_canary():
    layout = make_layout(hints_canary=True, canary_value=0x1122334455667700)
    listed = [name for name, _ in frame_distances(layout)]
    assert any("canary" in name for name in listed)
    canary_dist = next(
        dist for name, dist in frame_distances(layout) if "canary" in name
    )
    # buf at rbp-0x40, canary at rbp-0x8 → 0x38 = 56 bytes
    assert canary_dist == 56 == 0x38


# ------------------------------------------------------------------- 32-bit
def test_32bit_layout_word_size_four():
    rbp, rsp = 0x1000, 0x1000 - 0x20
    data = bytearray(0x20)
    data[rbp - rsp : rbp - rsp + 4] = (0x2000).to_bytes(4, "little")
    data[rbp + 4 - rsp : rbp + 8 - rsp] = (0x08048123).to_bytes(4, "little")
    hints = hints_from_instructions(
        [
            FakeInsn("push", "ebp"),
            FakeInsn("mov", "ebp, esp"),
            FakeInsn("sub", "esp, 0x10"),
            FakeInsn("lea", "eax, [ebp-0x10]"),
        ],
        bits=32,
    )
    layout = analyze_frame(
        arch="x86",
        frame_level=0,
        func_name="main",
        pc=0x08048000,
        rbp=rbp,
        rsp=rsp,
        window_base=rsp,
        window_bytes=bytes(data),
        hints=hints,
        symbols=[(0x08048000, "main", 0x400)],
    )
    assert layout.word == 4
    rows = rows_by_kind(layout)
    assert rows["saved_rbp"].address == rbp and rows["saved_rbp"].size == 4
    assert rows["ret_addr"].address == rbp + 4
    assert rows["ret_addr"].annotation == "main+0x123"
    # local spans [ebp-0x10, ebp) down to the saved rbp slot
    local = max(
        (row for row in layout.rows if row.kind == "local"),
        key=lambda row: row.size,
        default=None,
    )
    assert local is not None and local.address == rbp - 0x10


def test_row_at_and_buffer_start_helpers():
    layout = make_layout()
    row = layout.row_at(layout.rbp + 8)
    assert row is not None and row.kind == "ret_addr"
    assert layout.row_at(0x1) is None
    start = layout.buffer_start()
    # no dwarf/no buffer → falls back to the widest local/param row
    assert start is not None
    buf = layout.row_at(start)
    assert buf is not None


def test_kind_labels_present():
    for kind in ("ret_addr", "saved_rbp", "canary", "gap", "window"):
        assert kind in KIND_LABEL
