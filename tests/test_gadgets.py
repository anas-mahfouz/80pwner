# 80PWNER — by Anas Mahfouz (The 80)

"""Unit tests for the ROP/JOP gadget-finder engine.

Real binaries (the repo's vulnerable samples, plus /bin/ls as a perf smoke)
for properties; fabricated blob models for byte-exact determinism.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import pytest

from eightypwner.engines.binary_parser import BinaryModel, Section, Segment
from eightypwner.engines.gadgets import (
    MAX_GADGET_BYTES,
    Gadget,
    GadgetQuery,
    ScanResult,
    UnsupportedArchError,
    apply_query,
    exec_ranges,
    find_gadgets,
)

SAMPLES = Path(__file__).parent / "samples"
NONE = SAMPLES / "vuln_none.elf"
DEFAULTS = SAMPLES / "vuln_defaults.elf"
LS = Path("/bin/ls")


def fake_model(tmp_path: Path, data: bytes, base: int = 0x1000, bits: int = 64, arch: str = "x86_64") -> BinaryModel:
    """Minimal model: one exec LOAD mapped at *base*, bytes read from disk.

    ``build_mappings`` ignores zero file offsets, so the file gets one pad
    byte and the mapping starts at file_offset 1.
    """
    blob_path = tmp_path / "blob.elf"
    blob_path.write_bytes(b"\x90" + data)
    return BinaryModel(
        path=blob_path,
        fmt="ELF",
        arch=arch,
        bits=bits,
        endianness="little",
        entry_point=base,
        sections=[Section(name=".text", size=len(data), vaddr=base, type="PROGBITS")],
        segments=[
            Segment(type_name="LOAD", vaddr=base, size=len(data), flags="r-x", file_offset=1)
        ],
    )


def tokens(g: Gadget) -> set[str]:
    """Word tokens of the disassembly text (matches the engine's matching)."""
    return {t.lower() for t in re.findall(r"\w+", g.insns)}


# ------------------------------------------------------------------ ranges
def test_exec_ranges_cover_text_segment() -> None:
    import elftools  # noqa: F401

    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(NONE)
    ranges, note = exec_ranges(model)
    assert note == ""
    # .text lives at 0x4010b0; rw-/r-- segments must not appear
    covered = [(lo, lo + size) for lo, size in ranges]
    assert any(lo <= 0x4011BF < hi for lo, hi in covered)  # main
    assert all(hi <= 0x403170 for _, hi in []) or True  # rw- LOAD never scanned
    # no range overlaps the rw- segment starting at 0x403170
    for _lo, hi in covered:
        assert hi <= 0x403170  # rw- LOAD never scanned
    # ranges are within the single exec LOAD 0x401000..0x40122d
    assert all(lo >= 0x401000 for lo, _ in covered)


def test_exec_ranges_falls_back_to_segments_without_sections() -> None:
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(NONE)
    stripped = BinaryModel(
        path=model.path, fmt=model.fmt, arch=model.arch, bits=model.bits,
        endianness=model.endianness, entry_point=model.entry_point,
        sections=[], segments=model.segments,
    )
    ranges, note = exec_ranges(stripped)
    assert note == ""
    assert (0x401000, 557) in [(lo, size) for lo, size in ranges]


def test_exec_ranges_cap_truncates_with_note() -> None:
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(NONE)
    ranges, note = exec_ranges(model, max_bytes=100)
    assert note != "" and "partial" in note
    assert sum(size for _, size in ranges) <= 100


# ------------------------------------------------------------------ find_gadgets
def test_find_gadgets_properties_on_sample() -> None:
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(NONE)
    result = find_gadgets(model)
    assert isinstance(result, ScanResult)
    assert result.note == "" and result.scanned_bytes > 0
    assert result.gadgets, "a compiled binary always has rets"
    endings = {"ret", "jmp", "call", "syscall", "int80"}

    def tail(insns: str) -> str:
        return insns.rsplit(" ; ", 1)[-1]  # last instruction text

    for g in result.gadgets:
        assert g.ending in endings
        assert 1 <= g.size <= MAX_GADGET_BYTES
        assert len(bytes.fromhex(g.bytes_hex)) == g.size
        assert g.insns  # rendered text is never empty
        # the final instruction is the terminator kind that classified it
        if g.ending == "ret":
            assert tail(g.insns).startswith("ret")
        elif g.ending == "jmp":
            assert tail(g.insns).startswith("jmp ")
        elif g.ending == "call":
            assert tail(g.insns).startswith("call ")


def test_synthetic_exact_gadgets(tmp_path: Path) -> None:
    # pop rdi ; ret | syscall | int 0x80 | jmp rax | call rbx | ret imm16
    data = bytes.fromhex("5fc3") + bytes.fromhex("0f05") + bytes.fromhex("cd80")
    data += bytes.fromhex("ffe0") + bytes.fromhex("ffd3") + bytes.fromhex("c204eb")
    model = fake_model(tmp_path, data)
    result = find_gadgets(model)
    found = {(g.ending, g.insns) for g in result.gadgets}
    assert ("ret", "pop rdi ; ret") in found
    assert ("syscall", "syscall") in found
    assert ("int80", "int 0x80") in found
    assert ("jmp", "jmp rax") in found
    assert ("call", "call rbx") in found
    assert ("ret", "ret 0xeb04") in found
    # addresses line up with the base
    exact = [g for g in result.gadgets if g.address == model.entry_point and g.size == 2]
    assert any(g.insns == "pop rdi ; ret" for g in exact)


def test_mid_instruction_chains_are_rejected(tmp_path: Path) -> None:
    # '48 31 ff' = xor rdi, rdi (3 bytes); the 'ff' inside it must not be
    # walked back through as a jmp/call terminator start unless the whole
    # prior byte-run decodes cleanly into instructions
    data = bytes.fromhex("90") * 3 + bytes.fromhex("4831ff") + bytes.fromhex("c3")
    model = fake_model(tmp_path, data)
    result = find_gadgets(model)
    for g in result.gadgets:
        assert g.insns != ""  # nothing crashed; chains decode whole only
    kinds = {g.insns for g in result.gadgets if g.ending in ("jmp", "call")}
    assert kinds == set(), f"mid-instruction terminators leaked: {kinds}"


def test_unsupported_arch_is_a_clean_error(tmp_path: Path) -> None:
    model = fake_model(tmp_path, b"\xc3", arch="arm")
    with pytest.raises(UnsupportedArchError) as exc:
        find_gadgets(model)
    assert "arm" in str(exc.value) and "x86" in str(exc.value)


def test_cancellation_returns_partial_results() -> None:
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(NONE)
    calls = [0]

    def cancel() -> bool:
        calls[0] += 1
        return calls[0] > 1  # stop almost immediately

    result = find_gadgets(model, should_cancel=cancel)
    assert "cancel" in result.note.lower()
    # some gadgets may have already been collected — never a crash
    assert isinstance(result.gadgets, list)


def test_progress_cb_reaches_one() -> None:
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(NONE)
    seen: list[float] = []
    find_gadgets(model, progress_cb=seen.append)
    assert seen and seen[-1] == 1.0
    assert all(0.0 <= v <= 1.0 for v in seen)


def test_repeated_scans_are_deterministic() -> None:
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(NONE)
    a = find_gadgets(model).gadgets
    b = find_gadgets(model).gadgets
    assert a == b


# ------------------------------------------------------------------ filters
@pytest.fixture(scope="module")
def sample_gadgets() -> list[Gadget]:
    from eightypwner.engines.binary_parser import parse_binary

    return find_gadgets(parse_binary(NONE)).gadgets


def test_apply_query_kinds_filter(sample_gadgets: list[Gadget]) -> None:
    only_jmp = apply_query(sample_gadgets, GadgetQuery(kinds=("jmp",)))
    assert only_jmp and all(g.ending == "jmp" for g in only_jmp)
    both = apply_query(sample_gadgets, GadgetQuery(kinds=("ret", "call")))
    assert {g.ending for g in both} <= {"ret", "call"}


def test_apply_query_register_filter_narrows(sample_gadgets: list[Gadget]) -> None:
    unfiltered = len(sample_gadgets)
    narrowed = apply_query(sample_gadgets, GadgetQuery(regs=("rdi",)))
    assert 0 < len(narrowed) < unfiltered
    for g in narrowed:
        assert "rdi" in tokens(g)


def test_apply_query_regex_filter(sample_gadgets: list[Gadget]) -> None:
    hits = apply_query(sample_gadgets, GadgetQuery(regex=r"\blea\b"))
    assert hits and all("lea" in g.insns.lower() for g in hits)
    assert all(g in sample_gadgets for g in hits)


def test_apply_query_max_bytes(sample_gadgets: list[Gadget]) -> None:
    small = apply_query(sample_gadgets, GadgetQuery(max_bytes=3))
    assert all(g.size <= 3 for g in small)
    assert any(g.size > 3 for g in sample_gadgets)


def test_apply_query_bad_bytes_excludes_bytes_and_addresses(
    sample_gadgets: list[Gadget],
) -> None:
    bad = b"\x00\x0a\x0d"
    kept = apply_query(sample_gadgets, GadgetQuery(bad_bytes=bad))
    for g in kept:
        raw = bytes.fromhex(g.bytes_hex)
        assert not (set(raw) & set(bad))
        addr_enc = g.address.to_bytes(8, "little") + g.address.to_bytes(4, "little")
        assert not (set(addr_enc) & set(bad))
    # an address containing a bad byte is dropped even with clean gadget bytes
    loser = Gadget(address=0x4010B0, size=1, bytes_hex="c3", insns="ret", ending="ret")
    out = apply_query([loser], GadgetQuery(bad_bytes=b"\xb0"))
    assert out == []


def test_apply_query_combined(sample_gadgets: list[Gadget]) -> None:
    q = GadgetQuery(kinds=("ret",), regs=("rdi",), max_bytes=16)
    got = apply_query(sample_gadgets, q)
    for g in got:
        assert g.ending == "ret" and g.size <= 16
        assert "rdi" in tokens(g)


# ------------------------------------------------------------------ perf smoke
def test_perf_smoke_bin_ls() -> None:
    if sys.platform != "linux" or not LS.is_file():
        pytest.skip("Linux ELF binary required for gadget-scan smoke test")
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(LS)
    t0 = time.monotonic()
    result = find_gadgets(model)
    elapsed = time.monotonic() - t0
    assert elapsed < 30.0, f"scan took {elapsed:.1f}s — too slow"
    assert len(result.gadgets) > 500
    rdi_rets = apply_query(result.gadgets, GadgetQuery(regs=("rdi",), kinds=("ret",)))
    assert rdi_rets  # real binaries expose pop rdi ; ret chains


def test_perf_smoke_cancellation_speed() -> None:
    if sys.platform != "linux" or not LS.is_file():
        pytest.skip("Linux ELF binary required for gadget-scan smoke test")
    from eightypwner.engines.binary_parser import parse_binary

    model = parse_binary(LS)
    t0 = time.monotonic()
    result = find_gadgets(model, should_cancel=lambda: time.monotonic() - t0 > 0.25)
    elapsed = time.monotonic() - t0
    assert elapsed < 3.0
    assert "cancel" in result.note.lower() or result.gadgets
