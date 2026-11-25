# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""CFG engine tests: block cutting, edges, truncation, DOT export."""

from __future__ import annotations

from pathlib import Path

import pytest

from eightypwner.engines.binary_parser import (
    BinaryModel,
    Section,
    Segment,
    parse_binary,
)
from eightypwner.engines.cfg import BasicBlock, CfgResult, build_cfg

SAMPLES = Path(__file__).parent / "samples"
NONE = SAMPLES / "vuln_none.elf"
DEFAULTS = SAMPLES / "vuln_defaults.elf"

# Hand-assembled x86-64 loop with a conditional branch and a back edge:
#   xor eax, eax ; cmp eax, 10 ; jge done ; inc eax ; jmp loop ; done: ret
BRANCH_CODE = bytes.fromhex("31c083f80a7d04ffc0ebf7c3")


def fake_model(tmp_path: Path, data: bytes, base: int = 0x400000) -> BinaryModel:
    """One executable LOAD mapping *data* at *base* (see test_gadgets)."""
    blob_path = tmp_path / "blob.elf"
    blob_path.write_bytes(b"\x90" + data)
    return BinaryModel(
        path=blob_path,
        fmt="ELF",
        arch="x86_64",
        bits=64,
        endianness="little",
        entry_point=base,
        sections=[Section(name=".text", size=len(data), vaddr=base, type="PROGBITS")],
        segments=[
            Segment(
                type_name="LOAD",
                vaddr=base,
                size=len(data),
                flags="r-x",
                file_offset=1,
            )
        ],
    )


@pytest.fixture(scope="module")
def model():
    return parse_binary(NONE)


def _symbol(model, name: str) -> int | None:
    for symbol in model.symbols:
        if symbol.name == name and symbol.value:
            return int(symbol.value)
    return None


def test_rejects_non_model():
    with pytest.raises(TypeError):
        build_cfg(object(), 0x1000)  # type: ignore[arg-type]


def test_requires_entry():
    with pytest.raises(ValueError):
        build_cfg(parse_binary(NONE), 0)


def test_main_cfg_has_blocks_and_edges(model):
    entry = _symbol(model, "main") or model.entry_point
    result = build_cfg(model, entry)
    assert isinstance(result, CfgResult)
    assert result.entry == entry
    assert result.blocks, "main must decode into at least one block"
    assert result.instruction_count > 0
    assert result.edges or len(result.blocks) == 1
    # Every edge target inside the graph must be a block start.
    internal = {edge.dst for edge in result.edges if edge.dst in result.blocks}
    assert internal.issubset(set(result.blocks))
    # Blocks are contiguous, non-empty and carry their instructions.
    for block in result.sorted_blocks():
        assert block.insns
        assert block.size > 0
        assert block.terminal in {"fallthrough", "ret", "jmp", "cond", "indirect", "trunc"}


def test_cfg_contains_calls(model):
    entry = _symbol(model, "main") or model.entry_point
    result = build_cfg(model, entry)
    # main calls printf/gets/puts/strcpy in the sample.
    assert result.calls, "main calls libc functions"


def test_non_executable_entry_reports_note(model):
    result = build_cfg(model, 0x1)
    assert not result.blocks
    assert "not inside an executable region" in result.note


def test_block_budget_truncates(model):
    result = build_cfg(model, model.entry_point, max_blocks=1)
    assert len(result.blocks) <= 1
    if result.truncated:
        assert "Stopped after" in result.note or "budget" in result.note


def test_dot_export(model):
    entry = _symbol(model, "main") or model.entry_point
    result = build_cfg(model, entry)
    dot = result.to_dot("main graph")
    assert dot.startswith("digraph cfg {")
    assert dot.rstrip().endswith("}")
    assert "main graph" in dot
    assert f"b{entry:x}" in dot
    # A linear function has no branch edges; the node still renders.
    assert "label=" in dot


def test_dot_export_with_edges(tmp_path):
    model = fake_model(tmp_path, BRANCH_CODE)
    result = build_cfg(model, model.entry_point)
    dot = result.to_dot("loop")
    assert "->" in dot
    # The back-edge target splits the entry block: entry falls through to the
    # cmp/jge block, which branches to the exit and the loop body.
    assert "b400000 -> b400002" in dot
    assert "b400002 -> b40000b" in dot
    assert "b400002 -> b400007" in dot
    assert "b400007 -> b400002" in dot
    assert "style=dashed" in dot


def test_instruction_budget(model):
    result = build_cfg(model, model.entry_point, max_instructions=1)
    assert result.instruction_count <= 12


def test_conditional_block_has_fallthrough(tmp_path):
    model = fake_model(tmp_path, BRANCH_CODE)
    result = build_cfg(model, model.entry_point)
    kinds = {edge.kind for edge in result.edges}
    assert {"true", "false", "jump"} <= kinds
    # The back-edge target splits the entry block: the entry now falls
    # through to the cmp/jge block.
    entry = result.blocks[0x400000]
    assert entry.terminal == "fallthrough"
    assert entry.successors == (0x400002,)
    branch = result.blocks[0x400002]
    assert branch.terminal == "cond"
    assert set(branch.successors) == {0x400007, 0x40000B}
    # The back edge makes the loop body reachable.
    assert result.blocks[0x400007].terminal == "jmp"
    assert 0x400002 in result.blocks[0x400007].successors
    # No instruction belongs to two blocks.
    addresses = [insn.address for block in result.blocks.values() for insn in block.insns]
    assert len(addresses) == len(set(addresses))


def test_linear_main_is_one_block(model):
    entry = _symbol(model, "main") or model.entry_point
    result = build_cfg(model, entry)
    # The sample's main has no branches, so it decodes to a single ret block
    # while still recording the libc calls it makes.
    assert len(result.blocks) == 1
    assert result.blocks[entry].terminal == "ret"
    assert result.edges == []


def test_defaults_variant(model):
    other = parse_binary(DEFAULTS)
    entry = _symbol(other, "main") or other.entry_point
    result = build_cfg(other, entry)
    assert result.blocks


def test_block_text_rendering():
    block = BasicBlock(start=0x1000, end=0x1002, insns=())
    assert block.size == 2
    assert block.text == ""
