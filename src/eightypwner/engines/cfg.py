# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Control-flow graph construction (Step 7 A).

Builds a *function-scoped* CFG from the existing Capstone engine: decode
linearly from an entry address, cut basic blocks at every control-flow
boundary, and follow intra-binary branch targets. This is exactly what a pwn
workflow needs — you pick a function, see which paths reach the dangerous call
or the stack pivot, and copy the graph as DOT for notes.

Deliberate limits: the walk stays inside executable spans, never follows
calls, and stops at ``MAX_BLOCKS`` / ``MAX_INSTRUCTIONS`` (the UI shows the
truncation note instead of freezing). Pure engine: no Qt.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

from eightypwner.engines.disassembler import Disassembler, Instruction
from eightypwner.engines.gadgets import exec_ranges

MAX_BLOCKS = 512
MAX_INSTRUCTIONS = 12_000
MAX_BLOCK_INSNS = 512

# Instructions that end a block and produce no successor.
_TERMINAL = frozenset({"ret", "retf", "hlt", "ud2", "iret", "iretd", "iretq", "int3"})
# Unconditional jumps (arch-specific spellings).
_JMP = frozenset({"jmp", "b", "bx", "br"})
# Calls that never return to the next instruction in practice (still recorded
# as calls; the block ends at the call so the graph stays readable).
_NO_RETURN_HINT = frozenset({"call", "bl", "blx"})


@dataclass(frozen=True)
class BasicBlock:
    """One basic block: contiguous instructions, one entry, guarded exits."""

    start: int
    end: int
    insns: tuple[Instruction, ...]
    successors: tuple[int, ...] = ()
    terminal: str = "fallthrough"  # fallthrough | ret | jmp | cond | indirect | trunc
    external_target: int | None = None  # jump outside the executable spans

    @property
    def size(self) -> int:
        return max(self.end - self.start, 0)

    @property
    def text(self) -> str:
        return "\n".join(f"{ins.address:#x}: {ins.text()}" for ins in self.insns)


@dataclass(frozen=True)
class CfgEdge:
    src: int
    dst: int
    kind: str  # fallthrough | jump | true | false | call | external


@dataclass
class CfgResult:
    entry: int = 0
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    edges: list[CfgEdge] = field(default_factory=list)
    calls: list[CfgEdge] = field(default_factory=list)
    note: str = ""
    truncated: bool = False
    instruction_count: int = 0

    def sorted_blocks(self) -> list[BasicBlock]:
        return [self.blocks[start] for start in sorted(self.blocks)]

    def to_dot(self, title: str = "") -> str:
        """Graphviz rendering — paste into notes or a report figure."""
        label = _dot_escape(title or f"CFG @ {self.entry:#x}")
        lines = [
            "digraph cfg {",
            f'  label="{label}";',
            '  labelloc="t";',
            '  node [shape=box, style="rounded,filled", fillcolor="#161B20", '
            'color="#2A333A", fontcolor="#E8F0EC", fontname="monospace", fontsize=10];',
            '  edge [color="#9AA8A2", fontname="monospace", fontsize=9];',
        ]
        for block in self.sorted_blocks():
            rows = [f"{block.start:#x}"]
            for insn in block.insns[:8]:
                rows.append(_dot_escape(insn.text())[:64])
            if len(block.insns) > 8:
                rows.append(f"… {len(block.insns) - 8} more")
            text = "\\l".join(rows) + "\\l"
            color = _DOT_FILL.get(block.terminal, "#161B20")
            lines.append(
                f'  b{block.start:x} [label="{text}", fillcolor="{color}"];'
            )
        for edge in self.edges:
            if edge.src not in self.blocks:
                continue
            if edge.dst in self.blocks:
                style = "dashed" if edge.kind == "fallthrough" else "solid"
                label = "" if edge.kind == "fallthrough" else edge.kind
                color = _DOT_EDGE.get(edge.kind, "#9AA8A2")
                lines.append(
                    f'  b{edge.src:x} -> b{edge.dst:x} '
                    f'[style={style}, label="{label}", color="{color}"];'
                )
            else:
                lines.append(
                    f'  b{edge.src:x} -> ext{edge.dst:x} '
                    f'[style=dotted, label="{edge.kind}", color="#FFB454"];'
                )
                lines.append(
                    f'  ext{edge.dst:x} [shape=plaintext, label="ext {edge.dst:#x}", '
                    'fontcolor="#FFB454"];'
                )
        lines.append("}")
        return "\n".join(lines)


_DOT_FILL = {
    "ret": "#33230C",
    "jmp": "#1C2429",
    "cond": "#1C2429",
    "indirect": "#33230C",
    "trunc": "#2A333A",
}
_DOT_EDGE = {
    "true": "#34D399",
    "false": "#9E1B26",
    "jump": "#9AA8A2",
    "fallthrough": "#9AA8A2",
    "call": "#FFB454",
}


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\l")


class _Spans:
    """Fast 'is this address executable?' test over merged spans."""

    def __init__(self, spans: list[tuple[int, int]]) -> None:
        self._spans = sorted(spans)
        self._starts = [start for start, _size in self._spans]

    def contains(self, address: int) -> bool:
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return False
        start, size = self._spans[index]
        return start <= address < start + size


def _is_conditional(mnemonic: str, arch: str) -> bool:
    arch = arch.lower()
    if arch.startswith("x86"):
        return mnemonic.startswith("j") and mnemonic != "jmp"
    if arch in ("arm", "aarch64"):
        return (
            mnemonic.startswith("b.")
            or mnemonic in ("cbz", "cbnz", "tbz", "tbnz")
        )
    if arch.startswith("riscv"):
        return mnemonic.startswith("b") and mnemonic not in ("b",)
    if arch.startswith("ppc"):
        return mnemonic.startswith("b") and mnemonic not in ("b", "bl", "blr", "bctr")
    return False


def _immediate(operands: str) -> int | None:
    match = re.match(r"\s*0x[0-9a-fA-F]+", operands)
    if not match:
        return None
    try:
        return int(match.group(0), 16)
    except ValueError:  # pragma: no cover — regex guarantees hex
        return None


def _decode_one(disasm: Disassembler, address: int) -> Instruction | None:
    return next(iter(disasm.decode(address, 16, decode_all=False)), None)


def _decode_block(
    disasm: Disassembler,
    start: int,
    spans: _Spans,
    budget: int,
) -> tuple[BasicBlock | None, list[tuple[int, str]], list[tuple[int, str]]]:
    """Decode one block. Returns (block, internal successors, call targets)."""
    insns: list[Instruction] = []
    successors: list[tuple[int, str]] = []
    calls: list[tuple[int, str]] = []
    cursor = start
    terminal = "fallthrough"
    external: int | None = None

    for _ in range(min(MAX_BLOCK_INSNS, budget)):
        if not spans.contains(cursor):
            terminal = "trunc" if not insns else terminal
            break
        insn = _decode_one(disasm, cursor)
        if insn is None or insn.size <= 0:
            terminal = "trunc" if not insns else terminal
            break
        insns.append(insn)
        cursor = insn.address + insn.size
        mnemonic = insn.mnemonic.lower()
        base = mnemonic.split(".")[0]

        if base in _TERMINAL:
            terminal = "ret"
            break
        if base in _JMP:
            target = _immediate(insn.operands)
            if target is None:
                terminal = "indirect"
                break
            terminal = "jmp"
            if spans.contains(target):
                successors.append((target, "jump"))
            else:
                external = target
            break
        if _is_conditional(mnemonic, disasm.arch_name):
            target = _immediate(insn.operands)
            terminal = "cond"
            if target is not None:
                if spans.contains(target):
                    successors.append((target, "true"))
                else:
                    external = target
            # conditional falls through unless it is an unconditional-style
            # ARM branch spelling (b.<cond> still falls through)
            if spans.contains(cursor):
                successors.append((cursor, "false"))
            break
        if base in _NO_RETURN_HINT and base == "call":
            target = _immediate(insn.operands)
            if target is not None:
                calls.append((target, "call"))

    else:
        terminal = "trunc"

    if not insns:
        return None, [], []
    block = BasicBlock(
        start=insns[0].address,
        end=insns[-1].address + insns[-1].size,
        insns=tuple(insns),
        successors=tuple(dict.fromkeys(target for target, _k in successors)),
        terminal=terminal,
        external_target=external,
    )
    return block, successors, calls


def _split_overlaps(blocks: dict[int, BasicBlock]) -> None:
    """Split blocks that contain another block's start (branch targets).

    A target discovered after a containing block was decoded lands in the
    middle of it; the containing block must be cut at that instruction so the
    graph is a partition, not overlapping ranges. When the later start is not
    an instruction boundary, the first decode wins and the later block is
    dropped (misaligned control flow).
    """
    changed = True
    while changed:
        changed = False
        for start in sorted(blocks):
            block = blocks[start]
            inner = sorted(other for other in blocks if block.start < other < block.end)
            if not inner:
                continue
            cut = inner[0]
            prefix = [insn for insn in block.insns if insn.address < cut]
            suffix = [insn for insn in block.insns if insn.address >= cut]
            if not prefix or not suffix or suffix[0].address != cut:
                del blocks[cut]
                changed = True
                break
            blocks[start] = BasicBlock(
                start=block.start,
                end=cut,
                insns=tuple(prefix),
                successors=(cut,),
                terminal="fallthrough",
            )
            if cut not in blocks:
                blocks[cut] = BasicBlock(
                    start=cut,
                    end=block.end,
                    insns=tuple(suffix),
                    successors=block.successors,
                    terminal=block.terminal,
                    external_target=block.external_target,
                )
            changed = True
            break


def _edge_kinds(block: BasicBlock) -> list[str]:
    if block.terminal == "cond":
        # Branch target is recorded before the fallthrough successor; an
        # out-of-range target leaves only the fallthrough edge.
        return ["true", "false"] if len(block.successors) >= 2 else ["false"]
    if block.terminal == "jmp":
        return ["jump"]
    if block.terminal in ("fallthrough", "trunc"):
        return ["fallthrough"]
    return []


def _rebuild_edges(
    blocks: dict[int, BasicBlock],
) -> tuple[list[CfgEdge], list[CfgEdge]]:
    """Derive edges and call sites from the final (non-overlapping) blocks."""
    edges: list[CfgEdge] = []
    calls: list[CfgEdge] = []
    edge_keys: set[tuple[int, int, str]] = set()
    call_keys: set[tuple[int, int, str]] = set()
    for block in sorted(blocks.values(), key=lambda item: item.start):
        kinds = _edge_kinds(block)
        for index, target in enumerate(block.successors):
            kind = kinds[index] if index < len(kinds) else "fallthrough"
            key = (block.start, target, kind)
            if key not in edge_keys:
                edge_keys.add(key)
                edges.append(CfgEdge(block.start, target, kind))
        if block.external_target is not None:
            key = (block.start, block.external_target, "external")
            if key not in edge_keys:
                edge_keys.add(key)
                edges.append(CfgEdge(block.start, block.external_target, "external"))
        for insn in block.insns:
            base = insn.mnemonic.lower().split(".")[0]
            if base not in _NO_RETURN_HINT:
                continue
            target = _immediate(insn.operands)
            if target is None:
                continue
            key = (block.start, target, "call")
            if key not in call_keys:
                call_keys.add(key)
                calls.append(CfgEdge(block.start, target, "call"))
    return edges, calls


def build_cfg(
    model: object,
    entry: int,
    disasm: Disassembler | None = None,
    max_blocks: int = MAX_BLOCKS,
    max_instructions: int = MAX_INSTRUCTIONS,
) -> CfgResult:
    """Build the CFG reachable from *entry* inside *model*.

    The engine reuses a caller-provided :class:`Disassembler` (the app already
    owns one per binary), otherwise creates one. Raises ``RuntimeError`` when
    the architecture is unsupported or Capstone is missing — callers show the
    message verbatim.
    """
    from eightypwner.engines.binary_parser import BinaryModel

    if not isinstance(model, BinaryModel):
        raise TypeError("build_cfg expects a BinaryModel")
    if not entry:
        raise ValueError("CFG needs a non-zero entry address")
    engine = disasm or Disassembler(model)
    spans_list, range_note = exec_ranges(model)
    spans = _Spans(spans_list)
    result = CfgResult(entry=entry, note=range_note)

    if not spans.contains(entry):
        result.note = f"{entry:#x} is not inside an executable region."
        return result

    worklist: list[int] = [entry]
    seen_starts: set[int] = set()

    while worklist and len(result.blocks) < max_blocks:
        start = worklist.pop(0)
        if start in seen_starts:
            continue
        seen_starts.add(start)
        if not spans.contains(start):
            continue
        remaining = max_instructions - result.instruction_count
        if remaining <= 0:
            result.truncated = True
            result.note = (result.note + " Instruction budget reached.").strip()
            break
        block, successors, _calls = _decode_block(engine, start, spans, remaining)
        if block is None:
            continue
        # A later decode may have started mid-instruction; the first block
        # wins, and the duplicate start is simply ignored.
        if block.start in result.blocks:
            continue
        result.blocks[block.start] = block
        result.instruction_count += len(block.insns)

        for target, _kind in successors:
            if target in result.blocks or target in seen_starts:
                continue
            worklist.append(target)

    # Branch targets can land inside an already-decoded block; cut those
    # blocks so every instruction belongs to exactly one basic block, then
    # derive the edge list from the final partition.
    _split_overlaps(result.blocks)
    result.instruction_count = sum(len(block.insns) for block in result.blocks.values())
    result.edges, result.calls = _rebuild_edges(result.blocks)

    if worklist:
        pending = [target for target in worklist if target not in result.blocks]
        if pending:
            result.truncated = True
            result.note = (
                result.note + f" Stopped after {len(result.blocks)} basic blocks."
            ).strip()
    if not result.blocks:
        result.note = (result.note + " No basic blocks decoded.").strip()
    return result


def cfg_from_address(model: object, address: int) -> CfgResult:
    """Convenience wrapper that owns its own Disassembler."""
    return build_cfg(model, address)
