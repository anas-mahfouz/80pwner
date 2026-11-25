# 80PWNER — by Anas Mahfouz (The 80)

"""Stack frame layout analysis (Step 5) — pure logic: no Qt, no processes.

Given the register snapshot of a debuggee frame (``pc``/``rbp``/``rsp``), the
raw stack window read around the frame's SP, and (when available) the
function's disassembly plus its DWARF variable list, :func:`analyze_frame`
produces a :class:`FrameLayout` — disjoint rows ordered high-address-first
covering exactly ``[rsp, top)``:

* caller stack arguments (DWARF formal parameters above the CFA),
* return address (``rbp + word``) and saved frame pointer (``rbp``),
* stack canary (from the ``fs:0x28``/``gs:0x14`` store pattern, the
  checksec verdict, and a canary-shaped value heuristic),
* local variables/buffers — DWARF (``-g`` builds) when available, else
  inferred from the disassembly (``sub rsp`` / ``lea/mov [rbp-X]``),
* dim filler rows for the remaining (unknown) bytes, so nothing is hidden.

Frame-pointer builds are analyzed exactly (CFA = ``rbp + 2*word``; DWARF
``DW_OP_fbreg`` offsets resolve against the CFA). Without a frame pointer
(``-fomit-frame-pointer``/``-O1``+ or ``rbp <= rsp``) the layout degrades to
a plain SP-window word dump with a clear note — caller frame bounds cannot
be pinned down without unwind info.

Every row carries RBP/RSP offsets, byte size, the first-word raw value
(when the window covers it) and a pointer/ASCII annotation. The copyable
hotspot distances (``buffer start -> canary / saved RBP / return address``)
come from :func:`frame_distances`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from eightypwner.engines.disassembler import Instruction

log = logging.getLogger(__name__)

# BinaryModel.arch name → word/pointer size in bytes (None = unsupported).
WORD_SIZE = {
    "x86_64": 8,
    "x86": 4,
    "x86_32": 4,
}
DEFAULT_CANARY_OFFSET = -8  # rbp-relative; gcc writes the canary at rbp-8

# kind → human label (the visualizer diagram uses these).
KIND_LABEL = {
    "ret_addr": "return address",
    "saved_rbp": "saved RBP (frame ptr)",
    "canary": "stack canary",
    "buffer": "buffer",
    "local": "local variable",
    "param": "argument",
    "gap": "unknown",
    "window": "stack word",
}

_FP_RE = re.compile(r"^mov\s+(?:rbp|ebp),\s*(?:rsp|esp)\b")
_PUSH_RBP_RE = re.compile(r"^push\s+(?:rbp|ebp)\b")
_SUB_RSP_RE = re.compile(r"^sub\s+(?:rsp|esp),\s*(0x[0-9a-fA-F]+|\d+)\s*$")
_LEA_RBP_RE = re.compile(r"^lea\s+\w+,\s*\[[^\]]*\b(?:rbp|ebp)\s*-\s*(0x[0-9a-fA-F]+)\]$")
_MOV_RBP_RE = re.compile(r"^mov\b.*\[[^\]]*\b(?:rbp|ebp)\s*-\s*(0x[0-9a-fA-F]+)\]")
_CANARY_LOAD_RE = re.compile(
    r"^mov\s+(\w+),\s*(?:qword|dword)\s+ptr\s+(?:fs|gs):(?:0x28|0x14|0x18|0x64)\b"
)
_CANARY_STORE_RE = re.compile(
    r"^mov\s+(?:qword|dword)\s+ptr\s*\[[^\]]*\b(?:rbp|ebp)\s*-\s*(0x[0-9a-fA-F]+)\],\s*(\w+)\b"
)
_PRINTABLE = frozenset(range(0x20, 0x7F))
_STACK_SLAB = 0x100000  # pointer within 1 MiB of RSP counts as a stack pointer


# ------------------------------------------------------------------- models
@dataclass(frozen=True)
class DwarfVar:
    """One DWARF variable/parameter of a function (CFA-relative location)."""

    name: str
    fbreg: int  # DW_OP_fbreg offset (signed)
    size: int  # bytes when determinable, else 0
    is_param: bool
    type_name: str = ""


@dataclass
class FrameHints:
    """What the function's own disassembly implies about its frame."""

    have_frame_pointer: bool = False
    locals_bytes: int = 0  # sub rsp, N
    rbp_refs: list[int] = field(default_factory=list)  # negative rbp-relative offsets
    canary_offset: int | None = None  # rbp-relative (negative) from the pattern


@dataclass(frozen=True)
class StackRow:
    """One row of the frame diagram (a disjoint byte span on the stack)."""

    address: int
    kind: str  # ret_addr | saved_rbp | canary | buffer | local | param | gap | window
    size: int  # bytes
    label: str
    offset_rbp: int | None  # None when there is no frame pointer
    offset_rsp: int
    value: int | None  # first word at *address* (little-endian) when covered
    annotation: str = ""  # pointer/ASCII annotation for *value*
    is_pointer: bool = False  # double-click follows the value in memory view
    marker: str = ""  # "rsp" | "rbp" | "" — rendered as a chip on the row


@dataclass(frozen=True)
class FrameLayout:
    """Analysis result for one frame (immutable; safe to pass across threads)."""

    frame_level: int
    func_name: str
    arch: str
    word: int
    pc: int
    rbp: int | None
    rsp: int
    rows: tuple[StackRow, ...]
    notes: tuple[str, ...]  # human-readable degradations/flags
    source: str  # "dwarf" | "disassembly" | "window"
    error: str | None = None  # fatal (unsupported arch) → rows empty

    # ------------------------------------------------------------- helpers
    def has_frame_pointer(self) -> bool:
        return self.rbp is not None

    def row_at(self, address: int) -> StackRow | None:
        for row in self.rows:
            if row.address <= address < row.address + max(row.size, 1):
                return row
        return None

    def buffer_start(self) -> int | None:
        """Start address of the widest known buffer row (or None)."""
        rows = [row for row in self.rows if row.kind == "buffer"]
        if not rows:
            rows = [
                row
                for row in self.rows
                if row.kind in ("local", "param") and row.size > 0
            ]
        return max(rows, key=lambda row: row.size).address if rows else None


def word_size_for_arch(arch: str) -> int | None:
    """Word size for a BinaryModel.arch name, or None when unsupported."""
    return WORD_SIZE.get(str(arch).strip().lower())


def frame_distances(layout: FrameLayout) -> list[tuple[str, int]]:
    """(display, bytes) hotspot distances for the copyable distance strip."""
    if layout.error is not None or not layout.has_frame_pointer():
        return []
    start = layout.buffer_start()
    if start is None:
        return []
    landmarks: dict[str, StackRow] = {}
    for row in layout.rows:
        if row.kind in ("canary", "saved_rbp", "ret_addr") and row.kind not in landmarks:
            landmarks[row.kind] = row
    out: list[tuple[str, int]] = []
    for kind, name in (
        ("canary", "buffer -> canary"),
        ("saved_rbp", "buffer -> saved RBP"),
        ("ret_addr", "buffer -> return address"),
    ):
        row = landmarks.get(kind)
        if row is not None:
            dist = row.address - start
            out.append((f"{name}: {dist} bytes (0x{dist:x})", dist))
    return out


def value_word_at(base: int, data: bytes, address: int, word: int) -> int | None:
    """Little-endian word at *address* when the window covers it, else None."""
    if base <= address <= base + len(data) - word:
        chunk = data[address - base : address - base + word]
        return int.from_bytes(chunk, "little", signed=False)
    return None


def window_covers(base: int, data: bytes, address: int, word: int) -> bool:
    """True when the stack window contains a full word at *address*."""
    return value_word_at(base, data, address, word) is not None


def annotate_value(
    value: int,
    *,
    word: int,
    rsp: int,
    text_delta: int = 0,
    symbols: Iterable[tuple[int, str, int]] = (),
) -> str:
    """Pointer/ASCII annotation for a raw stack word.

    Pointer into the (possibly rebased) binary → ``main+0x1a``; pointer
    within 1 MiB of RSP → ``stack``; fully-printable word → ``'ABCD'``;
    zero → ``<null>``; otherwise empty.
    """
    value = int(value) & ((1 << (word * 8)) - 1)
    if value == 0:
        return "<null>"
    static = value - int(text_delta)
    for addr, name, size in symbols:
        limit = addr + size if size else addr
        if addr <= static < max(limit, addr + 1):
            return f"{name}+0x{static - addr:x}"
    if abs(value - rsp) < _STACK_SLAB:
        return "stack"
    data = value.to_bytes(word, "little", signed=False)
    if all(b in _PRINTABLE for b in data):
        return f"'{data.decode('ascii')}'"
    return ""


# ------------------------------------------------- disassembly → frame hints
def hints_from_instructions(insns: Iterable[Instruction], bits: int) -> FrameHints:
    """Scan a function's disassembly for its frame conventions (Intel syntax).

    Detects the frame-pointer setup (``push rbp`` + ``mov rbp, rsp``), the
    local allocation (``sub rsp, N``), every ``[rbp-X]`` reference, and the
    stack-canary pattern (``mov REG, fs:0x28`` then ``mov [rbp-off], REG``).
    The *bits* parameter keeps the signature symmetric with the DWARF helper
    (32-bit canary slots sit at ``rbp-8`` as well; see DEFAULT_CANARY_OFFSET).
    """
    hints = FrameHints()
    pending_canary_reg: str | None = None
    for insn in insns:
        mnemonic = (insn.mnemonic or "").strip().lower()
        # operands too: capstone renders lowercase, but hand-written rows may not
        text = f"{mnemonic} {(insn.operands or '').strip().lower()}".strip()
        if _PUSH_RBP_RE.match(text) or _FP_RE.match(text):
            hints.have_frame_pointer = True
            continue
        sub = _SUB_RSP_RE.match(text)
        if sub:
            with suppress(ValueError):
                hints.locals_bytes = int(sub.group(1), 0)
            continue
        canary_load = _CANARY_LOAD_RE.match(text)
        if canary_load:
            pending_canary_reg = canary_load.group(1).lower()
            continue
        store = _CANARY_STORE_RE.match(text)
        if store:
            offset = int(store.group(1), 16)
            if pending_canary_reg is None or store.group(2).lower() == pending_canary_reg:
                hints.canary_offset = -offset
            pending_canary_reg = None
        ref = _LEA_RBP_RE.match(text) or _MOV_RBP_RE.match(text)
        if ref:
            hints.rbp_refs.append(-int(ref.group(1), 16))
    return hints


# ------------------------------------------------------------- DWARF lookup
def dwarf_frame_variables(path: Path, func_addr: int) -> list[DwarfVar]:
    """DWARF variable/parameter list for the function containing *func_addr*.

    Needs :mod:`elftools` (optional analysis extra) and debug info in the
    binary; anything missing or malformed yields an empty list so the
    disassembly-inference fallback takes over. Recognized frame bases:
    ``DW_OP_call_frame_cfa`` (CFA-anchored, the gcc default) and a bare
    rbp register expression — anything else returns [] for that DIE.
    """
    try:
        from elftools.dwarf.dwarf_expr import DWARFExprParser
        from elftools.elf.elffile import ELFFile
    except ImportError:  # pragma: no cover — optional extra not installed
        log.debug("pyelftools unavailable — DWARF locals disabled")
        return []

    try:
        with open(path, "rb") as handle:
            elf = ELFFile(handle)
            if not elf.has_dwarf_info():
                return []
            dwarf = elf.get_dwarf_info()
            parser = DWARFExprParser(dwarf.structs)
            for cu in dwarf.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    if not _sp_contains(die, func_addr):
                        continue
                    fb = _frame_base_offset(parser, die)
                    if fb is None:
                        continue
                    return _dwarf_vars_of_die(cu, die, parser, fb)
    except Exception:  # malformed DWARF must never break the visualizer
        log.debug("DWARF lookup failed for %s@%#x", path, func_addr, exc_info=True)
        return []
    return []


def _sp_contains(die: Any, func_addr: int) -> bool:
    low, high = _sp_range(die)
    return low is not None and high is not None and low <= func_addr < high


def _sp_range(die: Any) -> tuple[int | None, int | None]:
    low_attr = die.attributes.get("DW_AT_low_pc")
    high_attr = die.attributes.get("DW_AT_high_pc")
    if low_attr is None or high_attr is None:
        return None, None
    try:
        low = int(low_attr.value)
    except (TypeError, ValueError):
        return None, None
    form = str(high_attr.form)
    if form in ("DW_FORM_addr", "DW_FORM_addr_index", "DW_FORM_sec_offset"):
        # address-class value → absolute end address
        try:
            return low, int(high_attr.value)  # absolute address
        except (TypeError, ValueError):
            return None, None
    # size form (off_size/data16/udata/implicit_const...)
    try:
        return low, low + int(high_attr.value)
    except (TypeError, ValueError):
        return None, None


def _frame_base_offset(parser: Any, die: Any) -> int | None:
    """How to turn ``DW_OP_fbreg X`` into an address, offset from the CFA.

    Returns 0 for CFA-anchored frame bases (``addr = CFA + X``) or ``word``
    for rbp-anchored ones (``addr = rbp + X``) — callers anchor at ``CFA =
    rbp + 2*word`` either way. None = unsupported frame base.
    """
    attr = die.attributes.get("DW_AT_frame_base")
    if attr is None:
        return 0  # no explicit frame base: gcc defaults to CFA anchoring
    try:
        from elftools.dwarf.locationlists import LocationExpr

        ops = parser.parse_expr(list(LocationExpr(attr.value).loc_expr))
    except Exception:
        return None
    names = [op.op_name for op in ops]
    if names and all(name == "DW_OP_call_frame_cfa" for name in names):
        return 0  # CFA-anchored: rbp+2*word + X
    if names and all(name in ("DW_OP_reg6",) for name in names):  # rbp
        return 0  # rbp-anchored resolves via the same CFA math (rbp = CFA-2*word)
    return None


def _dwarf_vars_of_die(cu: Any, die: Any, parser: Any, offset: int) -> list[DwarfVar]:
    """Collect DW_TAG_variable/formal_parameter rows under a subprogram DIE."""
    out: list[DwarfVar] = []
    for child in die.iter_children():
        if child.tag not in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
            continue
        name_attr = child.attributes.get("DW_AT_name")
        if name_attr is None:
            continue  # anonymous helper variables are noise in the diagram
        name = str(name_attr.value, "utf-8", "replace")
        if not name:
            continue
        fbreg = _var_fbreg(parser, child)
        if fbreg is None:
            continue
        size = _dwarf_type_size(child)
        type_name = _dwarf_type_name(child)
        out.append(
            DwarfVar(
                name=name,
                fbreg=int(fbreg + offset),
                size=int(size or 0),
                is_param=child.tag == "DW_TAG_formal_parameter",
                type_name=type_name,
            )
        )
    return out


def _var_fbreg(parser: Any, die: Any) -> int | None:
    """DW_OP_fbreg offset from a variable's DW_AT_location (else None)."""
    attr = die.attributes.get("DW_AT_location")
    if attr is None:
        return None
    try:
        from elftools.dwarf.locationlists import LocationExpr

        ops = parser.parse_expr(list(LocationExpr(attr.value).loc_expr))
    except Exception:
        return None
    for op in ops:
        if op.op_name == "DW_OP_fbreg":
            arg = op.args[0] if op.args else None
            if isinstance(arg, int):
                return int(arg)
            return None
        if op.op_name == "DW_OP_call_frame_cfa":
            return 0
    return None


def _dwarf_type_size(die: Any) -> int | None:
    """Allocation size (bytes) of a variable's DWARF type; None unknown."""
    type_die = _ref_die(die, "DW_AT_type")
    if type_die is None:
        return None
    return _type_size_walk(type_die, set())


def _type_size_walk(die: Any, seen: set[int]) -> int | None:
    marker = getattr(die, "offset", 0)
    if marker in seen:
        return None  # type-cycle guard
    seen.add(marker)
    attr = die.attributes.get("DW_AT_byte_size")
    if attr is not None:
        try:
            return int(attr.value)
        except (TypeError, ValueError):
            return None
    if die.tag == "DW_TAG_typedef":
        inner = _ref_die(die, "DW_AT_type")
        return _type_size_walk(inner, seen) if inner is not None else None
    if die.tag == "DW_TAG_array_type":
        element = _ref_die(die, "DW_AT_type")
        elem_size = _type_size_walk(element, seen) if element is not None else None
        count = _array_count(die)
        if elem_size and count is not None:
            return int(elem_size * count)
    return None


def _array_count(die: Any) -> int | None:
    for kid in die.iter_children():
        if kid.tag != "DW_TAG_subrange_type":
            continue
        count = kid.attributes.get("DW_AT_count")
        upper = kid.attributes.get("DW_AT_upper_bound")
        try:
            if count is not None:
                return int(count.value) + 1
            if upper is not None:
                return int(upper.value) + 1
        except (TypeError, ValueError):
            return None
    return None


def _ref_die(die: Any, attribute: str) -> Any | None:
    if die.attributes.get(attribute) is None:
        return None
    try:
        return die.get_DIE_from_attribute(attribute)
    except Exception:  # pragma: no cover — broken refs
        return None


def _dwarf_type_name(die: Any) -> str:
    type_die = _ref_die(die, "DW_AT_type")
    if type_die is None:
        return ""
    attr = type_die.attributes.get("DW_AT_name")
    if attr is not None:
        return str(attr.value, "utf-8", "replace")
    return str(type_die.tag)[7:].replace("TAG_", "")


# ---------------------------------------------------------------- analysis
def analyze_frame(
    *,
    arch: str,
    frame_level: int,
    func_name: str,
    pc: int,
    rbp: int | None,
    rsp: int,
    window_base: int,
    window_bytes: bytes,
    hints: FrameHints | None,
    dwarf_vars: Iterable[DwarfVar] = (),
    canary_enabled: bool = False,
    text_delta: int = 0,
    symbols: Iterable[tuple[int, str, int]] = (),
) -> FrameLayout:
    """Build the visualizer model for one debuggee frame (module docstring)."""
    word = word_size_for_arch(arch)
    if word is None:
        return FrameLayout(
            frame_level=frame_level,
            func_name=func_name,
            arch=arch,
            word=0,
            pc=pc,
            rbp=None,
            rsp=rsp,
            rows=(),
            notes=(
                f"{arch} is not supported yet — the stack visualizer covers "
                "x86-64 and x86 (32-bit) first.",
            ),
            source="window",
            error=f"unsupported architecture: {arch}",
        )

    if hints is None or not hints.have_frame_pointer or rbp is None or rbp <= rsp:
        return _window_layout(
            arch=arch,
            word=word,
            frame_level=frame_level,
            func_name=func_name,
            pc=pc,
            rsp=rsp,
            window_base=window_base,
            window_bytes=window_bytes,
            text_delta=text_delta,
            symbols=symbols,
            notes=(
                "no usable frame pointer in this frame — showing the raw SP "
                "window; caller frame bounds need -fno-omit-frame-pointer",
            ),
        )

    def value_at(address: int) -> int | None:
        return value_word_at(window_base, window_bytes, address, word)

    def annotation_for(address: int) -> str:
        raw = value_at(address)
        if raw is None:
            return ""
        text = annotate_value(
            raw, word=word, rsp=rsp, text_delta=text_delta, symbols=symbols
        )
        return text

    def pointerish(text: str) -> bool:
        return bool(text) and ("stack" in text or "+0x" in text)

    cfa = rbp + 2 * word
    placed: list[StackRow] = []  # disjoint rows, newest priority wins
    spans: list[tuple[int, int]] = []  # covered [start, end) pairs

    def place(address: int, kind: str, size: int, label: str, marker: str = "") -> None:
        """Insert a row for [address, address+size) minus covered zones."""
        address = int(address)
        size = max(int(size), word)
        end = address + size
        rest: list[tuple[int, int]] = []
        cursor = address
        for zone_start, zone_end in spans:
            if zone_end <= cursor or zone_start >= end:
                continue
            if zone_start > cursor:
                rest.append((cursor, min(zone_start, end)))
            cursor = max(cursor, zone_end)
            if cursor >= end:
                break
        else:
            rest.append((cursor, end))
        if not rest and cursor < end:  # loop exited without the else
            pass
        for part_start, part_end in rest:
            raw = value_at(part_start)
            annot = annotation_for(part_start)
            rows_kind = kind if part_start == address else "gap"
            rows_label = label if part_start == address else "… covered …"
            placed.append(
                StackRow(
                    address=part_start,
                    kind=rows_kind,
                    size=part_end - part_start,
                    label=rows_label,
                    offset_rbp=part_start - rbp,
                    offset_rsp=part_start - rsp,
                    value=raw,
                    annotation=annot if raw is not None else "",
                    is_pointer=pointerish(annot),
                    marker=marker if part_start == address else "",
                )
            )
            spans.append((part_start, part_end))

    # 1. anchor rows: return address + saved frame pointer
    place(rbp, "saved_rbp", word, KIND_LABEL["saved_rbp"], marker="rbp")
    place(rbp + word, "ret_addr", word, KIND_LABEL["ret_addr"])

    # 2. caller stack args + locals/params from DWARF (widest first)
    dwarf_rows = sorted(dwarf_vars, key=lambda var: -(var.size or 0))
    for var in dwarf_rows:
        address = cfa + var.fbreg
        if address < rsp:
            continue
        detail = f"{var.name}"
        if var.type_name:
            detail += f" · {var.type_name}"
        if address >= cfa:
            place(
                address, "param", var.size or word,
                f"caller arg ({detail})",
            )
            continue
        if address == rbp:  # occupies the saved-RBP slot — already placed
            continue
        kind = "param" if var.is_param else "local"
        label = f"{'arg' if var.is_param else 'local'} ({detail})"
        if (var.size or 0) >= 4 * word:
            label = f"buffer {var.name} [0x{(var.size or 0):x} B]"
            kind = "buffer"
        place(address, kind, var.size or word, label)

    # 3. canary (pattern-aware; checksec + value-shape as fallbacks)
    canary_addr: int | None = None
    if hints.canary_offset is not None:
        canary_addr = rbp + hints.canary_offset
    elif canary_enabled:
        candidate = value_at(rbp - word)
        if candidate is not None and candidate & 0xFF == 0x00:  # LSB-0 shape
            canary_addr = rbp - word
    if canary_addr is not None and rsp <= canary_addr < cfa:
        place(canary_addr, "canary", word, KIND_LABEL["canary"])

    # 4. locals inferred from disassembly refs (widest-to-narrow coverage)
    for ref in sorted(
        {
            offset
            for offset in hints.rbp_refs
            if rsp <= rbp + offset < cfa
            and (rbp + offset) not in {row.address for row in placed}
        },
        reverse=True,
    ):
        address = rbp + ref
        # span up to the next known item above (capped by already-placed rows)
        above = [row.address for row in placed if row.address >= address + word]
        upper = min(above) if above else cfa
        size = upper - address
        if size <= 0:
            continue
        place(
            address,
            "local",
            size,
            f"local (lea/mov [rbp-{-ref:#x}])",
        )

    # 6. tile the gaps between rsp and top so nothing is silently hidden
    top = _top(rows=placed, rbp=rbp, word=word, cfa=cfa)
    final_rows = _tile_gaps(placed, rsp, top, word)
    # marker chips: the saved-RBP row is rbp; the row holding rsp carries RSP
    marked = [
        replace(row, marker="rsp") if row.offset_rsp == 0 and row.marker != "rbp" else row
        for row in final_rows
    ]
    notes: list[str] = []
    if hints.locals_bytes:
        notes.append(f"locals allocate 0x{hints.locals_bytes:x} bytes (sub rsp)")
    if not window_covers(window_base, window_bytes, rbp + word, word):
        notes.append("stack window does not cover the whole frame — values may be missing")
    if canary_addr is None and canary_enabled:
        notes.append("canary enabled in checksec but no canary-shaped value found")
    if dwarf_rows:
        used = sum(1 for row in final_rows if row.kind in ("local", "param", "buffer"))
        notes.append(f"DWARF supplied {len(dwarf_rows)} variables; {used} rows placed")
    return FrameLayout(
        frame_level=frame_level,
        func_name=func_name,
        arch=arch,
        word=word,
        pc=pc,
        rbp=rbp,
        rsp=rsp,
        rows=tuple(sorted(marked, key=lambda row: row.address, reverse=True)),
        notes=tuple(notes),
        source="dwarf" if dwarf_rows else "disassembly",
    )


def _top(*, rows: list[StackRow], rbp: int, word: int, cfa: int) -> int:
    """Highest covered address: the CFA plus any caller-arg slot above it."""
    known = [row.address + row.size for row in rows if row.address >= cfa]
    return max([cfa, *known])


def _tile_gaps(
    placed: list[StackRow], rsp: int, top: int, word: int
) -> list[StackRow]:
    """Return [rsp, top) fully tiled: placed rows first, dim gaps between."""
    boundaries: set[int] = {rsp, top}
    for row in placed:
        if rsp <= row.address <= top:
            boundaries.add(row.address)
        if rsp <= row.address + row.size <= top:
            boundaries.add(row.address + row.size)
    edges = sorted(boundaries, reverse=True)
    out: list[StackRow] = list()
    consumed: set[int] = set()
    gaps: list[tuple[int, int]] = []
    for lower, upper in zip(edges[1:], edges, strict=False):
        if upper <= lower:
            continue
        owner = next(
            (row for row in placed if row.address <= lower and row.address + row.size >= upper),
            None,
        )
        if owner is not None:
            if owner.address not in consumed:
                out.append(owner)
                consumed.add(owner.address)
        else:
            gaps.append((lower, upper))
    # merge contiguous gaps, then convert to rows
    merged: list[tuple[int, int]] = []
    for lower, upper in sorted(gaps, reverse=True):
        if merged and merged[-1][0] == upper:
            merged[-1] = (lower, merged[-1][1])
            continue
        merged.append((lower, upper))
    for lower, upper in merged:
        out.append(
            StackRow(
                address=lower,
                kind="gap",
                size=upper - lower,
                label=KIND_LABEL["gap"],
                offset_rbp=None,
                offset_rsp=lower - rsp,
                value=None,
                annotation="",
            )
        )
    out.sort(key=lambda row: row.address, reverse=True)
    return out


# ------------------------------------------------------ SP-window fallback
def _window_layout(
    *,
    arch: str,
    word: int,
    frame_level: int,
    func_name: str,
    pc: int,
    rsp: int,
    window_base: int,
    window_bytes: bytes,
    text_delta: int,
    symbols: Iterable[tuple[int, str, int]],
    notes: tuple[str, ...] = (),
) -> FrameLayout:
    """No frame pointer (or unknown): show the raw SP window word dump."""
    end = window_base + len(window_bytes)
    end = end - (end - window_base) % word  # keep whole words only
    rows: list[StackRow] = []
    address = end - word
    while address >= window_base:
        if address >= rsp:
            raw = value_word_at(window_base, window_bytes, address, word)
            annot = annotate_value(
                raw or 0, word=word, rsp=rsp, text_delta=text_delta, symbols=symbols
            )
            rows.append(
                StackRow(
                    address=address,
                    kind="window",
                    size=word,
                    label=KIND_LABEL["window"],
                    offset_rbp=None,
                    offset_rsp=address - rsp,
                    value=raw,
                    annotation=annot,
                    is_pointer=annot in ("stack",) or "+0x" in annot,
                    marker="rsp" if address == rsp else "",
                )
            )
        address -= word
    return FrameLayout(
        frame_level=frame_level,
        func_name=func_name,
        arch=arch,
        word=word,
        pc=pc,
        rbp=None,
        rsp=rsp,
        rows=tuple(rows),
        notes=notes or ("no frame pointer available — showing the raw SP window",),
        source="window",
    )
