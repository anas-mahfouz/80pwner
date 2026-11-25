# 80PWNER — by Anas Mahfouz (The 80)

"""ROP/JOP gadget finder (x86 / x86-64).

Two-phase scan, the classic ropper approach:

1. locate *terminators* (ret, ret imm, jmp reg, call reg, syscall,
   int 0x80) by byte pattern inside executable ranges;
2. for every terminator, walk candidate start positions backwards and
   try to decode an instruction chain that lands *exactly* on the
   terminator's end — every chain that does is a gadget.

Pure engine: no Qt, worker-thread friendly (progress/cancel callbacks),
reads bytes through :class:`~eightypwner.engines.addrmap.AddrMap`.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from eightypwner.engines.addrmap import AddrMap
from eightypwner.engines.binary_parser import BinaryModel

MAX_GADGET_BYTES = 32  # deepest start position to walk back from a terminator
MAX_INSNS = 10         # instruction-count depth limit per gadget
MAX_SCAN_BYTES = 16 * 1024 * 1024  # cap across all exec ranges (note when hit)

ProgressCb = Callable[[float], None]
CancelCb = Callable[[], bool]

KINDS = ("ret", "jmp", "call", "syscall", "int80")

# order matters only for speed: c3 is by far the most common terminator
_TERM_RE = re.compile(rb"\xc3|\xc2|\xff[\xe0-\xe7]|\xff[\xd0-\xd7]|\x0f\x05|\xcd\x80")


class UnsupportedArchError(ValueError):
    """Clean degradation for non-x86 binaries (spec: x86 first)."""


@dataclass(frozen=True)
class Gadget:
    """One gadget: raw span + rendered Intel-syntax text."""

    address: int
    size: int
    bytes_hex: str
    insns: str  # "pop rdi ; ret"
    ending: str  # ret | jmp | call | syscall | int80


@dataclass(frozen=True)
class GadgetQuery:
    """Filter bundle for :func:`apply_query` — all fields optional."""

    regs: tuple[str, ...] = ()
    regex: str = ""
    max_bytes: int = 0  # 0 = unlimited
    bad_bytes: bytes = b""
    kinds: tuple[str, ...] = ()


@dataclass
class ScanResult:
    gadgets: list[Gadget] = field(default_factory=list)
    note: str = ""  # truncation / cancellation info for the UI
    scanned_bytes: int = 0


# ---------------------------------------------------------------- range selection
def exec_ranges(
    model: BinaryModel, max_bytes: int = MAX_SCAN_BYTES
) -> tuple[list[tuple[int, int]], str]:
    """Executable scan ranges: x-flagged LOAD segments ∩ PROGBITS sections.

    Falls back to whole exec segments when the binary has no usable section
    table. Returns ``([ (vaddr, size), ... ], note)`` — ranges are capped to
    *max_bytes* total with an explanatory note when truncated.
    """
    exec_segs = [
        s for s in model.segments if s.type_name == "LOAD" and "x" in s.flags and s.size > 0
    ]
    progbits = [c for c in model.sections if c.type == "PROGBITS" and c.size > 0]

    spans: list[tuple[int, int]] = []
    if progbits:
        for seg in exec_segs:
            seg_lo, seg_hi = seg.vaddr, seg.vaddr + seg.size
            for sec in progbits:
                # section vaddr 0 (stripped debug sections) must not slide spans
                if sec.vaddr == 0:
                    continue
                lo = max(seg_lo, sec.vaddr)
                hi = min(seg_hi, sec.vaddr + sec.size)
                if hi > lo:
                    spans.append((lo, hi - lo))
    else:
        spans = [(s.vaddr, s.size) for s in exec_segs]

    spans.sort()
    merged: list[tuple[int, int]] = []
    for lo, size in spans:
        hi = lo + size
        if merged and lo <= merged[-1][0] + merged[-1][1]:
            prev = merged[-1]
            merged[-1] = (prev[0], max(prev[0] + prev[1], hi) - prev[0])
        else:
            merged.append((lo, size))

    total = sum(size for _, size in merged)
    note = ""
    if total > max_bytes:
        trimmed: list[tuple[int, int]] = []
        budget = max_bytes
        for lo, size in merged:
            take = min(size, budget)
            if take <= 0:
                break
            trimmed.append((lo, take))
            budget -= take
        note = (
            f"Executable region is ~{total // (1024 * 1024) + 1} MB — scanned the first "
            f"{max_bytes // (1024 * 1024)} MB; results may be partial."
        )
        merged = trimmed
    return merged, note


# ---------------------------------------------------------------- scanning
def _cs_for(model: BinaryModel):
    import capstone

    arch = model.arch.lower()
    if arch not in ("x86_64", "x86"):
        raise UnsupportedArchError(
            f"Gadget finder supports x86/x86-64 only — this binary is '{model.arch}'."
        )
    mode = capstone.CS_MODE_64 if model.bits == 64 else capstone.CS_MODE_32
    return capstone.Cs(capstone.CS_ARCH_X86, mode)  # Intel syntax, no detail


def _decode_one(cs, blob: bytes, vaddr: int):
    """First instruction of *blob* as ``(size, text)`` or None."""
    for _addr, size, mnemonic, op_str in cs.disasm_lite(blob, vaddr):
        return size, f"{mnemonic} {op_str}".strip()
    return None


def _classify_term(term: bytes) -> tuple[str, int] | None:
    """(kind, terminator length) for a byte-pattern match, or None."""
    if term == b"\xc3":
        return "ret", 1
    if term == b"\xc2":
        return "ret", 3  # ret imm16 — span is short, following bytes are the imm
    if len(term) == 2:
        first, second = term[0], term[1]
        if first == 0xFF:
            return ("jmp", 2) if 0xE0 <= second <= 0xE7 else ("call", 2)
        if term == b"\x0f\x05":
            return "syscall", 2
        if term == b"\xcd\x80":
            return "int80", 2
    return None


def _scan_blob(
    cs,
    blob: bytes,
    base: int,
    out: list[Gadget],
    progress: ProgressCb | None,
    cancel: CancelCb | None,
    cancelled: list[bool],
) -> None:
    """One executable span: find terminators, walk back, collect gadgets."""
    insn_at: dict[int, tuple[int, str]] = {}  # pos → (size, text); (-1, "") = invalid
    seen: set[tuple[int, int]] = set()

    def chain(start: int, term_start: int, tlen: int) -> str | None:
        """Decode forward from *start*; every byte before the terminator must
        decode into whole instructions, and the terminator itself must decode
        as one instruction of exactly *tlen* bytes ending the gadget."""
        parts: list[str] = []
        pos = start
        while pos < term_start and len(parts) < MAX_INSNS:
            hit = insn_at.get(pos)
            if hit is None:
                one = _decode_one(cs, blob[pos:min(pos + 16, len(blob))], base + pos)
                hit = one if one is not None else (-1, "")
                insn_at[pos] = hit
            size, text = hit
            if size < 0 or pos + size > term_start:
                return None  # invalid instruction or mid-instruction start
            parts.append(text)
            pos += size
        if pos != term_start or len(parts) >= MAX_INSNS:
            return None
        # the terminator instruction itself, decoded from its own start
        term = _decode_one(cs, blob[term_start : term_start + tlen + 8], base + term_start)
        if term is None or term[0] != tlen:
            return None
        parts.append(term[1])
        return " ; ".join(parts)

    for m in _TERM_RE.finditer(blob):
        if cancel is not None and cancel():
            cancelled[0] = True
            break
        kind_tlen = _classify_term(m.group(0))
        if kind_tlen is None:
            continue
        kind, tlen = kind_tlen
        term_start = m.span()[0]
        term_end = term_start + tlen  # ret imm16: span is 1 byte, imm follows
        for back in range(tlen, MAX_GADGET_BYTES + 1):
            start = term_start + tlen - back
            if start < 0:
                break
            text = chain(start, term_start, tlen)
            if text is None:
                continue
            vaddr = base + start
            if (vaddr, back) in seen:
                continue
            seen.add((vaddr, back))
            out.append(
                Gadget(
                    address=vaddr,
                    size=back,
                    bytes_hex=blob[start:term_end].hex(),
                    insns=text,
                    ending=kind,
                )
            )
        if progress is not None and term_end & 0xFFF < 64:  # ~every 4 KiB
            progress(min(0.99, term_end / max(1, len(blob))))


def find_gadgets(
    model: BinaryModel,
    data: bytes | None = None,
    progress_cb: ProgressCb | None = None,
    should_cancel: CancelCb | None = None,
) -> ScanResult:
    """Scan every executable range of *model*; x86/x86-64 only.

    Raises :class:`UnsupportedArchError` for anything else — callers degrade
    cleanly. Honours *should_cancel* between candidates (partial results
    are returned with a note, never lost).
    """
    cs = _cs_for(model)
    ranges, note = exec_ranges(model)
    addrmap = AddrMap(model, data)
    result = ScanResult(note=note)
    cancelled = [False]
    total = sum(size for _, size in ranges) or 1
    done = 0
    for vaddr, size in ranges:
        if should_cancel is not None and should_cancel():
            cancelled[0] = True
            break
        try:
            blob = addrmap.read(vaddr, size)
        except Exception:
            note = (result.note + " Some executable ranges were unreadable.").strip()
            result.note = note
            done += size
            continue
        if not blob:
            done += size
            continue
        if progress_cb is not None:
            progress_cb(min(0.5, done / total))
        _scan_blob(cs, blob, vaddr, result.gadgets, progress_cb, should_cancel, cancelled)
        done += size
        if cancelled[0]:
            break
    if cancelled[0]:
        result.note = (result.note + " Scan cancelled — showing partial results.").strip()
    elif progress_cb is not None:
        progress_cb(1.0)
    result.scanned_bytes = min(done, total)
    return result


# ---------------------------------------------------------------- filtering
def apply_query(gadgets: list[Gadget], query: GadgetQuery) -> list[Gadget]:
    """Pure filter: registers / regex / max length / bad bytes / endings."""
    rx = re.compile(query.regex, re.IGNORECASE) if query.regex else None
    regs = {r.lower() for r in query.regs}
    out: list[Gadget] = []
    for g in gadgets:
        if query.kinds and g.ending not in query.kinds:
            continue
        if query.max_bytes and g.size > query.max_bytes:
            continue
        if regs:
            toks = {t.lower() for t in re.findall(r"\w+", g.insns)}
            if not regs <= toks:
                continue
        if rx is not None and not rx.search(g.insns):
            continue
        if query.bad_bytes:
            raw = bytes.fromhex(g.bytes_hex)
            # exclude on gadget bytes OR any little-endian address encoding
            if any(b in query.bad_bytes for b in raw):
                continue
            if any(b in query.bad_bytes for b in g.address.to_bytes(8, "little")):
                continue
            if any(b in query.bad_bytes for b in g.address.to_bytes(4, "little")):
                continue
        out.append(g)
    return out
