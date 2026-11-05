# 80PWNER — by Anas Mahfouz (The80)

"""Capstone disassembly engine (spec §6.2, Step 3).

Arch coverage: x86 (32/64), ARM (ARM/Thumb), AArch64, plus MIPS because the
mapping already exists. Intel syntax by default; AT&T toggle for x86. The
engine works on virtual addresses through the AddrMap, so ELF/PE/Mach-O are
handled identically. Function-scope decoding keeps the UI lazy — large
binaries are never disassembled wholesale.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass

try:
    import capstone

    _CAPSTONE_OK = True
except ImportError:  # pragma: no cover
    capstone = None
    _CAPSTONE_OK = False

from eightypwner.engines.addrmap import AddrMap, ReadError
from eightypwner.engines.binary_parser import BinaryModel

log = logging.getLogger(__name__)

SUPPORTED = ("x86", "+x86-64" if _CAPSTONE_OK else "", "arm", "arm64", "mips")
MAX_FUNCTION_INSTRUCTIONS = 4096
MAX_DISCOVERY_BYTES = 8 * 1024 * 1024

_ARCH_NOT_AVAILABLE = (
    "Capstone is not installed.\n"
    "Install it with:  pip install capstone"
)


@dataclass(frozen=True)
class Instruction:
    address: int
    size: int
    bytes_hex: str
    mnemonic: str
    operands: str

    def text(self) -> str:
        return f"{self.mnemonic} {self.operands}".strip()


@dataclass(frozen=True)
class BranchTarget:
    address: int      # immediate target when the operand encodes one
    insn_address: int
    kind: str         # call | jmp | cond


def _cs_arch_for(model: BinaryModel) -> tuple[int, int] | None:
    """Map BinaryModel arch/bits to capstone (arch, mode)."""
    if not _CAPSTONE_OK:
        raise RuntimeError(_ARCH_NOT_AVAILABLE)
    arch = model.arch.lower()
    endian = capstone.CS_MODE_BIG_ENDIAN if model.endianness == "big" else capstone.CS_MODE_LITTLE_ENDIAN
    if arch in ("x86_64", "x86"):
        return (capstone.CS_ARCH_X86, capstone.CS_MODE_64 if model.bits == 64 else capstone.CS_MODE_32)
    if arch == "aarch64":
        return (capstone.CS_ARCH_AARCH64, endian)
    if arch == "arm":
        mode = capstone.CS_MODE_THUMB if getattr(model, "thumb", False) else endian
        if not getattr(model, "thumb", True):
            mode = mode | endian
        return (capstone.CS_ARCH_ARM, mode)
    if arch == "mips":
        mode = capstone.CS_MODE_MIPS32 if model.bits == 32 else capstone.CS_MODE_MIPS64
        return (capstone.CS_ARCH_MIPS, mode | endian)
    if arch.endswith("riscv64"):
        return (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | endian)
    if arch.endswith("riscv32"):
        return (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32 | endian)
    if arch == "ppc64":
        return (capstone.CS_ARCH_PPC, capstone.CS_MODE_64 | endian)
    if arch == "ppc":
        return (capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | endian)
    return None


class Disassembler:
    """Stateful engine bound to one BinaryModel; caches decoded ranges."""

    def __init__(self, model: BinaryModel, data: bytes | None = None) -> None:
        if not _CAPSTONE_OK:
            raise RuntimeError(_ARCH_NOT_AVAILABLE)
        self.model = model
        self.addrmap = AddrMap(model, data)
        cs_spec = _cs_arch_for(model)
        if cs_spec is None:
            raise RuntimeError(
                f"Architecture '{model.arch}' is not supported by the disassembler yet."
            )
        arch, mode = cs_spec
        self.arch_name = model.arch
        self.is_x86 = arch == capstone.CS_ARCH_X86
        self._capstone = capstone
        self._cs_intel = capstone.Cs(arch, mode)
        self._cs_intel.detail = True
        self._cs_att = (
            capstone.Cs(arch, mode | capstone.CS_MODE_32 if False else mode) if self.is_x86 else None
        )
        if self._cs_att is not None:
            try:
                self._cs_att.syntax = capstone.CS_OPT_SYNTAX_ATT
                self._cs_att.detail = True
            except capstone.error.CapstoneError:  # pragma: no cover
                self._cs_att = None
        # caches
        self._cache_ranges: dict[tuple[int, bool, int, int], list[Instruction]] = {}

    # ------------------------------------------------------------- low-level
    def decode(
        self,
        vaddr: int,
        size: int,
        att_syntax: bool = False,
        decode_all: bool = True,
    ) -> Iterator[Instruction]:
        """Linear decode *size* bytes at *vaddr* in the chosen syntax."""
        cs = self._cs_att if att_syntax and self._cs_att is not None else self._cs_intel
        try:
            data = self.addrmap.read(vaddr, size)
        except ReadError:
            return
        stop_early = not decode_all
        for insn in cs.disasm(data, vaddr):
            bytes_hex = " ".join(f"{b:02x}" for b in insn.bytes)
            yield Instruction(
                address=insn.address,
                size=insn.size,
                bytes_hex=bytes_hex,
                mnemonic=insn.mnemonic,
                operands=insn.op_str,
            )
            if stop_early:
                return

    def decode_function(
        self,
        vaddr: int,
        att_syntax: bool = False,
        limit: int = MAX_FUNCTION_INSTRUCTIONS,
    ) -> list[Instruction]:
        """Decode a function: linear within its body, stopping at hard markers.

        Heuristic (function-scope, never the whole binary): decode linearly
        from entry; after an unconditional jump with no fallthrough target and
        no following instruction anchors (padding/ret), stop decoding.
        """
        cache_key = (vaddr, att_syntax, 0, limit)
        cached = self._cache_ranges.get(cache_key)
        if cached is not None:
            return cached
        out: list[Instruction] = []
        chunk = 4096
        cursor = vaddr
        stop = False
        while not stop and len(out) < limit:
            produced = 0
            prev_last = None
            for insn in self.decode(cursor, chunk, att_syntax):
                produced += 1
                out.append(insn)
                prev_last = insn
                if len(out) >= limit:
                    break
            if produced == 0 or prev_last is None:
                break
            cursor = prev_last.address + prev_last.size
            # extend detection: if the last instruction was ret/iret/hlt/jmp,
            # the function body likely ended; stop after seeing it.
            if prev_last.mnemonic.split(".")[0] in ("ret", "hlt", "jmp", "iret", "syscall"):
                stop = True
        self._cache_ranges[cache_key] = out
        return out

    # --------------------------------------------------------------- targets
    def branch_targets(self, instrs: list[Instruction]) -> list[BranchTarget]:
        """Extract immediate call/jmp targets (capstone detail not required)."""
        targets: list[BranchTarget] = []
        for insn in instrs:
            mnemonic = insn.mnemonic
            cond = _is_conditional(mnemonic, self.arch_name)
            if mnemonic in ("call", "jmp") or cond:
                address = _immediate_operand(insn.operands)
                if address is not None:
                    targets.append(
                        BranchTarget(address, insn.address, "call" if mnemonic == "call" else ("jmp" if not cond else "cond"))
                    )
        return targets

    def xrefs_from(self, vaddr: int, att_syntax: bool = False) -> list[BranchTarget]:
        """Targets referenced by the instruction at vaddr (call/jmp/cond)."""
        for insn in self.decode(vaddr, 16, att_syntax, decode_all=False):
            return self.branch_targets([insn])
        return []


def _immediate_operand(op_str: str) -> int | None:
    """Pull the first immediate hex operand like '0x4012ab' from an operand string."""
    import re

    match = re.match(r"\s*0x[0-9a-fA-F]+\b", op_str)
    if not match:
        return None
    return int(match.group(0), 16)


def _is_conditional(mnemonic: str, arch: str) -> bool:
    if arch.startswith("x86"):
        return mnemonic.startswith("j") and mnemonic not in ("jmp",)
    if arch == "arm" or arch == "aarch64":
        return mnemonic.startswith("b.") or mnemonic in ("bl",)
    return False
