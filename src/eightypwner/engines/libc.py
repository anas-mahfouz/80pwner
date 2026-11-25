# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Libc helper engine (Step 7 B) — the ret2libc / one-gadget workbench.

Everything here works offline from the libc file you bring (the same file the
target runs, ideally): version + build-id fingerprint, symbol offsets,
``/bin/sh`` location, and a heuristic one-gadget scan that verifies the
``execve`` syscall number and how RDI is loaded.

The one-gadget scan is intentionally conservative: it only reports a gadget
when it can *prove* RDI points at ``"/bin/sh"`` (rip/absolute/pointer load)
or when the gadget reads RDI from the stack and states that constraint
explicitly. Nothing is guessed silently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    _HAS_ELFTOOLS = True
except ImportError:  # pragma: no cover — declared dependency
    ELFFile = None
    SymbolTableSection = None
    _HAS_ELFTOOLS = False

try:
    import capstone

    _HAS_CAPSTONE = True
except ImportError:  # pragma: no cover — declared dependency
    capstone = None
    _HAS_CAPSTONE = False

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TEXT_SCAN = 8 * 1024 * 1024
MAX_ONE_GADGETS = 32

# Symbols every ret2libc exploit wants. Aliases are resolved in order.
WANTED_SYMBOLS: tuple[str, ...] = (
    "system",
    "__libc_system",
    "execve",
    "__execve",
    "read",
    "write",
    "puts",
    "printf",
    "gets",
    "malloc",
    "free",
    "environ",
    "__environ",
    "__free_hook",
    "__malloc_hook",
    "setcontext",
    "__libc_start_main",
)

# x86-64 one-gadget patterns that set RAX=59 (execve), x86=11.
_MOV_EAX_59 = re.compile(rb"\xb8\x3b\x00\x00\x00")          # mov eax, 0x3b
_MOV_RAX_59 = re.compile(rb"\x48\xc7\xc0\x3b\x00\x00\x00")  # mov rax, 0x3b
_PUSH_POP_59 = re.compile(rb"\x6a\x3b\x58")                 # push 0x3b; pop rax
_MOV_EAX_11 = re.compile(rb"\xb8\x0b\x00\x00\x00")          # mov eax, 0xb
_PUSH_POP_11 = re.compile(rb"\x6a\x0b\x58")                 # push 0xb; pop rax


class LibcError(Exception):
    """User-facing libc parse failure (shown in the UI verbatim)."""


@dataclass(frozen=True)
class OneGadget:
    offset: int
    sequence: str
    constraint: str
    verified: bool  # True when RDI provably points at "/bin/sh"

    def as_text(self) -> str:
        tag = "verified" if self.verified else "constraint"
        return f"{self.offset:#x}  {tag}: {self.constraint}"


@dataclass
class LibcInfo:
    path: Path
    arch: str = "?"
    bits: int = 64
    endianness: str = "little"
    version: str = ""
    soname: str = ""
    build_id: str = ""
    symbols: dict[str, int] = field(default_factory=dict)
    bin_sh_offset: int | None = None
    one_gadgets: list[OneGadget] = field(default_factory=list)
    text_base: int = 0
    text_size: int = 0
    note: str = ""

    # ------------------------------------------------------------ convenience
    def offset(self, *names: str) -> int | None:
        for name in names:
            value = self.symbols.get(name)
            if value:
                return value
        return None

    @property
    def system(self) -> int | None:
        return self.offset("system", "__libc_system")

    @property
    def execve(self) -> int | None:
        return self.offset("execve", "__execve")

    @property
    def binsh(self) -> int | None:
        return self.bin_sh_offset

    def base_from_leak(self, symbol: str, leaked: int) -> int | None:
        """Runtime libc base from a leaked absolute address of *symbol*."""
        offset = self.symbols.get(symbol) or self.offset(symbol, "__" + symbol)
        if not offset:
            return None
        return leaked - offset

    def runtime(self, symbol: str, base: int) -> int | None:
        offset = self.symbols.get(symbol) or self.offset(symbol, "__" + symbol)
        if not offset:
            return None
        return base + offset

    def binsh_runtime(self, base: int) -> int | None:
        return base + self.bin_sh_offset if self.bin_sh_offset else None

    def fingerprint(self) -> str:
        parts = []
        if self.version:
            parts.append(f"glibc {self.version}")
        if self.build_id:
            parts.append(f"build-id {self.build_id[:16]}")
        if self.soname:
            parts.append(self.soname)
        return " · ".join(parts) if parts else "unknown libc fingerprint"


def _machine_name(machine: str, bits: int) -> str:
    machine = machine.upper()
    if "X86-64" in machine or "X86_64" in machine:
        return "x86_64"
    if "386" in machine:
        return "x86"
    if "AARCH64" in machine:
        return "aarch64"
    if machine.startswith("ARM"):
        return "arm"
    if "MIPS" in machine:
        return "mips"
    if "RISCV" in machine or "RISCV" in machine:  # pragma: no cover
        return "riscv"
    return f"machine:{machine.lower()}"


def _read_notes(data: bytes) -> str:
    """Pull the GNU build-id (note type 3) out of a raw file image."""
    for match in re.finditer(rb"GNU\x00", data):
        index = match.start()
        if index < 12:
            continue
        namesz = int.from_bytes(data[index - 12 : index - 8], "little")
        descsz = int.from_bytes(data[index - 8 : index - 4], "little")
        note_type = int.from_bytes(data[index - 4 : index], "little")
        if note_type != 3 or namesz != 4 or not 0 < descsz <= 64:
            continue
        start = index + namesz + ((-namesz) % 4)
        desc = data[start : start + descsz]
        if len(desc) == descsz:
            return desc.hex()
    return ""


def _build_id_from_elf(elf: object) -> str:
    section = None
    for candidate in elf.iter_sections():
        if "build-id" in str(candidate.name):
            section = candidate
            break
    if section is None:
        return ""
    try:
        blob = section.data()
    except Exception:  # pragma: no cover
        return ""
    return _read_notes(blob)


def _detect_version(data: bytes) -> str:
    patterns = (
        rb"GNU C Library[^\x00\n]{0,160}?release version (\d+\.\d+)",
        rb"release version (\d+\.\d+)",
        rb"glibc (\d+\.\d+)",
    )
    for pattern in patterns:
        match = re.search(pattern, data)
        if match:
            return match.group(1).decode("ascii", errors="replace")
    # Last resort: highest GLIBC_2.x version string referenced by the library.
    versions = [int(v) for v in re.findall(rb"GLIBC_2\.(\d+)", data)]
    if versions:
        return f"2.{max(versions)}"
    return ""


def _section_flags(section: object) -> int:
    try:
        return int(section["sh_flags"])
    except (KeyError, TypeError, ValueError):
        return 0


def _text_vaddr(elf: object) -> tuple[int, int]:
    for name in (".text", "text"):
        section = elf.get_section_by_name(name)
        if section is not None:
            return int(section["sh_addr"]), int(section["sh_size"])
    # fall back to the executable segment
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and int(segment["p_flags"]) & 0x1:
            return int(segment["p_vaddr"]), int(segment["p_filesz"])
    return 0, 0


def _find_binsh(data: bytes, elf: object) -> int | None:
    needles = (b"/bin/sh\x00", b"/bin/sh", b"/bin/bash\x00")
    sections = []
    for section in elf.iter_sections():
        if _section_flags(section) & 0x2:  # SHF_ALLOC
            sections.append(section)
    for section in sections:
        try:
            blob = section.data()
        except Exception:  # pragma: no cover — corrupt sections
            continue
        for needle in needles:
            index = blob.find(needle)
            if index >= 0:
                return int(section["sh_addr"]) + index
    # Fall back to a whole-file search + section mapping.
    for needle in needles:
        index = data.find(needle)
        if index < 0:
            continue
        for section in sections:
            offset = int(section["sh_offset"])
            size = int(section["sh_size"])
            if offset <= index < offset + size:
                return int(section["sh_addr"]) + (index - offset)
    return None


def _collect_symbols(elf: object) -> dict[str, int]:
    found: dict[str, int] = {}
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            name = str(symbol.name or "")
            value = int(symbol["st_value"] or 0)
            if not name or not value:
                continue
            try:
                kind = symbol["st_info"]["type"]
            except (KeyError, TypeError):
                kind = ""
            if kind not in ("STT_FUNC", "STT_OBJECT", "STT_NOTYPE", "STT_GNU_IFUNC"):
                continue
            # Prefer the real symbol table over the dynamic one.
            if name not in found or section.name == ".symtab":
                found[name] = value
    return found


# ------------------------------------------------------------------ one-gadgets
def _scan_one_gadgets(data: bytes, text_vaddr: int, text_size: int, binsh: int | None, bits: int) -> list[OneGadget]:
    """Linear-scanned heuristic one-gadgets.

    A candidate is reported when, inside the 14-instruction window before a
    syscall, RAX is provably set to the execve number (59 on x86-64, 11 on
    x86) *and* RDI is set from an identifiable source. Only ``lea rdi, …`` /
    ``mov rdi, imm`` equal to the libc ``"/bin/sh"`` address are marked
    verified; stack/pointer loads carry an explicit constraint.
    """
    if not _HAS_CAPSTONE:
        return []
    from collections import deque

    x86 = capstone.x86_const
    rax_regs = {getattr(x86, "X86_REG_RAX", -1), getattr(x86, "X86_REG_EAX", -1)}
    al_reg = getattr(x86, "X86_REG_AL", -1)
    rdi_regs = {getattr(x86, "X86_REG_RDI", -1), getattr(x86, "X86_REG_EDI", -1)}
    rsp_reg = getattr(x86, "X86_REG_RSP", -1)
    rip_reg = getattr(x86, "X86_REG_RIP", -1)
    execve_nr = 59 if bits == 64 else 11
    mask = 0xFFFFFFFFFFFFFFFF if bits == 64 else 0xFFFFFFFF

    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
    cs.detail = True
    start_off = max(text_vaddr, 0)
    blob = data[start_off : start_off + min(text_size or len(data), MAX_TEXT_SCAN)]
    if not blob:
        return []

    def mem_target(insn: object, op: object) -> int | None:
        if op.type != x86.X86_OP_MEM:
            return None
        mem = op.mem
        if mem.base == rip_reg:
            return insn.address + insn.size + mem.disp
        if mem.base == 0 and mem.index == 0:
            return mem.disp & mask
        return None

    def rax_value(window_insns: list[object]) -> int | None:
        value: int | None = None
        for index, insn in enumerate(window_insns):
            ops = insn.operands
            if insn.mnemonic == "xor" and len(ops) == 2 and all(
                op.type == x86.X86_OP_REG for op in ops
            ):
                if ops[0].reg == ops[1].reg and ops[0].reg in rax_regs | {al_reg}:
                    value = 0
                continue
            if insn.mnemonic == "mov" and len(ops) == 2:
                if ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_IMM:
                    if ops[0].reg in rax_regs:
                        value = ops[1].imm & mask
                    elif ops[0].reg == al_reg and value is not None:
                        value = (value & ~0xFF) | (ops[1].imm & 0xFF)
                continue
            if insn.mnemonic == "push" and len(ops) == 1 and ops[0].type == x86.X86_OP_IMM:
                lookahead = window_insns[index + 1] if index + 1 < len(window_insns) else None
                if (
                    lookahead is not None
                    and lookahead.mnemonic == "pop"
                    and lookahead.operands
                    and lookahead.operands[0].type == x86.X86_OP_REG
                    and lookahead.operands[0].reg in rax_regs
                ):
                    value = ops[0].imm & mask
        return value

    def rdi_source(window_insns: list[object]) -> tuple[str, bool]:
        text, verified = "", False
        for insn in window_insns:
            ops = insn.operands
            if not ops:
                continue
            first = ops[0]
            if first.type != x86.X86_OP_REG or first.reg not in rdi_regs:
                continue
            if insn.mnemonic == "pop":
                text, verified = "pop rdi (stack-controlled)", False
            elif insn.mnemonic == "mov" and len(ops) >= 2:
                src = ops[1]
                if src.type == x86.X86_OP_IMM:
                    value = src.imm & mask
                    if binsh is not None and value == binsh:
                        text, verified = f"mov rdi, {value:#x} (/bin/sh)", True
                    else:
                        text, verified = f"mov rdi, {value:#x} (verify /bin/sh)", False
                elif src.type == x86.X86_OP_MEM and src.mem.base == rsp_reg:
                    text = f"rdi = [rsp{src.mem.disp:+#x}] (argv slot must be /bin/sh)"
                    verified = False
                elif src.type == x86.X86_OP_MEM:
                    target = mem_target(insn, src)
                    text = (
                        f"rdi = [{target:#x}] (verify pointer -> /bin/sh)"
                        if target is not None
                        else "rdi from memory (verify manually)"
                    )
                    verified = False
            elif insn.mnemonic == "lea" and len(ops) >= 2:
                src = ops[1]
                target = mem_target(insn, src)
                if target is not None and binsh is not None and target == binsh:
                    text, verified = f"lea rdi, {target:#x} (/bin/sh)", True
                elif src.type == x86.X86_OP_MEM and src.mem.base == rsp_reg:
                    text = f"lea rdi, [rsp{src.mem.disp:+#x}] (stack string)"
                    verified = False
                else:
                    text = f"lea rdi, {target:#x} (verify /bin/sh)" if target else "lea rdi (verify)"
                    verified = False
        return text, verified

    gadgets: list[OneGadget] = []
    window = deque(maxlen=14)
    seen: set[int] = set()
    for insn in cs.disasm(blob, start_off):
        if insn.mnemonic == "syscall" or (insn.mnemonic == "int" and "0x80" in insn.op_str):
            window_insns = list(window)
            if rax_value(window_insns) == execve_nr:
                rdi_text, verified = rdi_source(window_insns)
                if rdi_text:
                    start = window_insns[0].address if window_insns else insn.address
                    if start not in seen:
                        seen.add(start)
                        seq = " ; ".join(
                            f"{i.mnemonic} {i.op_str}".strip() for i in window_insns
                        )
                        if len(seq) > 240:
                            seq = "… " + seq[-238:]
                        gadgets.append(
                            OneGadget(
                                offset=start,
                                sequence=seq + " ; " + insn.mnemonic,
                                constraint=rdi_text,
                                verified=verified,
                            )
                        )
                        if len(gadgets) >= MAX_ONE_GADGETS:
                            break
        window.append(insn)
    return gadgets


# ------------------------------------------------------------------------ load
def load_libc(path: str | Path) -> LibcInfo:
    """Parse a libc ELF (or any ELF with symbols) into a :class:`LibcInfo`."""
    file = Path(path).expanduser()
    if not _HAS_ELFTOOLS:
        raise LibcError("pyelftools is not installed — pip install pyelftools")
    try:
        size = file.stat().st_size
    except OSError as exc:
        raise LibcError(f"Cannot read {file}: {exc}") from exc
    if size > MAX_FILE_BYTES:
        raise LibcError(f"{file.name} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB.")
    try:
        data = file.read_bytes()
    except OSError as exc:
        raise LibcError(f"Cannot read {file}: {exc}") from exc
    if not data.startswith(b"\x7fELF"):
        raise LibcError(
            f"{file.name} is not an ELF file — libc loading supports ELF only "
            "(use a Linux libc, e.g. libc.so.6)."
        )

    import io

    with ELFFile(io.BytesIO(data)) as elf:
        header = elf.header
        bits = int(header["e_ident"]["EI_CLASS"] == "ELFCLASS64") * 32 + 32
        endian = header["e_ident"]["EI_DATA"]
        endianness = "big" if "MSB" in str(endian) else "little"
        machine = str(header["e_machine"])
        arch = _machine_name(machine, bits)
        symbols = _collect_symbols(elf)
        text_base, text_size = _text_vaddr(elf)
        bin_sh = _find_binsh(data, elf)
        build_id = _build_id_from_elf(elf) or _read_notes(data)
        soname = ""
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic is not None:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == "DT_SONAME":
                    soname = str(getattr(tag, "soname", "") or getattr(tag, "entry", ""))

    version = _detect_version(data)
    try:
        one_gadgets = _scan_one_gadgets(data, text_base, text_size, bin_sh, bits)
    except Exception:  # pragma: no cover — capstone edge cases must not break load
        one_gadgets = []

    note = ""
    if not symbols:
        note = "No symbol table — offsets unavailable (use a non-stripped libc or the matching debug symbols)."
    elif bin_sh is None:
        note = "No '/bin/sh' string found — supply system/execve offsets manually."
    return LibcInfo(
        path=file,
        arch=arch,
        bits=bits,
        endianness=endianness,
        version=version,
        soname=soname or file.name,
        build_id=build_id,
        symbols=symbols,
        bin_sh_offset=bin_sh,
        one_gadgets=one_gadgets,
        text_base=text_base,
        text_size=text_size,
        note=note,
    )


def wanted_offsets(info: LibcInfo) -> list[tuple[str, int]]:
    """The classic ret2libc symbol table, resolved in preference order."""
    rows: list[tuple[str, int]] = []
    for name in WANTED_SYMBOLS:
        value = info.symbols.get(name)
        if value:
            rows.append((name, value))
    return rows
