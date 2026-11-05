# 80PWNER — by Anas Mahfouz (The80)

"""Binary parsing engine — static analysis for ELF / PE / Mach-O (spec C+D).

Primary backend: LIEF (parses native formats on every OS). When LIEF is not
installed, ELF files fall back to pyelftools so Overview + checksec keep
working; missing tools surface as ``ParseError`` messages with install hints,
never a crash (spec §7, §8).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

try:
    import lief

    _HAS_LIEF = True
except ImportError:  # pragma: no cover
    lief = None
    _HAS_LIEF = False

try:
    from elftools.elf.elffile import ELFFile

    _HAS_ELFTOOLS = True
except ImportError:  # pragma: no cover
    ELFFile = None
    _HAS_ELFTOOLS = False


class ParseError(Exception):
    """User-facing parse failure (shown in the UI, never a crash)."""


MAX_FILE_READ = 64 * 1024 * 1024  # don't blow up RAM on huge files (spec §8)
MAX_STRINGS = 2000


# ------------------------------------------------------------------ data model
@dataclass(frozen=True)
class Section:
    name: str
    size: int
    vaddr: int
    type: str = ""
    file_offset: int = 0


@dataclass(frozen=True)
class Segment:
    type_name: str  # LOAD, DYNAMIC, GNU_STACK, …
    vaddr: int
    size: int
    flags: str = "---"  # composite rwx
    file_offset: int = 0


@dataclass(frozen=True)
class Symbol:
    name: str
    size: int
    value: int
    origin: str = "symbol"  # symbol | dynsym


@dataclass(frozen=True)
class DangerousCall:
    name: str
    origin: str  # import | symbol
    severity: str  # critical | high | medium
    why: str


@dataclass(frozen=True)
class ChecksecItem:
    name: str
    status: str  # enabled | disabled | unknown
    explanation: str


@dataclass
class BinaryModel:
    path: Path
    fmt: str  # ELF | PE | Mach-O
    arch: str
    bits: int
    endianness: str
    entry_point: int
    sections: list[Section] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    strings: list[tuple[int, str]] = field(default_factory=list)  # (offset, text)
    checksec: list[ChecksecItem] = field(default_factory=list)
    dangerous: list[DangerousCall] = field(default_factory=list)
    parser_backend: str = "lief"

    @property
    def name(self) -> str:
        return self.path.name


# --------------------------------------------------- dangerous functions (§6.1)
# key: (regex, severity, one-line why)
_DANGEROUS: list[tuple[str, re.Pattern[str], str, str]] = [
    ("gets", re.compile(r"^(gets|_gets|__gets|_IO_gets)$"),
     "critical", "Unbounded read — stack smash on any long input."),
    ("system", re.compile(r"^system$"),
     "critical", "Command injection if attacker input reaches the string."),
    ("strcpy", re.compile(r"^strcpy$"),
     "high", "No bounds check — buffer overflow."),
    ("strcat", re.compile(r"^strcat$"),
     "high", "No bounds check — buffer overflow."),
    ("sprintf", re.compile(r"^sprintf$"),
     "high", "Unbounded copy into a fixed buffer."),
    ("vsprintf", re.compile(r"^vsprintf$"),
     "high", "Unbounded copy into a fixed buffer."),
    ("scanf", re.compile(r"^(_?scanf|__isoc99_scanf|__isoc99_vscanf|v?scanf)$"),
     "high", "%s without a width overflows the target buffer."),
    ("popen", re.compile(r"^popen$"),
     "high", "Runs a shell command — same injection risk as system."),
    ("exec", re.compile(r"^exec(l|le|lp|lpe|v|ve|vp|vpe)$"),
     "high", "Executes a path — track where the args come from."),
    ("printf-family", re.compile(r"^(printf|fprintf|snprintf|dprintf|syslog)$"),
     "medium", "Format-string usage — the format argument must be a constant."),
]

_INTERESTING_RE = re.compile(
    r"/bin/sh|/bin/bash|/bin/cat|system|flag|secret|passw|ctf|/home/|libc",
    re.IGNORECASE,
)
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e\t]{5,}")


def extract_strings(data: bytes) -> list[tuple[int, str]]:
    """Extract printable ASCII strings as (file_offset, text), interesting first."""
    hits: list[tuple[int, str]] = []
    for match in _PRINTABLE_RE.finditer(data):
        if len(hits) >= MAX_STRINGS:
            break
        text = match.group().decode("ascii", errors="replace")
        hits.append((match.start(), text))
    hits.sort(key=lambda item: 0 if _INTERESTING_RE.search(item[1]) else 1)
    return hits


def find_dangerous_functions(model: BinaryModel) -> list[DangerousCall]:
    """Scan imports + symbols for dangerous C functions (spec §6.1)."""
    seen: set[str] = set()
    out: list[DangerousCall] = []
    candidates = [(n, "import") for n in model.imports]
    candidates += [(s.name, "symbol") for s in model.symbols]
    for name, origin in candidates:
        if name in seen:
            continue
        seen.add(name)
        for key, regex, severity, why in _DANGEROUS:
            if regex.search(name):
                out.append(
                    DangerousCall(
                        name=key if key != "printf-family" else (name or key),
                        origin=origin,
                        severity=severity,
                        why=why,
                    )
                )
                break
    order = {"critical": 0, "high": 1, "medium": 2}
    out.sort(key=lambda d: order[d.severity])
    return out


# ------------------------------------------------------------ public parse API
def parse_binary(path: Path) -> BinaryModel:
    """Parse any supported format. Raises ParseError with a user-facing message."""
    if not _HAS_LIEF and not _HAS_ELFTOOLS:
        raise ParseError(
            "No binary parser is available.\n"
            "Install one with:\n"
            "  pip install lief          # full support (ELF/PE/Mach-O)\n"
            "  pip install pyelftools    # ELF-only fallback"
        )
    if path is None or not path.is_file():
        raise ParseError(f"File not found: {path}")
    try:
        if path.stat().st_size <= MAX_FILE_READ:
            data = path.read_bytes()
        else:
            data = path.read(MAX_FILE_READ)
            log.info("Huge file %s: strings scan limited to %d bytes", path, len(data))
    except OSError as exc:
        raise ParseError(f"Cannot read {path}: {exc}") from exc

    if _HAS_LIEF:
        raw = lief.parse(str(path))
        if raw is None:
            raise ParseError(
                f"'{path.name}' is not a recognized ELF/PE/Mach-O binary.\n"
                "80PWNER analyzes ELF, PE and Mach-O files."
            )
        return _from_lief(raw, path, data)
    if _looks_like_elf(path):
        return _from_pyelftools(path, data)
    raise ParseError(
        f"'{path.name}' could not be parsed.\n"
        "Install LIEF for PE/Mach-O support:  pip install lief"
    )


def _looks_like_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


# ------------------------------------------------------------------ LIEF backend
def _enum_name(value: object) -> str:
    """'lief._lief.X.FILE_TYPE.DYN' → 'DYN'; plain enums handled too."""
    return str(value).rsplit(".", 1)[-1].strip() if value is not None else ""


_ARCH_MAP = {
    "X86_64": "x86_64",
    "AMD64": "x86_64",
    "X86_32": "x86_32",
    "I386": "x86_32",
    "I486": "x86_32",
    "X86": "x86",
    "ARM64": "aarch64",
    "AARCH64": "aarch64",
    "ARM": "arm",
    "MIPS": "mips",
    "RISCV64": "riscv64",
    "RISCV32": "riscv32",
    "POWERPC64": "ppc64",
    "POWERPC": "ppc",
}


def _nice_arch(raw_name: str) -> str:
    key = raw_name.upper()
    for needle, nice in _ARCH_MAP.items():
        if needle in key:
            return nice
    return raw_name.lower() or "unknown"


def _flags_str(seg: object, fmt: str) -> str:
    """ELF p_flags bitmask (r=4,w=2,x=1); Mach-O VM_PROT (r=1,w=2,x=4); PE r--."""
    if fmt == "PE":
        return "r--"
    raw = getattr(seg, "raw_flags", None)
    try:
        raw = int(raw)
    except (TypeError, ValueError):
        return "---"
    if fmt == "ELF":  # PF_R=4, PF_W=2, PF_X=1
        return "".join(("r" if raw & 4 else "-", "w" if raw & 2 else "-", "x" if raw & 1 else "-"))
    return "".join(("r" if raw & 1 else "-", "w" if raw & 2 else "-", "x" if raw & 4 else "-"))


def _from_lief(raw: object, path: Path, data: bytes) -> BinaryModel:
    fmt_raw = _enum_name(getattr(raw, "format", "?")) or "?"
    fmt = {"ELF": "ELF", "PE": "PE", "MACHO": "Mach-O"}.get(fmt_raw.upper(), fmt_raw)
    header = getattr(raw, "header", None)

    arch_name: str = ""
    bits = 32
    endian = "little"
    entry = 0

    if fmt == "ELF":
        arch_name = _enum_name(getattr(header, "machine_type", ""))
        class_name = _enum_name(getattr(header, "identity_class", ""))
        bits = 64 if "64" in class_name else 32
        data_name = _enum_name(getattr(header, "identity_data", ""))
        endian = "big" if "MSB" in data_name.upper() else "little"
        entry = int(getattr(header, "entrypoint", 0) or 0)
    elif fmt == "PE":
        opt = getattr(raw, "optional_header", None)
        arch_name = _enum_name(getattr(header, "machine", ""))
        bits = 64 if "64" in _enum_name(getattr(opt, "magic", "")) else 32
        entry = int(getattr(opt, "addressof_entrypoint", 0) or 0)
    elif fmt == "Mach-O":
        arch_name = _enum_name(getattr(raw, "cpu_type", getattr(header, "cpu_type", "")))
        if not arch_name:  # fat files list cpu types
            try:
                arch_name = _enum_name(raw.cpu_types[0])
            except (AttributeError, IndexError, TypeError):
                arch_name = ""
        bits = 64 if ("64" in arch_name.upper() or "ARM64" in arch_name.upper()) else 32

    model = BinaryModel(
        path=path,
        fmt=fmt,
        arch=_nice_arch(arch_name),
        bits=bits,
        endianness=endian,
        entry_point=entry,
        parser_backend="lief",
    )
    _lief_sections(raw, model)
    _lief_segments(raw, model, fmt)
    _lief_symbols(raw, model)
    model.strings = extract_strings(data)
    model.checksec = _checksec(fmt, raw)
    model.dangerous = find_dangerous_functions(model)
    return model


def _lief_sections(raw: object, model: BinaryModel) -> None:
    for section in getattr(raw, "sections", []) or []:
        model.sections.append(
            Section(
                name=str(section.name),
                size=int(section.size),
                vaddr=int(getattr(section, "virtual_address", 0) or 0),
                type=_enum_name(getattr(section, "type", "")) or "content",
                file_offset=int(getattr(section, "offset", 0) or 0),
            )
        )


def _lief_segments(raw: object, model: BinaryModel, fmt: str) -> None:
    segments = getattr(raw, "segments", None)
    if segments is None:  # PE has no program headers; sections carry the info
        return
    for seg in segments:
        if fmt == "Mach-O":
            type_name = str(getattr(seg, "name", "") or "segment")
        else:
            type_name = _enum_name(getattr(seg, "type", "")) or "?"
        model.segments.append(
            Segment(
                type_name=type_name,
                vaddr=int(getattr(seg, "virtual_address", 0) or 0),
                size=int(getattr(seg, "virtual_size", getattr(seg, "size", 0)) or 0),
                flags=_flags_str(seg, fmt),
            )
        )


def _lief_symbols(raw: object, model: BinaryModel) -> None:
    for sym in getattr(raw, "symbols", None) or []:
        name = str(getattr(sym, "name", "")).strip()
        if not name:
            continue
        model.symbols.append(
            Symbol(
                name=name,
                size=int(getattr(sym, "size", 0) or 0),
                value=int(getattr(sym, "value", 0) or 0),
            )
        )
    model.imports = [
        str(getattr(i, "name", "")).strip()
        for i in getattr(raw, "imported_symbols", None) or []
        if str(getattr(i, "name", "")).strip()
    ]
    model.exports = [
        str(getattr(e, "name", "")).strip()
        for e in getattr(raw, "exported_symbols", None) or []
        if str(getattr(e, "name", "")).strip()
    ]


# --------------------------------------------------------------------- checksec
def _checksec(fmt: str, raw: object) -> list[ChecksecItem]:
    if fmt == "ELF":
        return _checksec_elf(raw)
    if fmt == "PE":
        return _checksec_pe(raw)
    if fmt == "Mach-O":
        return _checksec_macho(raw)
    return []


def _checksec_elf(raw: object) -> list[ChecksecItem]:
    seg_meta: list[tuple[str, str]] = []
    for seg in getattr(raw, "segments", []) or []:
        seg_meta.append((_enum_name(getattr(seg, "type", "")), _flags_str(seg, "ELF")))

    has_gnu_stack = any(t == "GNU_STACK" for t, _ in seg_meta)

    # NX: PT_GNU_STACK not executable → NX enabled.
    x_on_stack: bool | None = None
    for t, flags in seg_meta:
        if t == "GNU_STACK":
            x_on_stack = "x" in flags
    if not has_gnu_stack:
        nx = ChecksecItem("NX", "unknown", "PT_GNU_STACK header missing — old/unknown toolchain.")
    elif x_on_stack:
        nx = ChecksecItem("NX", "disabled", "Stack is executable (PT_GNU_STACK X) — shellcode runs from memory.")
    else:
        nx = ChecksecItem("NX", "enabled", "Stack is non-executable — ret2libc / ROP needed instead of shellcode.")

    # PIE: ET_DYN with an INTERP entry (loaded as program) == PIE; EXEC == no PIE.
    file_type = _enum_name(getattr(getattr(raw, "header", None), "file_type", ""))
    has_interp = any(t == "INTERP" for t, _ in seg_meta)
    if file_type == "DYN" and has_interp:
        pie = ChecksecItem("PIE", "enabled", "Rebased at load (ET_DYN) — absolute addresses must be leaked first.")
    elif file_type == "DYN":
        pie = ChecksecItem("PIE", "unknown", "ET_DYN without INTERP — shared object (or PIE lib-style build).")
    else:
        pie = ChecksecItem("PIE", "disabled", "Fixed load address (ET_EXEC) — addresses in the build are stable/known.")

    # RELRO: GNU_RELRO segment; full = BIND_NOW via DT_BIND_NOW or DF_1_NOW (FLAGS_1).
    has_relro = any(t == "GNU_RELRO" for t, _ in seg_meta)
    bind_now = False
    for entry in getattr(raw, "dynamic_entries", []) or []:
        tag = str(getattr(entry, "tag", ""))
        try:
            value = int(getattr(entry, "value", 0) or 0)
        except (TypeError, ValueError):
            value = 0
        if tag.endswith("BIND_NOW") or (tag.endswith("FLAGS_1") and value & 0x08000000) or (tag.endswith("FLAGS") and value & 0x0008):
            bind_now = True
    if has_relro and bind_now:
        relro = ChecksecItem("RELRO", "enabled", "Full RELRO + BIND_NOW — GOT is read-only after relocation.")
    elif has_relro:
        relro = ChecksecItem("RELRO", "unknown", "Partial RELRO — GOT is still writable (GOT overwrite possible).")
    else:
        relro = ChecksecItem("RELRO", "disabled", "No GNU_RELRO — GOT overwrite with no relocation hardening.")

    # Canary: __stack_chk_fail / __stack_chk_guard present.
    sym_names = [str(getattr(s, "name", "")).strip() for s in getattr(raw, "symbols", []) or []]
    imp_names = [str(getattr(i, "name", "")).strip() for i in getattr(raw, "imported_symbols", []) or []]
    all_names = sym_names + imp_names
    if any(n.startswith("__stack_chk") for n in all_names):
        canary = ChecksecItem("Stack canary", "enabled", "__stack_chk_* wired in — overrunning the canary aborts.")
    else:
        canary = ChecksecItem("Stack canary", "disabled", "No __stack_chk_* — smashed stack is detected by nothing.")

    # Fortify: *_chk wrappers other than stack_chk.
    fortified = [n for n in all_names if n.endswith("_chk") and not n.startswith("__stack_chk")]
    if fortified:
        fortify = ChecksecItem("Fortify", "enabled",
                               f"Bounded FORTIFY_SOURCE wrappers present ({', '.join(sorted(set(fortified))[:3])}).")
    else:
        fortify = ChecksecItem("Fortify", "disabled",
                               "No *_chk fortified libc wrappers in this build.")

    return [nx, pie, relro, canary, fortify]


def _checksec_pe(raw: object) -> list[ChecksecItem]:
    # LIEF exposes DllCharacteristics on the header; bits are gettable via int().
    dll = getattr(getattr(raw, "header", None), "dll_characteristics", None)
    try:
        dll_bits = int(dll)
    except (TypeError, ValueError):
        dll_bits = 0

    if dll_bits & 0x0100:  # NX_COMPAT
        nx = ChecksecItem("NX", "enabled", "IMAGE_DLLCHARACTERISTICS NX_COMPAT — stack pages are DEP/data-protected.")
    else:
        nx = ChecksecItem("NX", "disabled", "NX_COMPAT clear — DEP not requested for stack/data pages.")
    if dll_bits & 0x0040:  # DYNAMIC_BASE
        aslr = ChecksecItem("PIE", "enabled", "DYNAMIC_BASE — image base is randomized by the loader (ASLR).")
    else:
        aslr = ChecksecItem("PIE", "disabled", "DYNAMIC_BASE clear — image loads at its preferred base every run.")

    names = [str(getattr(s, "name", "")).strip() for s in getattr(raw, "symbols", []) or []]
    imports = [str(getattr(i, "name", "")).strip() for i in getattr(raw, "imported_symbols", []) or []]
    all_names = names + imports
    canary = (
        ChecksecItem("Stack canary", "enabled", "__security_cookie/check present (MSVC /GS).")
        if any("__security" in n for n in all_names)
        else ChecksecItem("Stack canary", "unknown", "No __security_cookie in symbols — /GS state unknown (stripped?).")
    )
    relro = ChecksecItem("RELRO", "unknown", "RELRO is an ELF mechanism — not applicable to PE.")
    fortify = ChecksecItem("Fortify", "unknown", "Fortify is a libc/ELF concept — check CRT hardening flags instead.")
    return [nx, aslr, relro, canary, fortify]


def _checksec_macho(raw: object) -> list[ChecksecItem]:
    header = getattr(raw, "header", None)
    flags = getattr(header, "flags", None)
    try:
        pie_on = any(_enum_name(f) == "MH_PIE" for f in flags)
    except TypeError:
        pie_on = False
    pie = (
        ChecksecItem("PIE", "enabled", "MH_PIE set — image base randomized by dyld.")
        if pie_on
        else ChecksecItem("PIE", "disabled", "No MH_PIE flag — image loads at its fixed base.")
    )
    nx = ChecksecItem("NX", "enabled", "macOS enforces per-page W^X for mapped images.")
    relro = ChecksecItem("RELRO", "unknown", "RELRO is an ELF mechanism — not applicable to Mach-O.")
    names = [str(getattr(s, "name", "")).strip() for s in getattr(raw, "symbols", []) or []]
    canary = (
        ChecksecItem("Stack canary", "enabled", "__stack_chk_fail wired in (libSystem).")
        if any(n.startswith("__stack_chk") for n in names)
        else ChecksecItem("Stack canary", "unknown", "No __stack_chk symbol — stripped or canary-free build.")
    )
    fortify = ChecksecItem("Fortify", "unknown", "Fortify is a libc/ELF concept — macOS uses macro-based variants.")
    return [nx, pie, relro, canary, fortify]


# --------------------------------------------------------- pyelftools fallback
def _from_pyelftools(path: Path, data: bytes) -> BinaryModel:
    """ELF-only fallback when LIEF is missing (keeps Overview + checksec alive)."""
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        is64 = elf.elfclass == 64
        endian = "big" if "MSB" in elf.get_machine_arch() or elf.little_endian is False else "little"
        arch_code = elf.header.e_machine
        arch_name = {
            62: "X86_64", 3: "I386", 183: "AARCH64", 40: "ARM",
            8: "MIPS", 20: "POWERPC", 21: "POWERPC64", 243: "RISCV64",
        }.get(int(arch_code), f"EM{arch_code}")
        model = BinaryModel(
            path=path,
            fmt="ELF",
            arch=_nice_arch(arch_name),
            bits=64 if is64 else 32,
            endianness=endian,
            entry_point=int(elf.header.e_entry),
            parser_backend="pyelftools",
        )
        for section in elf.iter_sections():
            model.sections.append(
                Section(
                    name=section.name,
                    size=int(section["sh_size"]),
                    vaddr=int(section["sh_addr"]),
                    type=section["sh_type"] if isinstance(section["sh_type"], str) else "",
                    file_offset=int(section["sh_offset"]),
                )
            )
        for seg in elf.iter_segments():
            p_type = seg["p_type"] if isinstance(seg["p_type"], str) else str(seg["p_type"])
            flags_int = int(seg["p_flags"])
            model.segments.append(
                Segment(
                    type_name=str(p_type).replace("PT_", ""),
                    vaddr=int(seg["p_vaddr"]),
                    size=int(seg["p_filesz"]),
                    flags=(
                        "r" if flags_int & 0x4 else "-"
                    ) + (
                        "w" if flags_int & 0x2 else "-"
                    ) + (
                        "x" if flags_int & 0x1 else "-"
                    ),
                    file_offset=int(seg["p_offset"]),
                )
            )
        # symbols: symtab first, then dynsym; SHN_UNDEF dynamic ones are imports
        for table_name in (".symtab", ".dynsym"):
            table = elf.get_section_by_name(table_name)
            if table is None:
                continue
            for sym in table.iter_symbols():
                name = sym.name
                if not name:
                    continue
                model.symbols.append(
                    Symbol(
                        name=name,
                        size=int(sym["st_size"]),
                        value=int(sym["st_value"]),
                        origin="dynsym" if table_name == ".dynsym" else "symbol",
                    )
                )
                if table_name == ".dynsym":
                    if sym["st_shndx"] == "SHN_UNDEF":
                        model.imports.append(name)
                    else:
                        model.exports.append(name)
    model.strings = extract_strings(data)
    model.checksec = _pyelftools_checksec(model)
    model.dangerous = find_dangerous_functions(model)
    return model


def _pyelftools_checksec(model: BinaryModel) -> list[ChecksecItem]:
    """Build the same 5-Item checksec list from what we collected."""
    seg_types = [s.type_name for s in model.segments]
    seg_flags = {s.type_name: s.flags for s in model.segments}
    stack_flags = seg_flags.get("GNU_STACK", "")

    if "GNU_STACK" not in seg_types:
        nx = ChecksecItem("NX", "unknown", "PT_GNU_STACK header missing — old/unknown toolchain.")
    elif "x" in stack_flags:
        nx = ChecksecItem("NX", "disabled", "Stack is executable — shellcode runs from memory.")
    else:
        nx = ChecksecItem("NX", "enabled", "Stack is non-executable — ROP/ret2libc needed instead.")

    pie_like = "EXEC" not in seg_types and model.entry_point and "INTERP" in seg_types
    if "INTERP" in seg_types and model.fmt == "ELF":
        # no direct e_type in our model — approximate via segments seen
        pie = (
            ChecksecItem("PIE", "unknown", "Fallback parser: PIE state approximated.")
            if not pie_like
            else ChecksecItem("PIE", "enabled", "Rebased at load — absolute addresses must be leaked.")
        )
    else:
        pie = ChecksecItem("PIE", "disabled", "Likely fixed load address (ET_EXEC-style build).")

    has_relro = "GNU_RELRO" in seg_types
    relro = (
        ChecksecItem("RELRO", "unknown", "Partial relro detected (BIND_NOW needs LIEF).")
        if has_relro
        else ChecksecItem("RELRO", "disabled", "No GNU_RELRO — GOT is writable.")
    )
    all_names = [s.name for s in model.symbols] + model.imports
    canary = (
        ChecksecItem("Stack canary", "enabled", "__stack_chk_* wired in.")
        if any(n.startswith("__stack_chk") for n in all_names)
        else ChecksecItem("Stack canary", "disabled", "No __stack_chk_* symbols.")
    )
    fortify_names = [n for n in all_names if n.endswith("_chk") and not n.startswith("__stack_chk")]
    fortify = (
        ChecksecItem("Fortify", "enabled", f"Bounded wrappers present ({', '.join(sorted(set(fortify_names))[:3])}).")
        if fortify_names
        else ChecksecItem("Fortify", "disabled", "No *_chk fortified libc wrappers.")
    )
    return [nx, pie, relro, canary, fortify]
