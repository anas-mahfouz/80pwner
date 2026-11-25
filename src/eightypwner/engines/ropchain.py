# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""ROP chain builder on top of the gadget scanner (Step 7 support).

Given the gadgets already found by the Gadget Finder (or a fresh scan), pick
the canonical ``pop reg ; ret`` gadgets and assemble common chains:

* ``ret2libc`` — alignment ret + pop rdi + system + "/bin/sh"
* ``syscall``  — pop rax/rsi/rdx/rdi + syscall with chosen arguments

Returns both raw bytes and pwntools-style ``p64(...)`` lines so the result can
be pasted into an exploit or a Generated script.
Pure engine: no Qt.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

MAX_CHAIN_BYTES = 4096

_POP_RET_RE = re.compile(r"^pop (\w+) ; ret$")
_REG_ALIASES = {
    "rax": ("rax", "eax", "ax", "al"),
    "rdi": ("rdi", "edi", "di"),
    "rsi": ("rsi", "esi", "si"),
    "rdx": ("rdx", "edx", "dx"),
    "rcx": ("rcx", "ecx", "cx"),
    "rbx": ("rbx", "ebx", "bx"),
    "rbp": ("rbp", "ebp"),
    "rsp": ("rsp", "esp"),
    "r8": ("r8", "r8d"),
    "r9": ("r9", "r9d"),
    "r12": ("r12", "r12d"),
}


@dataclass(frozen=True)
class RopChain:
    items: tuple[int, ...]
    bits: int = 64
    labels: tuple[str, ...] = ()
    note: str = ""

    @property
    def raw(self) -> bytes:
        width = self.bits // 8
        out = b""
        for item in self.items:
            out += int(item).to_bytes(width, "little", signed=False)
        return out

    def p64_lines(self) -> str:
        width = self.bits // 8
        name = "p64" if width == 8 else "p32"
        lines = []
        for index, item in enumerate(self.items):
            label = self.labels[index] if index < len(self.labels) and self.labels[index] else ""
            suffix = f"  # {label}" if label else ""
            lines.append(f"{name}({item:#x}),{suffix}")
        return "payload  = b''\n" + "".join(f"payload += {line}\n" for line in lines)

    def pwn_chain(self) -> str:
        """pwntools `flat(...)` line."""
        return "payload = flat(\n" + "".join(
            f"    {item:#x},  # {self.labels[i] if i < len(self.labels) else ''}\n"
            for i, item in enumerate(self.items)
        ) + ")"


def _gadget_text(gadget: object) -> str:
    return str(getattr(gadget, "insns", "")).strip()


def find_pop_ret(
    gadgets: Iterable[object],
    register: str,
    max_bytes: int = 0,
) -> object | None:
    """Shortest exact ``pop <register> ; ret`` gadget, or None."""
    wanted = {alias.lower() for alias in _REG_ALIASES.get(register.lower(), (register.lower(),))}
    best: object | None = None
    best_size = 10**9
    for gadget in gadgets:
        match = _POP_RET_RE.match(_gadget_text(gadget).lower())
        if not match or match.group(1) not in wanted:
            continue
        size = int(getattr(gadget, "size", 0) or 0)
        if max_bytes and size > max_bytes:
            continue
        if size < best_size:
            best, best_size = gadget, size
    return best


def find_exact(gadgets: Iterable[object], text: str, max_bytes: int = 0) -> object | None:
    """Shortest gadget whose full text matches *text* (case-insensitive)."""
    needle = text.strip().lower()
    best: object | None = None
    best_size = 10**9
    for gadget in gadgets:
        if _gadget_text(gadget).lower() != needle:
            continue
        size = int(getattr(gadget, "size", 0) or 0)
        if max_bytes and size > max_bytes:
            continue
        if size < best_size:
            best, best_size = gadget, size
    return best


def ret2libc_chain(
    gadgets: Iterable[object],
    binsh: int,
    system: int,
    bits: int = 64,
    align: bool = True,
) -> RopChain:
    """``ret(align) + pop rdi; ret + "/bin/sh" + system``."""
    gadget_list = list(gadgets)
    pop_rdi = find_pop_ret(gadget_list, "rdi")
    if pop_rdi is None:
        raise ValueError("No 'pop rdi ; ret' gadget in the scan — scan libc too.")
    ret = find_exact(gadget_list, "ret")
    items: list[int] = []
    labels: list[str] = []
    if align and ret is not None:
        items.append(int(ret.address))
        labels.append("ret (align)")
    items += [int(pop_rdi.address), binsh, system]
    labels += ["pop rdi ; ret", "/bin/sh", "system"]
    note = "" if align and ret is not None else (
        "No standalone 'ret' gadget found — if system() crashes in movaps, add one."
    )
    if len(items) * (bits // 8) > MAX_CHAIN_BYTES:
        raise ValueError("Chain too large")
    return RopChain(tuple(items), bits=bits, labels=tuple(labels), note=note)


def syscall_chain(
    gadgets: Iterable[object],
    *,
    rax: int,
    rdi: int = 0,
    rsi: int = 0,
    rdx: int = 0,
    bits: int = 64,
    syscall_text: str = "syscall",
) -> RopChain:
    """Set rax/rdi/rsi/rdx then invoke syscall, using pop gadgets."""
    gadget_list = list(gadgets)
    needed = [("rax", rax), ("rdi", rdi), ("rsi", rsi), ("rdx", rdx)]
    items: list[int] = []
    labels: list[str] = []
    for register, value in needed:
        gadget = find_pop_ret(gadget_list, register)
        if gadget is None:
            if value == 0:
                continue  # leave whatever is already there; note it
            raise ValueError(f"No 'pop {register} ; ret' gadget for syscall setup.")
        items += [int(gadget.address), int(value) & ((1 << bits) - 1)]
        labels += [f"pop {register} ; ret", f"{register} = {value:#x}"]
    syscall = find_exact(gadget_list, syscall_text) or find_exact(
        gadget_list, syscall_text + " ; ret"
    )
    if syscall is None:
        raise ValueError(f"No '{syscall_text}' gadget in the scan.")
    items.append(int(syscall.address))
    labels.append(syscall_text)
    return RopChain(tuple(items), bits=bits, labels=tuple(labels))


def chain_from_addresses(addresses: list[int], labels: list[str] | None = None, bits: int = 64) -> RopChain:
    """Escape hatch: turn a hand-written address list into a chain."""
    return RopChain(
        tuple(int(address) for address in addresses),
        bits=bits,
        labels=tuple(labels or ()),
    )
