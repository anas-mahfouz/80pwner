# 80PWNER — by Anas Mahfouz (The80)

"""De Bruijn cyclic pattern generator/finder — pwntools-compatible.

Byte-for-byte port of ``pwnlib.util.cyclic`` behaviour (its FKM generator,
verified against upstream doctests): default alphabet "abcdefghijklmnopqrstuvwxyz",
default subsequence size n=4. ``cyclic(20) == b'aaaabaaacaaadaaaeaaa'``,
``cyclic_find(b'baaa') == 4``. Lookup returns **-1** when not found.

Lazy generator keeps n=8 patterns truncatable without materializing
203 GB; offset lookup streams the generator and is exhaustive whenever
the period fits the search cap (n ≤ 5 for the 26-letter alphabet).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import lru_cache

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"

_MAX_SEARCH = 16_000_000  # chars scanned by cyclic_find before giving up


def de_bruijn(alphabet: str = LOWERCASE, n: int = 4) -> Iterator[str]:
    """Lazy FKM (Lyndon words) de Bruijn generator, ported from pwnlib."""
    k = len(alphabet)
    a = [0] * k * n

    def db(t: int, p: int) -> Iterator[str]:
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                yield from db(t + 1, t)

    return db(1, 1)


@lru_cache(maxsize=8)
def _period_bytes(alphabet: str, n: int) -> bytes:
    """Whole (or capped) period materialized once, for fast ``find``."""
    k = len(alphabet)
    period = k**n
    if period <= _MAX_SEARCH:
        return bytes(islice_chars(de_bruijn(alphabet, n), period))
    return bytes(islice_chars(de_bruijn(alphabet, n), _MAX_SEARCH))


def islice_chars(gen: Iterator[str], count: int) -> bytes:
    out = bytearray()
    for i, c in enumerate(gen):
        if i >= count:
            break
        out.append(ord(c) & 0xFF)
    return bytes(out)


def cyclic(length: int | None = None, n: int = 4, alphabet: str = LOWERCASE) -> bytes:
    """First *length* bytes of the de Bruijn pattern (None = whole period)."""
    if n < 1 or not alphabet:
        raise ValueError("n must be >= 1 and the alphabet non-empty")
    period = len(alphabet) ** n
    if length is None:
        length = period
    if length < 0:
        raise ValueError("length must be >= 0")
    if length > period:
        raise ValueError(
            f"Can't create a pattern length={length} with len(alphabet)=={len(alphabet)} "
            f"and n=={n} (period {period})"
        )
    if period <= _MAX_SEARCH:
        return _period_bytes(alphabet, n)[:length]
    return islice_chars(de_bruijn(alphabet, n), length)


def cyclic_find(subseq: bytes | int | str, n: int = 4, alphabet: str = LOWERCASE) -> int:
    """First offset of *subseq* inside the pattern; **-1** when not found.

    Mirrors pwnlib ``cyclic_find``: ints pack little-endian into n bytes
    (oversize ints truncate to the low n bytes); subsequences longer than n
    truncate to n; every byte must belong to the alphabet or the result is
    -1 immediately.
    """
    if n < 1 or not alphabet:
        return -1
    if isinstance(subseq, int):
        if subseq < 0:
            return -1
        if subseq >= 1 << (8 * n):
            subseq &= (1 << (8 * n)) - 1  # little-endian low-n-byte truncation
        subseq = subseq.to_bytes(n, "little")
    if isinstance(subseq, str):
        subseq = subseq.encode(errors="replace")
    subseq = bytes(subseq)
    if not subseq:
        return -1
    if len(subseq) > n:
        subseq = subseq[:n]
    if any(c not in alphabet.encode() for c in subseq):
        return -1
    base = _period_bytes(alphabet, n)
    offset = base.find(subseq)
    return offset  # capped searches only see the first _MAX_SEARCH chars


# ------------------------------------------------------------------ parsing
def parse_value(text: str) -> int | None:
    """User-entered value → int, or None when unparseable.

    ``0x…`` hex, decimal (possibly negative), spaced hex byte-pairs
    ("61 61 61 62" → little-endian int), bare hex-digit runs, and raw ASCII
    chunks ("baaa") are all accepted.
    """
    text = text.strip()
    if not text:
        return None
    if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", text):
        try:
            return int(text, 16)
        except ValueError:
            return None
    if re.fullmatch(r"[+-]?[0-9]+", text):
        try:
            return int(text, 10)
        except ValueError:
            return None
    stripped = text.strip()
    tokens = stripped.split()
    if tokens and all(re.fullmatch(r"[0-9a-fA-F]{2}", t) for t in tokens):
        raw = bytes.fromhex("".join(tokens))
        return int.from_bytes(raw, "little")
    cleaned = stripped.replace(" ", "").replace(",", "")
    if re.fullmatch(r"[0-9a-fA-F]{2}+", cleaned):
        raw = bytes.fromhex(cleaned)
        return int.from_bytes(raw, "little")
    if re.fullmatch(r"[a-zA-Z]+", stripped):
        raw = stripped.encode("ascii", errors="replace")
        return int.from_bytes(raw, "little") if len(raw) <= 8 else None
    return None


def _chunks_for(value: int) -> list[bytes]:
    """Little-endian byte representations of *value* to try lookups with."""
    chunks: list[bytes] = []
    for width in (4, 8):
        if 0 <= value < (1 << (8 * width)):
            chunks.append(value.to_bytes(width, "little"))
    return chunks


def lookup(text: str, n: int = 4, alphabet: str = LOWERCASE) -> tuple[int, str]:
    """Offset lookup from user text → ``(offset, description)``.

    ``offset`` is -1 when the value is not pattern data; *description* then
    carries a hint. Several interpretations of ambiguous input are tried and
    the first non-(-1) offset wins.
    """
    text = text.strip()
    if not text:
        return -1, "Enter a value: hex (0x61616162), decimal, bytes ('61 61 61 62') or ASCII ('baaa')."

    candidates: list[bytes] = []

    value = parse_value(text)
    if value is not None:
        candidates.extend(_chunks_for(value))
    if re.fullmatch(r"[a-zA-Z]+", text):  # ASCII reading wins when plausible
        candidates.append(text.encode("ascii", errors="replace")[:n])

    if not candidates:
        return -1, "Not parseable — hex (0x61616162), decimal, bytes ('61 61 61 62') or ASCII ('baaa')."

    for chunk in candidates:
        off = cyclic_find(chunk, n=n, alphabet=alphabet)
        if off != -1:
            pretty = chunk[: min(8, len(chunk))]
            return off, f"{pretty!r} → offset {off}"
    return -1, (
        f"Not found in the n={n} pattern — the value may not be pattern data, or "
        f"the crash offset exceeds the period ({len(alphabet) ** n})."
    )


def suggest_offset(
    regs: dict[str, str | int], n: int = 4, alphabet: str = LOWERCASE
) -> tuple[int, str] | None:
    """Best (smallest-offset) pattern match in a stopped register dump.

    *regs* maps register name → hex-string ("0x6161616161616162", possibly
    gdb-style "$rax") or int. Every value is sliced little-endian into n-byte
    windows at every byte start; windows made only of alphabet characters are
    looked up, smallest offset wins. Returns ``(offset, "rdi chunk 'baaa'")``
    or None when nothing matches.
    """
    best: tuple[int, str] | None = None
    for name, raw in regs.items():
        value = _to_int(raw)
        if value is None or value < 0:
            continue
        for width in (4, 8):
            if value >= (1 << (8 * width)):
                continue
            data = value.to_bytes(width, "little")
            for start in range(0, width - n + 1):
                chunk = data[start : start + n]
                try:
                    text = chunk.decode("ascii")
                except UnicodeDecodeError:
                    continue
                if not all(c in alphabet for c in text):
                    continue
                off = cyclic_find(chunk, n=n, alphabet=alphabet)
                if off == -1:
                    continue
                cand = (off, f"{name.lstrip('$')} chunk {text!r}")
                if best is None or off < best[0]:
                    best = cand
    return best


def _to_int(raw: str | int | None) -> int | None:
    if isinstance(raw, int):
        return raw
    if not isinstance(raw, str):
        return None
    text = raw.strip().lstrip("$")
    if not text:
        return None
    for base in (0, 16):
        try:
            return int(text, base)
        except ValueError:
            continue
    return None
