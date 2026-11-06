# 80PWNER — by Anas Mahfouz (The80)

"""Unit tests for the pwntools-compatible cyclic pattern engine.

Ground truth: hardcoded values from the upstream pwnlib doctests
(pwnlib is deliberately NOT installed in this venv), plus algorithmic
properties (every n-window occurs once, chunk arithmetic, wrap behaviour).
"""

from __future__ import annotations

import itertools
import time

import pytest

from eightypwner.engines.pattern import (
    LOWERCASE,
    cyclic,
    cyclic_find,
    de_bruijn,
    lookup,
    parse_value,
    suggest_offset,
)

# ------------------------------------------------- pwntools doctest ground truth

def test_cyclic_matches_pwnlib_docs() -> None:
    assert cyclic(20) == b"aaaabaaacaaadaaaeaaa"
    assert cyclic(32) == b"aaaabaaacaaadaaaeaaafaaagaaahaaa"
    assert cyclic(20, n=8) == b"aaaaaaaabaaaaaaacaaa"
    assert cyclic(20, n=2) == b"aabacadaeafagahaiaja"


def test_de_bruijn_alphabet_and_n_variants() -> None:
    got = "".join(itertools.islice(de_bruijn("ABC", 3), 27)).encode()
    assert got == b"AAABAACABBABCACBACCBBBCBCCC"  # pwnlib docstring


def test_cyclic_find_matches_pwnlib_docs() -> None:
    assert cyclic_find(b"baaa") == 4
    assert cyclic_find(b"caaa") == 8
    assert cyclic_find(b"aaaa") == 0
    assert cyclic_find(b"baaacaaa") == 4  # truncated to n
    assert cyclic_find(0x61616162) == 4
    assert cyclic_find(0x6161616361616162) == 4  # big int low-n truncation
    assert cyclic_find(cyclic(1000)[514:518]) == 514


def test_cyclic_find_n8_matches_pwnlib_docs() -> None:
    t0 = time.monotonic()
    assert cyclic_find(b"baaacaaa", n=8) == 3515208
    assert time.monotonic() - t0 < 30.0  # one-time 16M-char materialization


def test_cyclic_find_not_found() -> None:
    assert cyclic_find(b"\xff\xff\xff\xff") == -1              # not in alphabet
    assert cyclic_find(b"aaa\x00") == -1
    assert cyclic_find(b"") == -1
    assert cyclic_find(-1) == -1
    # a chunk that wraps the period end exists only cyclically — linear find misses
    pattern = cyclic(len(LOWERCASE) ** 4)
    straddle = pattern[-3:] + pattern[:1]
    assert cyclic_find(straddle) == -1


def test_cyclic_find_short_chunks() -> None:
    # shorter-than-n chunks search as-is, substring anywhere
    assert cyclic_find(b"baa") == 4
    assert cyclic_find(b"a") == 0
    assert cyclic_find(b"aaab") == 1


# ------------------------------------------------- properties

def test_every_window_occurs_once() -> None:
    pattern = cyclic(len(LOWERCASE) ** 4)
    # chunk i at offset 4i for the first letters (verified pwntools semantics…)
    for i in range(5):
        chunk = bytes([ord("a") + i]) + b"aaa"
        assert cyclic_find(chunk) == 4 * i
        assert pattern[4 * i : 4 * i + 4] == chunk
    assert len(pattern) == 456976 == len(LOWERCASE) ** 4


def test_cyclic_length_rules() -> None:
    assert cyclic(0) == b""
    assert cyclic(6) == b"aaaaba"
    assert len(cyclic(None, n=3)) == len(LOWERCASE) ** 3
    with pytest.raises(ValueError, match="period"):
        cyclic(len(LOWERCASE) ** 4 + 1)


def test_generation_beyond_materialize_cap_is_lazy() -> None:
    head = cyclic(64, n=8)  # materializing the full period would need 208 GB
    assert len(head) == 64
    assert head[:20] == b"aaaaaaaabaaaaaaacaaa"


# ------------------------------------------------- parse_value

def test_parse_value_forms() -> None:
    assert parse_value("0x61616162") == 0x61616162
    assert parse_value("100") == 100
    assert parse_value("-5") == -5
    assert parse_value("61 61 61 62") == int.from_bytes(bytes.fromhex("61616162"), "little")
    assert parse_value("61616162") == 61616162  # all digits → decimal
    assert parse_value("6a 6a") == int.from_bytes(bytes.fromhex("6a6a"), "little")
    assert parse_value("baaa") == int.from_bytes(b"baaa", "little")
    assert parse_value("") is None
    assert parse_value("&&&") is None


# ------------------------------------------------- lookup

def test_lookup_finds_all_input_styles() -> None:
    off, why = lookup("baaa")
    assert off == 4 and "baaa" in why
    off, why = lookup("0x61616162")
    assert off == 4
    off, why = lookup("61 61 61 62")  # spaced byte pairs → 'aaab' → 1
    assert off == 1
    off, _ = lookup("100")
    assert off == -1  # '\x64...' never alphabet data


def test_lookup_not_found_and_unparseable() -> None:
    off, why = lookup("0xffffffff")  # parseable value, but not alphabet data
    assert off == -1 and "pattern" in why.lower()
    off, why = lookup("&&&&")
    assert off == -1 and "parseable" in why.lower()


def test_lookup_ascii_prefix_wins_like_pwntools() -> None:
    assert lookup("baaad")[0] == 4          # truncated like cyclic_find
    assert lookup("aaaaaaaa")[0] == 0


# ------------------------------------------------- suggest_offset (bus helper)

def test_suggest_offset_best_register() -> None:
    # rbp holds 0x6161616261616161 → chunks 'aaab'@1 'aaba'@2 'baaa'@4 'aaaa'@0
    got = suggest_offset({"rbp": "0x6161616261616161"})
    assert got == (0, "rbp chunk 'aaaa'")
    # plain 32-bit style hex string values
    got = suggest_offset({"rsp": "0x61616161"})
    assert got == (0, "rsp chunk 'aaaa'")


def test_suggest_offset_skips_garbage() -> None:
    assert suggest_offset({"rax": "0x00000000"}) is None
    assert suggest_offset({}) is None
    assert suggest_offset({"rip": "not-a-value", "rdi": "0xz"}) is None
    # a real crash value among junk still wins
    got = suggest_offset({"rip": "junk", "rdi": 0x61616162, "rbx": "0x41414141"})
    assert got is not None and got[0] == 4 and got[1].startswith("rdi")


def test_suggest_offset_smaller_offset_wins() -> None:
    # rdi has 'baaa' (4), rax has 'caaa' (8) → rdi wins
    got = suggest_offset({"rax": 0x61616163, "rdi": 0x61616162})
    assert got == (4, "rdi chunk 'baaa'")
