# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""ROP-chain builder tests using fabricated gadgets."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from eightypwner.engines.ropchain import (
    RopChain,
    chain_from_addresses,
    find_exact,
    find_pop_ret,
    ret2libc_chain,
    syscall_chain,
)


@dataclass(frozen=True)
class FakeGadget:
    address: int
    size: int
    insns: str


GADGETS = [
    FakeGadget(0x401100, 2, "pop rdi ; ret"),
    FakeGadget(0x401102, 2, "pop rsi ; ret"),
    FakeGadget(0x401104, 2, "pop rdx ; ret"),
    FakeGadget(0x401106, 2, "pop rax ; ret"),
    FakeGadget(0x401108, 1, "ret"),
    FakeGadget(0x401109, 2, "syscall"),
    FakeGadget(0x40110B, 2, "pop rbp ; ret"),
    FakeGadget(0x40110D, 5, "pop rdi ; pop rsi ; ret"),
]


def test_find_pop_ret_prefers_shortest_exact():
    gadget = find_pop_ret(GADGETS, "rdi")
    assert gadget is not None
    assert gadget.address == 0x401100
    assert find_pop_ret(GADGETS, "rcx") is None
    assert find_pop_ret(GADGETS, "rdi", max_bytes=1) is None


def test_find_exact():
    assert find_exact(GADGETS, "ret").address == 0x401108
    assert find_exact(GADGETS, "syscall").address == 0x401109
    assert find_exact(GADGETS, "nope") is None


def test_ret2libc_chain_with_alignment():
    chain = ret2libc_chain(GADGETS, binsh=0x7FFFF7F00000, system=0x7FFFF7E00000)
    assert chain.items[0] == 0x401108  # ret for stack alignment
    assert 0x401100 in chain.items
    assert 0x7FFFF7F00000 in chain.items
    assert 0x7FFFF7E00000 in chain.items
    assert chain.labels[0] == "ret (align)"
    assert len(chain.items) == 4


def test_ret2libc_chain_without_alignment():
    chain = ret2libc_chain(
        GADGETS, binsh=0x1000, system=0x2000, align=False
    )
    assert chain.items == (0x401100, 0x1000, 0x2000)


def test_ret2libc_requires_pop_rdi():
    with pytest.raises(ValueError, match="pop rdi"):
        ret2libc_chain([FakeGadget(0x401108, 1, "ret")], 0x1000, 0x2000)


def test_syscall_chain_order_and_raw():
    chain = syscall_chain(GADGETS, rax=59, rdi=0x1000, rsi=0, rdx=0)
    assert chain.items[-1] == 0x401109
    assert chain.items[0] == 0x401106  # pop rax
    assert chain.items[1] == 59
    # rsi/rdx are zero and have pop gadgets, so they are still set.
    assert 0x401102 in chain.items and 0x401104 in chain.items
    raw = chain.raw
    assert len(raw) == 8 * len(chain.items)
    assert raw[:8] == (0x401106).to_bytes(8, "little")


def test_syscall_chain_missing_gadget():
    with pytest.raises(ValueError, match="pop rax"):
        syscall_chain([FakeGadget(0x401108, 1, "ret")], rax=1)


def test_chain_rendering():
    chain = chain_from_addresses([0x401000, 0xDEAD], ["main", "value"], bits=64)
    assert "p64(0x401000),  # main" in chain.p64_lines()
    assert "p64(0xdead)" in chain.p64_lines()
    flat = chain.pwn_chain()
    assert "flat(" in flat
    assert "0x401000" in flat
    assert len(chain.raw) == 16


def test_chain_32bit_width():
    chain = chain_from_addresses([0xDEADBEEF], bits=32)
    assert chain.raw == b"\xef\xbe\xad\xde"


def test_chain_dataclass_immutability():
    import dataclasses

    chain = RopChain((1, 2))
    with pytest.raises(dataclasses.FrozenInstanceError):
        chain.items = (3,)  # type: ignore[misc]
