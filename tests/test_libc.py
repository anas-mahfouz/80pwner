# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Libc helper tests against the system libc (skipped when unavailable)."""

from __future__ import annotations

from pathlib import Path

import pytest

from eightypwner.engines.libc import (
    LibcError,
    load_libc,
    wanted_offsets,
)

LIBC_CANDIDATES = (
    Path("/usr/lib/libc.so.6"),
    Path("/lib/x86_64-linux-gnu/libc.so.6"),
    Path("/usr/lib64/libc.so.6"),
)


def _system_libc() -> Path:
    for candidate in LIBC_CANDIDATES:
        if candidate.exists():
            return candidate
    pytest.skip("no system libc found")


@pytest.fixture(scope="module")
def info():
    return load_libc(_system_libc())


def test_fingerprint(info):
    assert info.bits in (32, 64)
    assert info.soname
    assert info.arch.startswith(("x86", "aarch64", "arm", "mips", "riscv", "ppc")) or info.arch
    assert info.version.startswith("2."), f"unexpected glibc version {info.version!r}"
    assert "glibc" in info.fingerprint()
    assert _system_libc().name in str(info.path)


def test_core_symbols_present(info):
    assert info.system is not None
    assert info.symbols.get("system") or info.symbols.get("__libc_system")
    assert info.symbols.get("puts")
    assert info.symbols.get("read")
    assert info.symbols.get("write")
    assert info.execve is not None


def test_binsh_offset(info):
    assert info.binsh is not None
    assert info.binsh > 0
    assert info.text_base <= info.binsh < info.text_base + info.text_size + 0x4000000


def test_runtime_math(info):
    base = 0x7F0000000000
    assert info.runtime("system", base) == base + info.system
    assert info.binsh_runtime(base) == base + info.binsh
    leaked = base + info.system
    assert info.base_from_leak("system", leaked) == base
    assert info.base_from_leak("no_such_symbol", leaked) is None


def test_one_gadget_entries_are_sane(info):
    assert isinstance(info.one_gadgets, list)
    for gadget in info.one_gadgets:
        assert gadget.offset > 0
        assert gadget.sequence
        assert gadget.constraint
        assert "syscall" in gadget.sequence or "int" in gadget.sequence
        assert isinstance(gadget.verified, bool)


def test_wanted_offsets_are_resolved(info):
    rows = wanted_offsets(info)
    names = [name for name, _value in rows]
    assert "system" in names or "__libc_system" in names
    assert all(value > 0 for _name, value in rows)


def test_load_rejects_non_elf(tmp_path):
    bad = tmp_path / "not-libc.txt"
    bad.write_text("hello")
    with pytest.raises(LibcError, match="not an ELF"):
        load_libc(bad)


def test_load_rejects_missing_file(tmp_path):
    with pytest.raises(LibcError):
        load_libc(tmp_path / "nope.so.6")


def test_offset_lookup_accepts_aliases(info):
    assert info.offset("system", "__libc_system")
    assert info.offset("definitely-not-there") is None
