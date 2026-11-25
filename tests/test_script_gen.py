# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Exploit script generator tests: every template must be valid Python."""

from __future__ import annotations

from pathlib import Path

import pytest

from eightypwner.engines.binary_parser import parse_binary
from eightypwner.engines.script_gen import (
    TEMPLATES,
    ExploitContext,
    generate,
)

SAMPLES = Path(__file__).parent / "samples"
NONE = SAMPLES / "vuln_none.elf"


@pytest.fixture(scope="module")
def model():
    return parse_binary(NONE)


def test_context_from_model(model):
    ctx = ExploitContext.from_model(model)
    assert ctx.binary_path.endswith("vuln_none.elf")
    assert ctx.binary_name.endswith("vuln_none.elf")
    assert ctx.bits in (32, 64)
    assert ctx.checksec, "checksec items must be captured"
    assert any(address for address in ctx.functions.values())


def test_all_templates_compile(model):
    ctx = ExploitContext.from_model(model)
    ctx.crash_offset = 72
    for template in TEMPLATES:
        text = generate(ctx, template)
        compile(text, f"<{template}>", "exec")
        assert text.startswith("#!/usr/bin/env python3")
        assert "80PWNER — by The 80" in text
        assert "from pwn import *" in text


def test_skeleton_lists_targets(model):
    ctx = ExploitContext.from_model(model)
    text = generate(ctx, "skeleton")
    assert "def start(" in text
    assert "def exploit(" in text
    assert "Handy targets" in text


def test_ret2win_uses_win_symbol(model):
    ctx = ExploitContext.from_model(model)
    ctx.functions["win"] = 0x4011A9
    ctx.crash_offset = 72
    text = generate(ctx, "ret2win")
    assert "exe.sym['win']" in text
    assert "OFFSET = 72" in text
    assert "flat({ OFFSET: [alignment, p64(target)] })" in text
    compile(text, "<ret2win>", "exec")


def test_ret2win_without_win_is_a_todo():
    ctx = ExploitContext(functions={}, crash_offset=0)
    text = generate(ctx, "ret2win")
    assert "no win/flag symbol" in text
    assert "OFFSET = 0" in text
    compile(text, "<ret2win-empty>", "exec")


def test_ret2libc_includes_libc_and_one_gadgets(model, tmp_path):
    ctx = ExploitContext.from_model(model)
    ctx.crash_offset = 40
    ctx.libc_path = "/tmp/libc.so.6"
    ctx.libc_version = "2.42"
    ctx.libc_one_gadgets = ["0xebcf1 constraint: rdi == NULL"]
    text = generate(ctx, "ret2libc")
    assert "libc = ELF('/tmp/libc.so.6', checksec=False)" in text
    assert "one-gadget candidates" in text
    assert "libc.address = leaked - libc.sym[\"puts\"]" in text
    compile(text, "<ret2libc>", "exec")


def test_shellcode_template_warns_on_nx():
    ctx = ExploitContext(checksec={"NX": "enabled"}, crash_offset=16)
    text = generate(ctx, "shellcode")
    assert "NX is enabled" in text
    compile(text, "<shellcode>", "exec")


def test_unknown_template_rejected(model):
    with pytest.raises(ValueError, match="Unknown template"):
        generate(ExploitContext.from_model(model), "ropchain")


def test_checksec_comment():
    ctx = ExploitContext(checksec={"NX": "enabled", "Stack canary": "disabled"})
    assert "nx=enabled" in ctx.checksec_comment()
    assert "stackcanary=disabled" in ctx.checksec_comment()


def test_win_function_prefers_pattern():
    ctx = ExploitContext(functions={"main": 0x1000, "print_flag": 0x2000})
    assert ctx.win_function() == ("print_flag", 0x2000)
    legacy = ExploitContext(functions={"main": 0x1000, "shell": 0x3000})
    assert legacy.win_function() == ("shell", 0x3000)
