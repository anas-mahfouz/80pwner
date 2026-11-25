# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Shellcode studio tests: assemble, disassemble, hex parsing, bad bytes, XOR."""

from __future__ import annotations

import pytest

from eightypwner.engines import shellcode
from eightypwner.engines.shellcode import (
    ShellcodeError,
    assemble,
    bad_byte_offsets,
    build_xor_stub,
    contains_bad,
    disassemble,
    encode_xor,
    format_bytes,
    parse_hex_bytes,
    xor_bytes,
)

pytestmark = pytest.mark.skipif(
    not shellcode.ARCH_TABLE, reason="keystone/capstone unavailable"
)


def test_assemble_x86_64_nop_ret():
    assert assemble("nop\nret", "x86_64") == b"\x90\xc3"


def test_assemble_execve_sequence():
    code = "xor eax, eax\nmov al, 60\nxor edi, edi\nsyscall"
    data = assemble(code, "x86_64")
    assert data.endswith(b"\x0f\x05")
    assert len(data) >= 8


def test_assemble_errors_are_user_facing():
    with pytest.raises(ShellcodeError):
        assemble("this-is-not-an-instruction", "x86_64")
    with pytest.raises(ShellcodeError):
        assemble("nop", "vax")


def test_disassemble_roundtrip():
    rows = disassemble(b"\x90\xc3", "x86_64")
    assert rows[0].bytes_hex == "90"
    assert rows[0].text == "nop"
    assert rows[1].text == "ret"


def test_parse_hex_variants():
    assert parse_hex_bytes("90 90 c3") == b"\x90\x90\xc3"
    assert parse_hex_bytes("\\x90\\x90\\xc3") == b"\x90\x90\xc3"
    assert parse_hex_bytes("0x9090c3") == b"\x90\x90\xc3"
    assert parse_hex_bytes("9090") == b"\x90\x90"
    assert parse_hex_bytes("") == b""
    with pytest.raises(ShellcodeError):
        parse_hex_bytes("909")  # odd length
    with pytest.raises(ShellcodeError):
        parse_hex_bytes("zz")


def test_format_bytes_styles():
    data = b"\x41\x00"
    assert format_bytes(data) == 'b"\\x41\\x00"'
    assert format_bytes(data, "escaped") == "\\x41\\x00"
    assert format_bytes(data, "hex") == "4100"
    assert format_bytes(data, "c") == "{0x41, 0x00}"
    assert format_bytes(data, "c_string") == '"\\x41\\x00"'
    assert format_bytes(data, "base64") == "QQA="
    with pytest.raises(ShellcodeError):
        format_bytes(data, "rot13")


def test_bad_bytes_detection():
    data = b"\x41\x00\x0a"
    assert bad_byte_offsets(data, b"\x00\x0a") == [1, 2]
    assert contains_bad(data, b"\x00")
    assert not contains_bad(data, b"\xff")


def test_xor_bytes_key_range():
    assert xor_bytes(b"\x41", 0x01) == b"\x40"
    with pytest.raises(ShellcodeError):
        xor_bytes(b"\x41", 0)
    with pytest.raises(ShellcodeError):
        xor_bytes(b"\x41", 256)


def test_xor_stub_layout():
    data = b"\x90\xc3"
    stub, asm_text = build_xor_stub(data, 0x41)
    assert stub
    assert "call decoder" in asm_text
    payload = stub + xor_bytes(data, 0x41)
    assert payload.startswith(stub)
    assert payload.endswith(b"\xd1\x82")


def test_encode_xor_auto_key_is_clean_for_payload():
    data = assemble("xor eax, eax\nmov al, 60\ndec edi\nsyscall", "x86_64")
    encoded = encode_xor(data, bad=b"\x00\x0a")
    assert not contains_bad(encoded.encoded, b"\x00\x0a")
    assert encoded.key not in b"\x00\x0a"
    assert encoded.payload == encoded.stub + encoded.encoded
    # The decoder stub itself must be null-free for strcpy/gets targets.
    assert not contains_bad(encoded.payload, b"\x00\x0a")
    assert encoded.decoder_asm


def test_xor_stub_actually_decodes_and_runs():
    """Execute stub+encoded blob in RWX memory; it must return the magic."""
    import ctypes
    import mmap

    payload = assemble("mov eax, 0x1337\nret", "x86_64")
    encoded = encode_xor(payload, bad=b"\x00\x0a")
    region = mmap.mmap(
        -1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
    )
    try:
        region.write(encoded.payload)
        address = ctypes.addressof(ctypes.c_char.from_buffer(region))
        function = ctypes.CFUNCTYPE(ctypes.c_uint64)(address)
        assert function() == 0x1337
    finally:
        region.close()


def test_encode_xor_explicit_key():
    data = b"\x41\x42"
    encoded = encode_xor(data, key=0x20)
    assert encoded.key == 0x20
    assert encoded.encoded == b"\x61\x62"


def test_encode_xor_rejects_bad_key():
    with pytest.raises(ShellcodeError):
        encode_xor(b"\x41", bad=b"\x10", key=0x10)


def test_encode_xor_no_possible_key():
    with pytest.raises(ShellcodeError):
        encode_xor(bytes(range(256)), bad=bytes(range(1, 255)))


def test_presets_assemble():
    for preset in shellcode.PRESETS:
        if preset.arch not in shellcode.ARCH_TABLE:
            continue
        data = assemble(preset.asm, preset.arch)
        assert data, preset.name
