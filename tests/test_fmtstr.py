# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Format-string helper tests: marker discovery and %n write planning."""

from __future__ import annotations

import struct

import pytest

from eightypwner.engines.fmtstr import (
    FmtPlan,
    build_plan,
    find_marker,
    find_marker_in_value,
    pwntools_payload,
    write_plan,
)


def test_find_marker_basic():
    output = "0x7ffd1234 0x1 0x41414141 0x0"
    assert find_marker(output, "41414141") == (3, "41414141")


def test_find_marker_with_truncation_and_pointer_bits():
    output = "0x0000000041414141 0xdeadbeef41414141"
    found = find_marker(output, "41414141")
    assert found is not None
    assert found[0] == 1


def test_find_marker_with_punctuation():
    output = "(nil) 0x41414141, 0x41424344"
    assert find_marker(output, "0x41414141") == (2, "41414141")


def test_find_marker_missing():
    assert find_marker("0x1 0x2 0x3", "41414141") is None
    assert find_marker("", "41414141") is None


def test_find_marker_in_value():
    assert find_marker_in_value(0x7FFF41414141, 0x41414141)
    assert not find_marker_in_value(0x7FFFDEADBEEF, 0x41414141)


def test_find_marker_in_value_32bit():
    assert find_marker_in_value(0x41414141, 0x41414141, bits=32)


def test_write_plan_shapes_payload():
    plan = write_plan(6, [(0x404060, 0x401230)], bits=64, write_size=2)
    assert isinstance(plan, FmtPlan)
    assert plan.offset == 6
    assert plan.format_string.count("$hn") == 4
    # Address table follows the format string, one qword per %hn write, in
    # write order (values are sorted ascending so padding never underflows).
    table = b"".join(struct.pack("<Q", write.address) for write in plan.writes)
    assert plan.raw.endswith(table)
    assert {write.address for write in plan.writes} == {
        0x404060, 0x404062, 0x404064, 0x404066
    }
    assert "writes" in plan.note
    assert plan.text().startswith("# arg offset 6")


def test_write_plan_splits_full_pointer():
    plan = write_plan(8, [(0x404060, 0xDEADBEEFCAFEBABE)], write_size=2)
    pieces = {(w.address, w.value) for w in plan.writes}
    assert (0x404060, 0xBABE) in pieces
    assert (0x404062, 0xCAFE) in pieces
    assert (0x404064, 0xBEEF) in pieces
    assert (0x404066, 0xDEAD) in pieces
    # Writes are ordered by ascending value for monotonic %hn padding.
    assert [w.value for w in plan.writes] == sorted(w.value for w in plan.writes)


def test_write_plan_multiple_targets_sorted_by_value():
    plan = write_plan(6, [(0x404060, 0x100), (0x404070, 0x10)], write_size=1)
    values = [write.value for write in plan.writes]
    assert values == sorted(values)


def test_write_plan_write_sizes():
    for size in (1, 2, 4, 8):
        plan = write_plan(6, [(0x404060, 1)], write_size=size)
        assert plan.raw
        assert all(write.size == size for write in plan.writes)


def test_write_plan_errors():
    with pytest.raises(ValueError):
        write_plan(6, [])
    with pytest.raises(ValueError):
        write_plan(6, [(0x404060, 1)], write_size=3)
    with pytest.raises(ValueError):
        write_plan(6, [(0, 1)])
    with pytest.raises(ValueError):
        write_plan(6, [(0x404060, 1)], write_size=16)


def test_write_plan_bad_bytes_note():
    plan = write_plan(6, [(0x404060, 0x10)], bad_bytes=b"\x00")
    assert "bad bytes" in plan.note or "NUL" in plan.note


def test_build_plan_alias():
    assert build_plan(6, [(0x1000, 0x20)]).raw


def test_pwntools_payload_line():
    line = pwntools_payload(6, [(0x404060, 0x401230)])
    assert line.startswith("fmtstr_payload(6, {")
    assert "0x404060: 0x401230" in line
    assert "write_size='short'" in line
