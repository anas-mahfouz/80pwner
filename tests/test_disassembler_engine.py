# 80PWNER — by Anas Mahfouz (The80)

"""Step-3 engine tests: disassembly, function discovery, xrefs, annotations."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("capstone", reason="disassembler needs capstone")
pytest.importorskip("lief", reason="samples were built against LIEF parsing")

SAMPLES = Path(__file__).resolve().parent / "samples"


@pytest.fixture()
def model():
    from eightypwner.engines.binary_parser import parse_binary

    return parse_binary(SAMPLES / "vuln_none.elf")


def test_addrmap_entry_bytes(model):
    from eightypwner.engines.addrmap import AddrMap, ReadError

    addrmap = AddrMap(model)
    entry = model.entry_point
    data = addrmap.read(entry, 4)
    assert len(data) == 4
    # first x86-64 entry instruction with endbr64 is expected for glibc targets
    assert addrmap.section_of(entry) == ".text"
    # offset mapping is a real file offset (positive, within file size)
    offset = addrmap.to_offset(entry)
    raw = Path(model.path).read_bytes()
    assert 0 < offset < len(raw)
    assert raw[offset : offset + 4] == data
    with pytest.raises(ReadError):
        addrmap.read(0xDEAD_BEEF_F0F0, 16)


def test_decode_function_stops_at_function_end(model):
    from eightypwner.engines.disassembler import Disassembler

    d = Disassembler(model)
    entry = model.entry_point
    body = d.decode_function(entry)
    assert body, "no instructions decoded"
    assert body[0].address == entry
    # bounded by the heuristic, never a runaway linear sweep
    assert len(body) < 4096
    assert body[-1].mnemonic in ("hlt", "jmp", "ret")
    # cache hit returns the same list
    assert d.decode_function(entry) is body


def test_intel_and_att_syntax(model):
    from eightypwner.engines.disassembler import Disassembler

    d = Disassembler(model)
    entry = model.entry_point
    intel = d.decode_function(entry, att_syntax=False)
    att = d.decode_function(entry, att_syntax=True)
    assert [i.address for i in intel] == [i.address for i in att]
    assert intel, "entry decoded in both syntaxes"
    assert intel != att, "AT&T rendering must differ from Intel"
    # AT&T prefixes registers with %
    att_operands = " ".join(i.operands for i in att[:16])
    if "%" not in att_operands:
        # some stubs have no GPR operands; intel/att still must not be identical
        assert all(a.operands != b.operands for a, b in zip(intel[:16], att[:16], strict=False))


def test_branch_targets_and_xref_kinds(model):
    from eightypwner.engines.disassembler import Disassembler
    from eightypwner.engines.functions import FunctionFinder

    d = Disassembler(model)
    index = FunctionFinder(model).discover()
    # _start's calls go through the GOT (immediate-less), so probe a function
    # that really branches into other code.
    candidates = [f for f in index.functions if f.name != "_start"] or index.functions
    targets = []
    for func in candidates:
        targets.extend(d.branch_targets(d.decode_function(func.address)))
    # fall back to a wide linear window if per-function bodies have no branches
    if not targets:
        targets = d.branch_targets(list(d.decode(model.entry_point, 0x400)))
    assert targets, "expected at least one call/jmp with an immediate target"
    kinds = {t.kind for t in targets}
    assert kinds <= {"call", "jmp", "cond"}
    for target in targets:
        assert target.address > 0


def test_function_discovery_and_xrefs(model):
    from eightypwner.engines.functions import FunctionFinder

    index = FunctionFinder(model).discover()
    names = {f.name for f in index.functions}
    assert "_start" in names
    assert "main" in names
    addresses = [f.address for f in index.functions]
    assert addresses == sorted(addresses), "functions sorted by address"
    assert len(index.functions) >= 10
    call_xrefs = [x for x in index.xrefs if x.kind == "call"]
    assert call_xrefs, "at least one resolved call xref expected"
    # every xref points to a known function address
    function_addresses = {f.address for f in index.functions}
    assert all(x.to_address in function_addresses for x in call_xrefs)


def test_filter_functions(model):
    from eightypwner.engines.functions import FunctionFinder, filter_functions

    index = FunctionFinder(model).discover()
    functions = list(index.functions)
    assert filter_functions(functions, "") == functions
    hits = filter_functions(functions, "main")
    assert hits and any(f.name == "main" for f in hits)
    # hex attribute filtering matches by address text too
    entry = next(f for f in functions if f.name == "main")
    assert entry in filter_functions(functions, format(entry.address, "x"))
    assert filter_functions(functions, "zzz_no_such") == []


def test_session_annotations_roundtrip(tmp_path, monkeypatch, model):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    from eightypwner.core.session import SessionState

    session = SessionState()
    session.binary_path = Path(model.path)
    session.set_comment(0x401010, "call site of puts")
    session.rename_symbol(0x4011BF, "vuln_main")
    assert session.save_annotations()
    fresh = SessionState()
    fresh.binary_path = Path(model.path)
    assert fresh.load_annotations()
    assert fresh.comment_at(0x401010) == "call site of puts"
    assert fresh.display_name(0x4011BF, "main") == "vuln_main"
    # empty text clears a comment
    fresh.set_comment(0x401010, "")
    assert fresh.comment_at(0x401010) is None
