# 80PWNER — by Anas Mahfouz (The80)
#
"""Parser engine tests on the sample binaries (with and without protections)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent / "samples"

VARIANTS = ("vuln_none.elf", "vuln_defaults.elf", "vuln_full.elf")


def have_samples() -> bool:
    if all((SAMPLES / v).exists() for v in VARIANTS):
        return True
    # try to build them if the compiler exists
    if _any_cc():
        result = subprocess.run(
            ["bash", str(SAMPLES / "build_samples.sh")],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0 and all(
            (SAMPLES / v).exists() for v in VARIANTS
        )
    return False


def _any_cc() -> str | None:
    import shutil

    return shutil.which("gcc") or shutil.which("cc")


pytestmark = pytest.mark.skipif(
    not have_samples(), reason="sample binaries missing and no compiler available"
)


@pytest.fixture(scope="module")
def parsed():
    from eightypwner.engines.binary_parser import parse_binary

    return {name: parse_binary(SAMPLES / name) for name in VARIANTS}


def test_metadata(parsed):
    model = parsed["vuln_none.elf"]
    assert model.fmt == "ELF"
    assert model.bits == 64
    assert model.endianness == "little"
    assert model.entry_point != 0
    assert model.sections and any(s.name == ".text" for s in model.sections)
    assert any(s.type_name == "GNU_STACK" for s in model.segments)


def test_symbols_and_imports(parsed):
    model = parsed["vuln_none.elf"]
    all_names = [s.name for s in model.symbols] + model.imports
    assert "main" in all_names
    assert "gets" in model.imports


def test_dangerous_functions(parsed):
    model = parsed["vuln_none.elf"]
    flagged = {d.name for d in model.dangerous}
    assert {"gets", "printf"} <= flagged
    severities = {d.name: d.severity for d in model.dangerous}
    assert severities["gets"] == "critical"


def test_checksec_none_variant(parsed):
    statuses = {c.name: c.status for c in parsed["vuln_none.elf"].checksec}
    assert statuses["NX"] == "disabled"
    assert statuses["PIE"] == "disabled"
    assert statuses["RELRO"] == "disabled"
    assert statuses["Stack canary"] == "disabled"


def test_checksec_full_variant(parsed):
    statuses = {c.name: c.status for c in parsed["vuln_full.elf"].checksec}
    assert statuses["NX"] == "enabled"
    assert statuses["PIE"] == "enabled"
    assert statuses["RELRO"] == "enabled"
    assert statuses["Stack canary"] == "enabled"
    assert statuses["Fortify"] == "enabled"


def test_checksec_defaults_variant(parsed):
    statuses = {c.name: c.status for c in parsed["vuln_defaults.elf"].checksec}
    # distro defaults vary: PIE usually on, canary usually on, but assert both parse
    assert statuses["NX"] in ("enabled", "unknown")
    assert statuses["PIE"] in ("enabled", "disabled", "unknown")
    assert len(statuses) == 5


def test_strings_extracted(parsed):
    model = parsed["vuln_none.elf"]
    texts = " ".join(t for _, t in model.strings)
    assert "80PWNER sample" in texts
    # interesting strings (with the flag marker) surface near the top
    flag_hits = [i for i, (_off, t) in enumerate(model.strings) if "flag{" in t]
    assert flag_hits and flag_hits[0] < 50


def test_backend_recorded(parsed):
    for model in parsed.values():
        assert model.parser_backend in ("lief", "pyelftools")


def test_parse_errors_are_user_facing():
    from eightypwner.engines.binary_parser import ParseError, parse_binary

    with pytest.raises(ParseError):
        parse_binary(SAMPLES / "definitely-not-here.elf")
    not_a_binary = SAMPLES / "not_a_binary.txt"
    not_a_binary.write_text("plain text, not a binary", encoding="utf-8")
    with pytest.raises(ParseError):
        parse_binary(not_a_binary)
