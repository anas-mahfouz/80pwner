# 80PWNER — by Anas Mahfouz (The80)

"""GDB/MI engine tests: integration on the sample binaries (skipped when gdb
is missing) plus mocked error paths (gdb missing at boot, crashes, timeouts).
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any

import pytest

import eightypwner.engines.gdb_mi as gdb_mi
from eightypwner.engines.gdb_mi import (
    COMMAND_TIMEOUT,
    T_BP_ADDED,
    T_DIED,
    T_ERROR,
    T_EXITED,
    T_MEMORY_CHANGED,
    T_REGISTERS,
    T_STACK_WORDS,
    T_STARTED,
    T_STOPPED,
    GdbEngine,
    GdbEngineError,
    GdbNotAvailableError,
)

SAMPLE_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = SAMPLE_ROOT / "tests" / "samples" / "vuln_none.elf"
GDB_PRESENT = shutil.which("gdb") is not None
SAMPLE_PRESENT = SAMPLE.is_file()

GDB_SKIP_REASON = "gdb is not installed on this machine"


def _wait(events: list[tuple[str, Any]], topic: str, timeout: float = 20.0, count: int = 1):
    """*count* events with *topic* once it appears, else None after *timeout*."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hits = [payload for name, payload in events if name == topic]
        if len(hits) >= count:
            return hits
        time.sleep(0.05)
    return None


# --------------------------------------------------------------- fake gdb
class _FakeIo:
    """Scripted IoManager stand-in: each write pops the next recipe.

    Recipes: an exception (raised), a (False, _) tuple (timeout raise),
    or a (True, records) tuple.
    """

    def __init__(self, *args: Any):
        self.script: list[Any] = [(True, [{"type": "result", "message": "done", "payload": None}])]

    def write(self, cmd, timeout_sec=1, raise_error_on_timeout=True, read_response=True):
        recipe = self.script.pop(0) if self.script else (True, [])
        if isinstance(recipe, BaseException):
            raise recipe
        ok, records = recipe if isinstance(recipe, tuple) else (True, recipe)
        if not ok:
            raise gdb_mi.GdbTimeoutError("did not get response")
        return records

    def get_gdb_response(self, timeout_sec=1, raise_error_on_timeout=True):
        return []

    def exit(self):
        return None


class _FakeController:
    """Minimal GdbController double (constructor/exit + scripted IO)."""

    def __init__(self, command=None, **_kwargs):
        self.io = _FakeIo()
        self.written: list[str] = []
        self.exited = False

    def write(self, cmd, timeout_sec=1, raise_error_on_timeout=True, read_response=True):
        self.written.append(str(cmd))
        return self.io.write(cmd, timeout_sec, raise_error_on_timeout, read_response)

    def get_gdb_response(self, timeout_sec=1, raise_error_on_timeout=True):
        return []

    def exit(self):
        self.exited = True


class _UnavailableStatus:
    available = False
    version = ""
    hint = "apt install gdb"


class _AvailableStatus:
    available = True
    version = "gdb-fake"
    hint = ""
    support_level = "full"


@pytest.fixture()
def fake_env(monkeypatch):
    monkeypatch.setattr(gdb_mi, "gdb_status", lambda: _AvailableStatus())
    monkeypatch.setattr(gdb_mi, "GdbController", _FakeController)
    events: list[tuple[str, Any]] = []
    engine = GdbEngine(lambda topic, payload: events.append((topic, payload)))
    return engine, events


# ------------------------------------------------------------ error paths
def test_no_gdb_raises(monkeypatch):
    monkeypatch.setattr(gdb_mi, "gdb_status", lambda: _UnavailableStatus())
    with pytest.raises(GdbNotAvailableError) as excinfo:
        GdbEngine(lambda topic, payload: None)
    assert "gdb is not installed" in str(excinfo.value)


def test_boot_failure_reports_error(fake_env):
    engine, events = fake_env

    class _BrokenController(_FakeController):
        def __init__(self, command=None, **_kwargs):
            raise FileNotFoundError(2, "No such file")

    gdb_mi.GdbController = _BrokenController
    engine.start_program("some_target")
    errors = _wait(events, T_ERROR, 10)
    assert errors is not None, "boot failure must surface a debugger_error"
    assert "Could not start gdb" in errors[-1]["message"]


def test_timeout_reports_error(fake_env):
    engine, events = fake_env
    engine.start_program("some_target")
    assert _wait(events, T_STARTED, 10) is not None
    events.clear()
    engine._controller.io.script = [(False, [])]  # next write hangs
    running = engine._thread
    assert running is not None
    engine.queued("-exec-run")
    errors = _wait(events, T_ERROR, 10)
    assert errors is not None
    assert any("did not answer within" in p["message"] for p in errors)


def test_gdb_death_reports(fake_env):
    engine, events = fake_env
    engine.start_program("some_target")
    assert _wait(events, T_STARTED, 10) is not None
    events.clear()
    engine._controller.io.script = [BrokenPipeError("gdb died")]
    engine.queued("-exec-run")
    assert _wait(events, T_DIED, 10) is not None
    assert engine.state == "exited"


def test_second_start_rejected(fake_env):
    engine, _events = fake_env
    engine.start_program("some_target")
    assert _wait([], T_STARTED, 0.2) is None  # helper sanity: empty list
    with pytest.raises(GdbEngineError):
        engine.start_program("another_target")
    engine.shutdown()


def test_shutdown_swallows_write_errors(fake_env):
    engine, events = fake_env
    engine.start_program("some_target")
    assert _wait(events, T_STARTED, 10) is not None
    engine._controller.io.script = [BrokenPipeError("dying mid-shutdown")]
    engine.shutdown()  # must not raise
    assert engine.state == "exited"


# ------------------------------------------------------------ integration
def _start_and_break(engine: GdbEngine, events: list, **start_kwargs) -> dict:
    engine.start_program(str(SAMPLE), **start_kwargs)
    assert _wait(events, T_STARTED, 30) is not None
    engine.set_breakpoint("main")
    assert _wait(events, T_BP_ADDED, 15) is not None
    engine.run()
    stops = _wait(events, T_STOPPED, 30)
    assert stops is not None, "did not stop at the main breakpoint"
    return stops[-1]


@pytest.mark.skipif(not GDB_PRESENT, reason=GDB_SKIP_REASON)
@pytest.mark.skipif(not SAMPLE_PRESENT, reason="sample binary missing")
class TestGdbIntegration:
    @pytest.fixture()
    def engine(self):
        events: list[tuple[str, Any]] = []
        engine = GdbEngine(lambda topic, payload: events.append((topic, payload)))
        yield engine, events
        engine.shutdown()

    def test_break_at_main(self, engine):
        engine, events = engine
        stop = _start_and_break(engine, events)
        assert stop["reason"] == "breakpoint-hit"
        assert int(stop["pc"], 16) > 0x400000
        assert int(stop["sp"], 16) > 0
        assert stop["frame"]["func"] == "main"
        # names fetched after -file-exec-and-symbols → x86-64 flavor mappings
        assert "$rip" in stop["regs"], "PC register named $rip (not stale i386 eip)"
        assert "$rsp" in stop["regs"], "SP register named $rsp"

    def test_step_over_advances_pc(self, engine):
        engine, events = engine
        first = _start_and_break(engine, events)
        engine.step_over()
        stops = _wait(events, T_STOPPED, 20, count=2)
        assert stops is not None, "stepping did not report another stop"
        second = stops[-1]
        assert second["pc"] != first["pc"]
        assert second["changed"], "at least one register changed across the step"

    def test_registers_event(self, engine):
        engine, events = engine
        _start_and_break(engine, events)
        engine.read_registers()
        hits = _wait(events, T_REGISTERS, 15)
        assert hits is not None
        payload = hits[-1]
        assert payload["values"]
        assert payload["sp"].startswith("0x")
        assert payload["pc"].startswith("0x")

    def test_stack_words_annotate_sp(self, engine):
        engine, events = engine
        stop = _start_and_break(engine, events)
        engine.read_stack_words(16)
        hits = _wait(events, T_STACK_WORDS, 20)
        assert hits is not None
        payload = hits[-1]
        assert payload["size"] == 192
        assert len(payload["words"]) == 24
        rows_at_sp = [w for w in payload["words"] if w["is_sp"]]
        assert rows_at_sp and rows_at_sp[0]["address"] == stop["sp"]

    def test_backtrace_has_main(self, engine):
        engine, events = engine
        _start_and_break(engine, events)
        engine.backtrace()
        hits = _wait(events, "debugger_backtrace", 20)
        assert hits is not None
        assert "main" in {f["func"] for f in hits[-1]["frames"]}

    def test_memory_write_then_read(self, engine):
        engine, events = engine
        stop = _start_and_break(engine, events)
        sp = int(stop["sp"], 16)
        engine.write_memory(sp, b"\x90" * 4)
        changed = _wait(events, T_MEMORY_CHANGED, 10)
        assert changed is not None
        assert int(changed[-1]["address"], 16) == sp
        events.clear()
        engine.read_memory(sp, 4)
        deadline = time.monotonic() + 20
        exact: dict | None = None
        while time.monotonic() < deadline:
            for p in (payload for topic, payload in events if topic == "debugger_memory_read"):
                if int(p["address"], 16) == sp and p["size"] == 4:
                    exact = p
            if exact is not None:
                break
            time.sleep(0.05)
        assert exact is not None, "requested 4-byte read never arrived"
        assert exact["hex"] == "90909090"

    def test_continue_to_exit_code(self, engine, tmp_path):
        engine, events = engine
        # the sample blocks in gets() unless stdin is redirected from a file
        stdin_file = tmp_path / "in.txt"
        stdin_file.write_text("AAAAAAA\n")
        _start_and_break(engine, events, stdin_file=str(stdin_file))
        engine.remove_breakpoint("1")
        engine.continue_()
        exits = _wait(events, T_EXITED, 30)
        assert exits is not None
        assert exits[-1]["exit_code"] == 0

    def test_stdin_file_redirect(self, engine, tmp_path):
        engine, events = engine
        stdin_file = tmp_path / "in.txt"
        stdin_file.write_text("AAAAAAA\n")
        _start_and_break(engine, events, stdin_file=str(stdin_file))
        engine.remove_breakpoint("1")
        engine.continue_()
        exits = _wait(events, T_EXITED, 30)
        assert exits is not None and exits[-1]["exit_code"] == 0

    def test_shutdown_no_orphans(self, engine):
        engine, events = engine
        _start_and_break(engine, events)
        pid = engine._inferior_pid
        assert pid, "inferior pid recorded while running"
        engine.shutdown()
        time.sleep(0.2)
        assert engine._inferior_pid is None
        assert not Path(f"/proc/{pid}").exists(), "inferior killed — no orphan processes"


def test_command_timeout_sane():
    assert 1.0 <= COMMAND_TIMEOUT <= 60.0
