# 80PWNER — by Anas Mahfouz (The80)

"""GDB/MI debugger engine (Step 4, spec §6.3).

One :class:`GdbEngine` owns one gdb subprocess (pygdbmi) plus one worker
thread. All MI I/O happens on the worker: the UI only pushes non-blocking
commands and receives a clean typed event stream via ``emit(topic, payload)``
— the plugin puts those topics straight on the bus, and the UiBus bridge
marshals them to the UI thread. GDB hang → timeouts, gdb death →
``debugger_died``, inferior crash → ``debugger_stopped`` (signal-received) or
``debugger_exited`` — the UI thread never blocks.

Cleanup: ``shutdown()`` sends ``-target-kill`` + ``-gdb-exit``, terminates the
gdb subprocess, and hard-SIGKILLs the recorded inferior PID so a broken
teardown still leaves no orphan processes.

Linux: full support. macOS/Windows: works when a usable gdb exists, else
construction fails with :class:`GdbNotAvailable` (UI shows a clear message;
all static modules keep working).
"""

from __future__ import annotations

import base64
import errno
import logging
import os
import queue
import shlex
import shutil
import signal
import sys
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pygdbmi.constants import GdbTimeoutError
from pygdbmi.gdbcontroller import GdbController

from eightypwner.platform.debuggers import gdb_status

log = logging.getLogger(__name__)

COMMAND_TIMEOUT = 15.0
_POLL_SEC = 0.05

# typed topics (published on the bus by the plugin)
T_STATE = "debugger_state"  # {"state": idle|launching|running|stopped|exited}
T_STARTED = "debugger_started"
T_RUNNING = "debugger_running"
T_STOPPED = "debugger_stopped"  # registers/PC/SP/breakpoint info
T_EXITED = "debugger_exited"  # {"exit_code": 0}
T_ERROR = "debugger_error"
T_DIED = "debugger_died"
T_OUTPUT = "debugger_output"  # gdb console/log stream
T_PROGRAM_OUTPUT = "program_output"
T_BP_ADDED = "breakpoint_added"
T_BP_REMOVED = "breakpoint_removed"
T_BP_UPDATED = "breakpoint_updated"  # full snapshot after any change
T_MEMORY_CHANGED = "memory_changed"
T_MEMORY_READ = "debugger_memory_read"
T_REGISTERS = "debugger_registers"
T_BACKTRACE = "debugger_backtrace"
T_STACK_WORDS = "debugger_stack_words"


class GdbEngineError(Exception):
    """User-facing debugger failure (shown in the UI verbatim)."""


class GdbNotAvailableError(GdbEngineError):
    """No usable gdb on this machine/platform."""


# keep the friendly exception import shape stable for callers
GdbNotAvailable = GdbNotAvailableError


@dataclass
class Breakpoint:
    number: str
    address: int | None = None
    func: str = ""
    enabled: bool = True
    temp: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "address": hex(self.address) if self.address is not None else "",
            "func": self.func,
            "enabled": self.enabled,
            "temp": self.temp,
        }


class GdbEngine:
    """Async GDB/MI controller. Every public call is non-blocking."""

    def __init__(
        self,
        emit: Callable[[str, dict[str, Any]], None],
        gdb_path: str | None = None,
    ) -> None:
        self._emit = emit
        status = gdb_status()
        if not status.available:
            raise GdbNotAvailable(
                f"gdb is not installed on this system.\n{status.hint}\n"
                "The Debugger module stays disabled; all static modules keep working."
            )
        self._gdb_path = gdb_path or shutil.which("gdb") or "gdb"
        self._controller: GdbController | None = None
        self._thread: threading.Thread | None = None
        self._cmd_queue: queue.Queue[str] = queue.Queue()
        self._stopping = False
        self._state = "idle"
        self._target_path: str | None = None
        self._register_names: list[str] = []
        self._prev_registers: dict[str, str] = {}
        self._breakpoints: dict[str, Breakpoint] = {}
        self._inferior_pid: int | None = None
        self._pty_master: int | None = None
        self._pty_slave: int | None = None
        self._pty_reader: threading.Thread | None = None
        self._boot_plan: dict[str, Any] | None = None

    # ------------------------------------------------------------------- API
    @property
    def state(self) -> str:
        return self._state

    @property
    def breakpoints(self) -> dict[str, Breakpoint]:
        return dict(self._breakpoints)

    def start_program(
        self,
        target_path: str | Path,
        args: list[str] | None = None,
        stdin_file: str | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        break_address: int | None = None,
    ) -> None:
        """Queue a fresh gdb session that launches *target_path*."""
        if self._thread is not None and self._thread.is_alive():
            raise GdbEngineError("A debugging session is already running")
        self._boot_plan = {
            "target": str(target_path),
            "args": list(args or []),
            "stdin": stdin_file or "",
            "env": dict(env or {}),
            "cwd": cwd or "",
            "break_address": break_address,
            "attach": None,
        }
        self._spawn_worker()

    def attach(self, pid: int, target_path: str | None = None) -> None:
        if self._thread is not None and self._thread.is_alive():
            raise GdbEngineError("A debugging session is already running")
        self._boot_plan = {
            "target": target_path or "",
            "args": [],
            "stdin": "",
            "env": {},
            "cwd": "",
            "break_address": None,
            "attach": int(pid),
        }
        self._spawn_worker()

    # -- execution control ----------------------------------------------------
    def run(self) -> None:
        self.queued("-exec-run")

    def continue_(self) -> None:
        self.queued("-exec-continue")

    def step_into(self) -> None:
        self.queued("-exec-step")

    def step_over(self) -> None:
        self.queued("-exec-next")

    def step_finish(self) -> None:
        self.queued("-exec-finish")

    def run_to(self, address: int) -> None:
        """Temporary breakpoint at *address*, then continue (run to cursor)."""
        self.queued(f"-break-insert -t *0x{address:x}")
        self.queued("-exec-continue")

    def restart(self) -> None:
        self.queued("-target-kill")
        self.queued("-exec-run")

    def stop_program(self) -> None:
        self.queued("-target-kill")

    # -- breakpoints -----------------------------------------------------------
    def set_breakpoint(self, where: int | str, temp: bool = False) -> None:
        flag = "-t " if temp else ""
        if isinstance(where, int):
            self.queued(f"-break-insert {flag}*0x{where:x}")
        else:
            self.queued(f"-break-insert {flag}{shlex.quote(where)}")

    def remove_breakpoint(self, number: str) -> None:
        self.queued(f"-break-delete {number}")

    def toggle_breakpoint(self, address: int) -> None:
        """Insert unless one already exists at *address*; then remove it."""
        for bp in list(self._breakpoints.values()):
            if bp.address == address and not bp.temp:
                self.remove_breakpoint(bp.number)
                return
        self.set_breakpoint(address)

    def enable_breakpoint(self, number: str, enabled: bool) -> None:
        self.queued(f"-break-{'enable' if enabled else 'disable'} {number}")

    # -- data -------------------------------------------------------------------
    def read_registers(self) -> None:
        self.queued("-data-list-register-names")
        self.queued("-data-list-register-values x")

    def write_register(self, name: str, value: str) -> None:
        if not name.startswith("$"):
            name = f"${name}"
        self.queued(f"-gdb-set {name} = {value}")
        self.queued("-data-list-register-values x")  # refreshed after the write

    def read_memory(self, address: int, size: int) -> None:
        self.queued(f"-data-read-memory-bytes 0x{address:x} {int(size)}")

    def write_memory(self, address: int, data: bytes) -> None:
        encoded = base64.b64encode(data).decode("ascii")
        self.queued(f"-data-write-memory-bytes 0x{address:x} {encoded}")
        # ^done carries no echo; announce so the UI can refresh its region
        self._emit(T_MEMORY_CHANGED, {"address": hex(address), "size": len(data)})

    def read_stack_words(self, count: int = 16) -> None:
        """*count* quadwords around $sp (8 bytes each side is covered)."""
        window = (count // 2 + 1) * 8
        self.queued(f'-data-read-memory-bytes "($sp - {window})" {window * 2}')

    def backtrace(self) -> None:
        self.queued("-stack-list-frames")

    def send_raw(self, line: str) -> None:
        """Console input: lines starting with '-' go raw, else console-wrapped."""
        line = line.strip()
        if not line:
            return
        if line.startswith("-"):
            self.queued(line)
        else:
            self.queued(f"-interpreter-exec console {_mi_quote(line)}")

    def program_stdin(self, text: str) -> None:
        """Feed the inferior's stdin through the program TTY (POSIX)."""
        if self._pty_master is None:
            self._emit(
                T_ERROR,
                {"message": "No program TTY on this platform — the Program I/O "
                            "stdin box is off; use a stdin file in the run dialog."},
            )
            return
        os.write(self._pty_master, text.encode(errors="replace"))

    # -- lifecycle ----------------------------------------------------------------
    def shutdown(self) -> None:
        """Kill inferior + gdb; hard-kill the inferior PID as a final safety."""
        self._stopping = True
        controller = self._controller
        pid = self._inferior_pid
        if controller is not None:
            with suppress(Exception):
                controller.write("-target-kill", timeout_sec=1, raise_error_on_timeout=False)
                controller.write("-gdb-exit", timeout_sec=1, raise_error_on_timeout=False)
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        if controller is not None:
            with suppress(Exception):
                controller.exit()  # terminate() the gdb subprocess
        self._controller = None
        if pid and _pid_alive(pid):
            with suppress(OSError):
                os.kill(pid, signal.SIGKILL)
        if self._pty_master is not None:
            with suppress(OSError):
                os.close(self._pty_master)
            self._pty_master = None
        if self._pty_slave is not None:
            with suppress(OSError):
                os.close(self._pty_slave)
            self._pty_slave = None
        self._inferior_pid = None
        self._set_state("exited")

    # --------------------------------------------------------------- internals
    def queued(self, command: str) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._emit(T_ERROR, {"message": "Debugger is not running"})
            return
        self._cmd_queue.put(command)

    def _spawn_worker(self) -> None:
        self._stopping = False
        self._thread = threading.Thread(
            target=self._run, name="80pwner-gdbmi", daemon=True
        )
        self._thread.start()

    # -- the worker loop (owns gdb: all read/write happens here) ----------------
    def _run(self) -> None:
        boot = self._boot_plan or {}
        try:
            argv = ["gdb", "-q", "-nx", "--interpreter=mi3"]
            if boot.get("attach"):
                argv.append(f"-p={boot['attach']}")
            self._controller = GdbController(command=argv)
        except Exception as exc:
            self._controller = None
            log.exception("gdb could not be started")
            self._emit(
                T_ERROR,
                {"message": f"Could not start gdb ({self._gdb_path}): {exc}"},
            )
            return
        self._set_state("launching")
        try:
            self._prepare_target(boot)
        except GdbNotAvailable:
            return
        except Exception:
            log.exception("gdb session preparation failed")
            self._emit(T_ERROR, {"message": "gdb session preparation failed"})
            return
        if boot.get("attach"):
            self._inferior_pid = int(boot["attach"])
            self._state = "stopped"
            self._refresh_registers_and_announce("attached")
        else:
            self._set_state("idle")

        while not self._stopping:
            command: str | None = None
            with suppress(queue.Empty):
                command = self._cmd_queue.get(timeout=_POLL_SEC)
            if command is None:
                self._drain_async()
                continue
            try:
                assert self._controller is not None
                records = self._controller.write(command, timeout_sec=COMMAND_TIMEOUT)
            except GdbTimeoutError:
                self._emit(
                    T_ERROR,
                    {"message": f"gdb did not answer within {COMMAND_TIMEOUT:.0f}s: {command}"},
                )
                continue
            except (BrokenPipeError, OSError, ValueError) as exc:
                self._on_gdb_died(exc)
                return
            self._dispatch(records)
        self._set_state("exited")

    def _prepare_target(self, boot: dict[str, Any]) -> None:
        controller = self._controller
        if controller is None:
            return
        self._ensure_register_names(controller)
        # program TTY for the inferior's output + our program_stdin writes
        if self._pty_master is None and sys.platform != "win32":
            try:
                import pty

                master, slave = pty.openpty()
                tty_name = os.ttyname(slave)
                controller.write(
                    f"-inferior-tty-set {shlex.quote(tty_name)}",
                    timeout_sec=COMMAND_TIMEOUT,
                )
                self._pty_master = master
                # Keep our slave fd open for the whole session: a pty master
                # read raises EIO whenever no slave fd exists, and between
                # openpty() and -exec-run nobody else holds one.
                self._pty_slave = slave
                self._start_pty_reader(master)
            except (ImportError, OSError):
                log.debug("program TTY unavailable — inferior shares gdb stdio")
        if boot.get("target"):
            controller.write(
                f"-file-exec-and-symbols {shlex.quote(boot['target'])}",
                timeout_sec=COMMAND_TIMEOUT,
            )
            self._target_path = boot["target"]
        if boot.get("cwd"):
            controller.write(
                f"-environment-cd {shlex.quote(boot['cwd'])}", timeout_sec=COMMAND_TIMEOUT
            )
        for key, value in boot.get("env", {}).items():
            controller.write(
                f'-interpreter-exec console "set env {key} {_mi_quote(value)}"',
                timeout_sec=COMMAND_TIMEOUT,
            )
        args_text = list(boot.get("args", []))
        if boot.get("stdin"):
            args_text += ["<", boot["stdin"]]
        if args_text:
            # NOTE: -exec-arguments passes its text to the startup shell, so
            # redirection operators must NOT be quoted (shlex.quote('<') would
            # turn the redirect into a literal "<" argument and hang the run).
            _redirect_ops = {"<", ">", "<<", ">>", "2>&1", "&>"}
            joined = " ".join(
                a if a in _redirect_ops else shlex.quote(a) for a in args_text
            )
            controller.write(f"-exec-arguments {joined}", timeout_sec=COMMAND_TIMEOUT)
        break_at = boot.get("break_address")
        if break_at is not None:
            with suppress(GdbTimeoutError, BrokenPipeError, OSError, ValueError):
                controller.write(
                    f"-break-insert *0x{int(break_at):x}", timeout_sec=COMMAND_TIMEOUT
                )
        self._emit(
            T_STARTED,
            {
                "target": self._target_path or "",
                "attach": boot.get("attach"),
                "program_io": self._pty_master is not None,
            },
        )

    def _ensure_register_names(self, controller: GdbController) -> None:
        try:
            records = controller.write(
                "-data-list-register-names", timeout_sec=COMMAND_TIMEOUT
            )
        except (GdbTimeoutError, BrokenPipeError, OSError, ValueError):
            return
        for record in records:
            if record.get("type") == "result" and isinstance(record.get("payload"), dict):
                names = record["payload"].get("register-names")
                if isinstance(names, list):
                    self._register_names = [str(n) for n in names]
                    return

    def _start_pty_reader(self, master: int) -> None:
        def read_loop() -> None:
            while not self._stopping:
                try:
                    import selectors

                    sel = selectors.DefaultSelector()
                    sel.register(master, selectors.EVENT_READ)
                    ready = sel.select(timeout=0.2)
                    sel.close()
                    if not ready:
                        continue
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        # no slave open this instant (inferior not running yet);
                        # retry instead of killing the whole reader thread
                        time.sleep(0.1)
                        continue
                    return
                if not chunk:
                    return
                self._emit(T_PROGRAM_OUTPUT, {"text": chunk.decode(errors="replace")})

        self._pty_reader = threading.Thread(target=read_loop, daemon=True)
        self._pty_reader.start()

    def _drain_async(self) -> None:
        """Unsolicited MI records (stops, breakpoints, process mgmt…)."""
        controller = self._controller
        if controller is None:
            return
        try:
            records = controller.get_gdb_response(
                timeout_sec=_POLL_SEC, raise_error_on_timeout=False
            )
        except (BrokenPipeError, OSError, ValueError) as exc:
            self._on_gdb_died(exc)
            return
        except GdbTimeoutError:  # pragma: no cover
            return
        if records:
            self._dispatch(records)

    def _on_gdb_died(self, exc: Exception) -> None:
        log.warning("gdb died: %s", exc)
        self._set_state("exited")
        self._emit(T_DIED, {"error": str(exc)})

    # ------------------------------------------------------------- dispatching
    def _dispatch(self, records: list[dict[str, Any]]) -> None:
        for record in records:
            rtype = record.get("type")
            payload = record.get("payload")
            if rtype == "result":
                self._on_result(record)
            elif rtype == "notify":
                self._on_notify(record)
            elif rtype in ("output", "log", "target"):
                stream = {"output": "console", "log": "log", "target": "program"}[rtype]
                self._emit(T_OUTPUT, {"stream": stream, "text": str(payload or "")})

    def _on_result(self, record: dict[str, Any]) -> None:
        cls = str(record.get("message") or "")
        payload = record.get("payload")
        if cls == "error":
            message = payload if isinstance(payload, str) else str(payload)
            self._emit(T_ERROR, {"message": message, "from_gdb": True})
            return
        if not isinstance(payload, dict):
            return
        if "bkpt" in payload and isinstance(payload["bkpt"], dict):
            info = payload["bkpt"]
            self._track_breakpoint(info)
            bp = self._breakpoints.get(str(info.get("number", "?")))
            if bp is not None and not bp.temp:
                self._emit(T_BP_ADDED, bp.as_dict())
            self._announce_breakpoints()
        if "register-names" in payload and isinstance(payload["register-names"], list):
            self._register_names = [str(n) for n in payload["register-names"]]
        if "register-values" in payload:
            self._announce_registers(self._map_registers(payload["register-values"]))
        if "memory" in payload and isinstance(payload["memory"], list) and payload["memory"]:
            self._announce_memory(payload["memory"][0])
        if "value" in payload:
            log.debug("gdb value: %r", payload["value"])
        if "stack" in payload:
            frames: list[dict[str, Any]] = []
            for row in payload["stack"]:
                entry = row.get("frame", row)
                frames.append(
                    {
                        "level": str(entry.get("level", "")),
                        "address": str(entry.get("addr", "")),
                        "func": str(entry.get("func", "")),
                        "file": str(entry.get("file", "")) or str(entry.get("from", "")),
                        "line": str(entry.get("line", "")),
                    }
                )
            self._emit(T_BACKTRACE, {"frames": frames})

    def _on_notify(self, record: dict[str, Any]) -> None:
        payload = record.get("payload")
        if isinstance(payload, str) or payload is None:
            return
        if not isinstance(payload, dict):
            return

        # '=' status records vs '*' exec records both arrive as 'notify'
        reason = payload.get("reason")
        if payload.get("pid"):
            with suppress(TypeError, ValueError):
                self._inferior_pid = int(str(payload["pid"]))
        if reason in ("breakpoint-hit", "signal-received", "end-stepping-range",
                      "function-finished", "syscall-entry", "syscall-return"):
            self._on_stopped(payload)
        elif reason in ("exited", "exited-normally", "exited-signalled") or (
            reason is None and payload.get("exit-code")
        ):
            self._on_exited(payload)
        elif reason is None and payload.get("group-id") and self._state != "exited":
            # *running-style record; pid was captured above
            self._set_state("running")
            self._emit(T_RUNNING, {"pid": self._inferior_pid})

        bp_info = payload.get("bkpt") if isinstance(payload.get("bkpt"), dict) else None
        where = payload.get("class") or payload.get("id") or ""
        if bp_info is not None or (
            isinstance(payload.get("number"), str) and where.startswith("breakpoint")
        ):
            if payload.get("deleted") == "y":
                number = str((bp_info or payload).get("number", "?"))
                self._breakpoints.pop(number, None)
                self._announce_breakpoints()
                self._emit(T_BP_REMOVED, {"number": number})
            else:
                self._track_breakpoint(bp_info or payload)
                self._announce_breakpoints()

    # -- stopped/exited state machine -----------------------------------------
    def _on_stopped(self, payload: dict[str, Any]) -> None:
        if str(payload.get("reason", "")).startswith("exited"):
            self._on_exited(payload)
            return
        frame = payload.get("frame") if isinstance(payload.get("frame"), dict) else {}
        self._state = "stopped"
        self._emit(T_STATE, {"state": "stopped"})
        regs = self._refresh_registers()
        changed = self._changed_keys(regs)
        self._prev_registers = dict(regs)
        sp = self._evaluate("$sp")
        pc = str(frame.get("addr") or "") or self._evaluate("$pc")
        self._emit(
            T_STOPPED,
            {
                "reason": str(payload.get("reason", "")),
                "bkpt_no": str(payload.get("bkptno") or ""),
                "signal": str(payload.get("signal-name") or ""),
                "pc": pc,
                "sp": sp,
                "frame": {
                    "func": str(frame.get("func", "") or ""),
                    "file": str(frame.get("fullname", "") or frame.get("file", "") or ""),
                    "line": str(frame.get("line", "") or ""),
                },
                "regs": regs,
                "changed": sorted(changed),
            },
        )
        # auto-collect context the panels want on every stop
        self.queued("-stack-list-frames")
        self.queued('-data-read-memory-bytes "($sp - 64)" 192')

    def _on_exited(self, payload: dict[str, Any]) -> None:
        if self._state == "exited":  # thread-group-exited echoes: emit once
            return
        self._state = "exited"
        self._inferior_pid = None
        code = str(payload.get("exit-code", ""))
        if not code:
            code = self._evaluate("$_exitcode")
        self._emit(T_STATE, {"state": "exited"})
        try:
            exit_code = int(code, 16) if code.startswith("0x") else int(code)
        except ValueError:
            exit_code = None
        self._emit(T_EXITED, {"exit_code": exit_code})

    # -- register helpers ---------------------------------------------------------
    def _map_registers(self, rows: Any) -> dict[str, str]:
        names = self._register_names
        out: dict[str, str] = {}
        for row in rows if isinstance(rows, list) else []:
            try:
                index = int(row["number"])
            except (KeyError, TypeError, ValueError):
                continue
            name = names[index] if index < len(names) else f"r{index}"
            out.setdefault(self._reg_display(name), str(row.get("value", "")))
        return out

    @staticmethod
    def _reg_display(name: str) -> str:
        name = name.lstrip("$")
        return f"${name}" if name else name

    def _refresh_registers(self) -> dict[str, str]:
        controller = self._controller
        if controller is None:
            return {}
        try:
            records = controller.write(
                "-data-list-register-values x", timeout_sec=COMMAND_TIMEOUT
            )
        except (GdbTimeoutError, BrokenPipeError, OSError, ValueError) as exc:
            self._emit(T_ERROR, {"message": f"registers: {exc}"})
            return {}
        for record in records:
            if record.get("type") == "result" and isinstance(record.get("payload"), dict):
                return self._map_registers(record["payload"].get("register-values", []))
        return {}

    def _announce_registers(self, values: dict[str, str]) -> None:
        queued_change = self._changed_keys(values)
        self._prev_registers = dict(values)
        self._emit(
            T_REGISTERS,
            {
                "values": values,
                "changed": sorted(queued_change),
                "pc": values.get("$rip") or values.get("$pc", ""),
                "sp": values.get("$rsp") or values.get("$sp", ""),
            },
        )

    def _refresh_registers_and_announce(self, reason: str) -> None:
        regs = self._refresh_registers()
        self._emit(
            T_STOPPED,
            {
                "reason": reason,
                "pc": self._evaluate("$pc"),
                "sp": self._evaluate("$sp"),
                "frame": {},
                "regs": regs,
                "changed": [],
            },
        )

    def _changed_keys(self, values: dict[str, str]) -> set[str]:
        changed = {
            name
            for name, val in values.items()
            if name not in self._prev_registers
            or self._prev_registers[name] != val
        }
        return changed - {"$rip", "$rsp"}  # pc/sp shown separately per stop

    def _evaluate(self, expr: str) -> str:
        controller = self._controller
        if controller is None:
            return ""
        try:
            records = controller.write(
                f"-data-evaluate-expression {expr}", timeout_sec=COMMAND_TIMEOUT
            )
        except (GdbTimeoutError, BrokenPipeError, OSError, ValueError):
            return ""
        for record in records:
            if record.get("type") == "result" and isinstance(record.get("payload"), dict):
                value = record["payload"].get("value")
                if value is not None:
                    return str(value)
        return ""

    # -- memory ----------------------------------------------------------------
    def _announce_memory(self, block: dict[str, Any]) -> None:
        try:
            begin = int(str(block.get("begin", "0x0")), 16)
        except ValueError:
            return
        contents = str(block.get("contents", ""))
        size = len(contents) // 2
        if size <= 0:
            return
        sp_hex = self._evaluate("$sp") if self._state == "stopped" else ""
        # stack-window shape → annotated word table
        if size % 8 == 0 and size >= 16 and sp_hex:
            try:
                sp_int = int(sp_hex, 16)
                bytes_hex = [contents[i : i + 2] for i in range(0, len(contents), 2)]
                raw = bytes.fromhex(contents)
                rows = []
                for i in range(0, size // 8):
                    address = begin + i * 8
                    word = int.from_bytes(raw[i * 8 : i * 8 + 8], "little", signed=False)
                    rows.append(
                        {
                            "address": hex(address),
                            "is_sp": address == sp_int,
                            "word_hex": format(word, "016x"),
                            "bytes_hex": "".join(bytes_hex[i * 16 : i * 16 + 16]),
                        }
                    )
                self._emit(
                    T_STACK_WORDS, {"sp": hex(sp_int), "base": hex(begin), "size": size, "words": rows}
                )
            except ValueError:
                pass
        self._emit(T_MEMORY_READ, {"address": hex(begin), "size": size, "hex": contents})

    # -- breakpoints --------------------------------------------------------------
    def _track_breakpoint(self, info: dict[str, Any]) -> None:
        number = str(info.get("number", "?"))
        if number not in self._breakpoints and number != "?":
            try:
                address = int(str(info.get("addr", "")), 16)
            except ValueError:
                address = None
            self._breakpoints[number] = Breakpoint(
                number=number,
                address=address,
                func=str(info.get("func", "") or ""),
                enabled=str(info.get("enabled", "y")) == "y",
                temp=str(info.get("disp", "")) == "del",
            )

    def _announce_breakpoints(self) -> None:
        self._emit(
            T_BP_UPDATED,
            {"breakpoints": sorted(
                (bp.as_dict() for bp in self._breakpoints.values()),
                key=lambda d: (d["address"] or "", d["number"]),
            )},
        )
        numbers = ",".join(sorted(self._breakpoints)) or "(none)"
        log.debug("breakpoints now: %s", numbers)

    def _set_state(self, state: str) -> None:
        if state != self._state:
            self._state = state
            self._emit(T_STATE, {"state": state})


# ------------------------------------------------------------------ helpers
def _mi_quote(text: str) -> str:
    """Escape *text* so gdb/MI parses it as one string argument."""
    escaped = (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", " ")
    )
    return f'"{escaped}"'


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
