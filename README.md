# 80PWNER — An Integrated GUI Pwn / Binary Analysis Workbench

```text
████████╗██╗  ██╗███████╗ █████╗  ██████╗       ██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗ 
╚══██╔══╝██║  ██║██╔════╝██╔══██╗██╔═████╗      ██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗
   ██║   ███████║█████╗  ╚█████╔╝██║██╔██║█████╗██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝
   ██║   ██╔══██║██╔══╝  ██╔══██╗████╔╝██║╚════╝██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗
   ██║   ██║  ██║███████╗╚█████╔╝╚██████╔╝      ██║     ╚███╔███╔╝██║ ╚████║███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚════╝  ╚═════╝       ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

**80PWNER — by Anas Mahfouz (The80)**

One desktop app instead of the scattered terminal workflow of CTF pwn (checksec,
objdump, gdb+pwndbg, ROPgadget, cyclic patterns, notes). Open a binary once —
every module works on the same target and stays synchronized.

> Educational + CTF use (pwn.college, picoCTF, HackTheBox, local labs).
> Analyze and debug binaries you own or are authorized to test.

## Features (build status: Step 4 of 10 ✅)

- **Theme system** — Dark / Light / follow-system, persisted; red accent
  (#FF2D3D dark / #C8102E light); semantic colors stay separate so checksec
  badges remain green=enabled / red=disabled; WCAG-contrast tested
- **Plugin system** — every module is an independent plugin on an event bus;
  third-party plugins plug in via the `80pwner.plugins` entry-point group
- **Binary Overview + checksec** — ELF / PE / Mach-O via LIEF (pyelftools
  fallback)*: arch/bits/endianness/entry, sections, segments, symbols,
  imports/exports, strings (interesting first), colored mitigation badges
  (NX, PIE, RELRO, canary, fortify) with one-line explanations, and
  dangerous-function highlighting (gets, strcpy, system, printf-family…)
- **Disassembler + function list** — Capstone engine (x86 32/64, ARM,
  AArch64, MIPS, PPC, RISC-V); discover functions from symbols + entry +
  call targets with per-function lazy decoding (big binaries stay fast);
  address/bytes/instruction view with token-based syntax coloring, Intel/AT&T
  toggle (x86), function filter + sort, xrefs to/from, Ctrl+G address jump,
  back/forward history, double-click call/jmp navigation, per-session
  comments and renamed symbols (persisted JSON), right-click copy
- **Debugger (live GDB/MI)** — run dialogs (args / stdin-file / env / working
  dir, break at main) or attach to a PID; Registers panel (changed values
  highlighted, editable — Enter rewrites the register), Stack panel (words
  around $sp with pointer annotations), hex Memory view (go-to `0x…`/`$sp`,
  click-to-edit bytes), Breakpoints panel (add 0x… or fn-name,
  enable/disable/delete), GDB console (MI or plain `c` / `info locals`) and
  Program I/O (live stdout on a pty + stdin box); shortcuts F5 run/continue,
  F9 toggle breakpoint (in the disassembly too — menu or F9), F10 step over,
  F11 step into, Shift+F11 finish; the disassembly view follows the debugger:
  current-instruction marking, navigation to the stop address and breakpoint
  marks; clean shutdown kills gdb + the debuggee (no orphans)
- Cross-platform: platformdirs paths (+ auto-migration from `~/.80pwner`),
  bundled JetBrains Mono (OFL), Fusion Qt style, high-DPI scaling

\* Live debugging: GDB/MI on **Linux (full support)**; on macOS/Windows 80PWNER
detects what's available and degrades to static analysis with clear install
hints — no crashes, no silent failures.

## Install (per OS)

### Linux (Mint/Debian first)

```bash
sudo apt install gdb                 # debugger backend, Steps 4+
pipx install .                       # or: pip install .
80pwner                              # or: ./80pwner
```

### Windows

```bash
py -3 -m pip install -U pip
pip install .
python -m eightypwner                # or: 80pwner.bat
```

### macOS

```bash
brew install gdb                     # note: codesign may be required
pipx install .
80pwner                              # python3 -m eightypwner --no-splash
```

### Launcher details

- `./80pwner` (bash) uses `.venv` if present, else the installed package, else
  runs straight from `src/` for development
- `80pwner.bat` (Windows) does the same for `%DIR%.venv\Scripts\python.exe`
- `python -m eightypwner` always works

### Options

```
80pwner [--version] [--no-splash] [--theme {dark,light,system}] [--log-level LEVEL]
```

### Engine dependencies

Core needs only PySide6 + platformdirs. From Step 2 onward install the
`analysis` extra: `pipx install '80pwner[analysis]'` or
`pip install '.[analysis]'` (pwntools, capstone, LIEF, pygdbmi, keystone,
pyelftools). The About dialog shows what's present with install hints per
missing tool.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,analysis]'
ruff check src tests      # lint
pytest                    # headless (offscreen Qt by default)
./80pwner                 # run from source
```

- CI: GitHub Actions matrix (ubuntu / windows / macos) runs ruff, pytest and an
  offscreen GUI smoke test on every push/PR
- Packaging: `pyproject.toml` is the source of truth; PyInstaller spec at
  `packaging/80pwner.spec` for standalone bundles (build when ready):
  `pip install pyinstaller && pyinstaller packaging/80pwner.spec`
- Sample targets: `tests/samples/build_samples.sh` compiles `vulnerable.c`
  into three ELF variants — `vuln_none.elf` (no protections),
  `vuln_defaults.elf` (distro defaults), `vuln_full.elf` (all mitigations)

## Delivery plan

1. ✅ Scaffold, theme manager, main window, branding, plugin system
2. ✅ Binary Overview + checksec (+ samples)
3. ✅ Disassembler + function list (Capstone)
4. GDB/MI integration + Debugger GUI
5. Stack Visualizer
6. Gadget Finder + Pattern Tool
7. CFG + Libc helper
8. Heap Visualizer
9. Script Generator + Notes/Session Manager
10. Packaging, tests, screenshots, polish

---

*Made by The80* — Anas Mahfouz
