# 80PWNER — An Integrated GUI Pwn / Binary Analysis Workbench

```text
█████ █   █ █████  ███   ███        ████  █   █ █   █ █████ ████ 
  █   █   █ █     █   █ █   █       █   █ █   █ ██  █ █     █   █
  █   █   █ █     █   █ █  ██       █   █ █   █ █ █ █ █     █   █
  █   █████ ████   ███  █ █ █  ███  ████  █   █ █ █ █ ████  ████ 
  █   █   █ █     █   █ ██  █       █     █ █ █ █ █ █ █     █ █  
  █   █   █ █     █   █ █   █       █     █ █ █ █  ██ █     █  █ 
  █   █   █ █████  ███   ███        █      █ █  █   █ █████ █   █
```

**80PWNER — by Anas Mahfouz (The 80)**

> **Download:** [standalone builds for Linux / Windows / macOS](https://github.com/the80/80pwner/releases/latest)
> · **Install:** `pipx install "80pwner[analysis] @ git+https://github.com/the80/80pwner.git"`
> · **License:** MIT

One desktop app instead of the scattered terminal workflow of CTF pwn (checksec,
objdump, gdb+pwndbg, ROPgadget, cyclic patterns, notes). Open a binary once —
every module works on the same target and stays synchronized.

> Educational + CTF use (pwn.college, picoCTF, HackTheBox, local labs).
> Analyze and debug binaries you own or are authorized to test.

## Features (build status: Step 10 of 10 ✅)

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
- **Stack Visualizer (live frame diagram)** — a vertical diagram of the
  selected debuggee frame with high addresses on top: return address, saved
  RBP, stack canary (checksec + `fs:0x28`/`gs:0x14` disassembly pattern +
  heuristic), locals/buffers (DWARF when built with `-g`, else inferred from
  `sub rsp` / `[rbp-X]` references), and on-demand filler rows for unknown
  bytes. Each row shows its address, RBP/RSP-relative offsets, size, raw
  value and a pointer/ASCII annotation (symbol±offset with the PIE runtime
  delta; double-click a pointer to follow it into the Memory view). The
  "buffer start → canary / saved RBP / return address" distances recompute on
  every stop and copy with one click; changed stack words highlight in the
  accent color; a frame selector walks the backtrace; x86-64 and x86 (32-bit)
  first — other architectures show a clear explanation instead of crashing;
  frame-pointerless builds degrade to a raw SP word-dump with a
  `-fno-omit-frame-pointer` note
- **Gadget Finder (x86/x86-64 ROP/JOP)** — scans the loaded binary plus any
  extra module you load (libc.so.6, …) for gadgets ending in `ret`,
  `ret imm16`, `jmp reg`, `call reg`, `syscall` and `int 0x80`; the classic
  two-phase scan (byte-pattern terminators, then walk-back decoding that
  keeps only whole-instruction chains) runs in a worker thread with live
  progress + cancellation (partial results kept). Filter by registers,
  instruction regex, max length, bad bytes (excluded from gadget bytes AND
  both little-endian address encodings) and ending kinds; sortable results
  table with search-as-you-type; one-click copy of the address as `p64` /
  `p32` / raw hex / gadget bytes / gadget text (double-click = p64).
  Executable scan ranges come from x-flagged LOAD segments ∩ PROGBITS
  sections (16 MB cap with a note); non-x86 binaries say so instead of
  crashing; per-module caches invalidate on binary reload
- **Pattern Tool (cyclic patterns + crash offset)** — pwntools-compatible
  de Bruijn pattern generator (`aaaabaaacaaadaaaeaaa`, n=2..8, up to 2 MB,
  verified against pwnlib's doctests) with one-click copy; find the crash
  offset from `0x…` hex, decimal, byte pairs (`61 61 61 62`) or the ASCII
  chunk (`baaa`); a live register dropdown fills the lookup from the
  stopped debugger, and a crash stop (SIGSEGV/SIGBUS/SIGILL/SIGFPE)
  automatically scans the register dump byte-windows and proposes the
  smallest matching offset
- **Control Flow dock** — build an interactive basic-block CFG for any
  discovered function (or a typed address): branch targets become leaders,
  blocks split on every control-flow boundary, conditional/true/false,
  jump and fallthrough edges are drawn with distinct colors, and clicking a
  block shows its disassembly (and publishes the address to the rest of the
  app). Live theme-aware rendering with pan/zoom/fit, per-build worklist
  budgets (max blocks/instructions) with a truncation note instead of a
  freeze, and one-click Graphviz DOT export
- **Libc Helper** — fingerprint the exact `libc.so.6` (glibc version, arch,
  bits, build-id, `/bin/sh` and `system()` offsets), searchable symbol table
  with file-relative offsets, heuristic one-gadget scan (only candidates
  whose constraints are verified by backtracking the register setup), base
  computation from a `puts`/`printf`/… leak, and a ret2libc chain builder
  that emits `p64` lines with automatic stack alignment. Publishes
  `libc_loaded` / `libc_base_computed` so the Script Generator and any
  third-party plugin stay in sync
- **Heap Visualizer** — snapshot the live glibc heap through the debugger
  (or parse a dump): walks the malloc chunk chain with `PREV_INUSE`
  correction, highlights free vs in-use vs wilderness/top chunks, parses the
  `tcache_perthread_struct` with both the modern (`uint16_t` counts) and
  legacy (`char` counts) layouts, flags corrupt counts (> 7), malformed
  sizes and duplicate tcache entries, and shows chunk addresses, sizes,
  flags and state in a sortable table. Snapshots are read in 4 KiB MI chunks
  so large heaps don't wedge GDB
- **Script Generator** — turn the loaded binary into a runnable pwntools
  exploit: skeleton, ret2win, ret2libc and shellcode templates; carries the
  architecture, bits, checksec mitigations, interesting symbols, libc path,
  one-gadget candidates, gadget addresses and the Pattern Tool crash offset
  into the script; local/remote/gdb `start()` helper, `p64` chain layout and
  stack alignment included; every rendered template is syntax-checked in the
  test-suite
- **Challenges (sessions + notes)** — per-binary SQLite library keyed by the
  target's SHA-256: reuse the session on reopen, keep free-form notes with
  debounced autosave, record findings (severity/title/address/detail) in a
  sortable table, pull the latest Pattern Tool offset into a finding, and
  export the whole writeup as Markdown or JSON
- **Payload Studio** — assemble shellcode from curated presets or your own
  asm (x86/x86-64/ARM/AArch64/MIPS/PPC/SPARC via Keystone), disassemble the
  result with Capstone, check for bad bytes, format/copy the output as
  Python/C/escaped/hex/base64, XOR-encode with a self-decoding x86-64 stub
  and an auto-selected bad-byte-free key (the stub itself is NUL-free), and
  plan format-string writes: paste `%p` output to find the argument offset,
  then build the exact `%hn` payload and address table (plus the equivalent
  `fmtstr_payload()` line)
- Cross-platform: platformdirs paths (+ auto-migration from `~/.80pwner`),
  bundled JetBrains Mono (OFL), Fusion Qt style, high-DPI scaling

\* Live debugging: GDB/MI on **Linux (full support)**; on macOS/Windows 80PWNER
detects what's available and degrades to static analysis with clear install
hints — no crashes, no silent failures.

## Install & run

80PWNER runs from a terminal on Linux, Windows (CMD/PowerShell) and macOS.
Pick whichever path fits your machine — all three give the same app.

### 1. Standalone binary — no Python required (recommended)

Download the archive for your platform from the
[latest release](https://github.com/the80/80pwner/releases/latest), extract it,
and run the executable inside the `80pwner/` folder:

| Platform | Archive | Run |
|---|---|---|
| Linux x86-64 | `80pwner-linux-x86_64.tar.gz` | `./80pwner/80pwner` |
| Windows x64 | `80pwner-windows-x86_64.zip` | `80pwner\80pwner.exe` |
| macOS Apple Silicon | `80pwner-macos-arm64.tar.gz` | `./80pwner/80pwner` |
| macOS Intel | `80pwner-macos-x86_64.tar.gz` | `./80pwner/80pwner` |

Linux / macOS one-liner:

```bash
curl -L https://github.com/the80/80pwner/releases/latest/download/80pwner-linux-x86_64.tar.gz | tar xz
chmod +x 80pwner/80pwner
./80pwner/80pwner
```

Windows CMD:

```bat
curl -LO https://github.com/the80/80pwner/releases/latest/download/80pwner-windows-x86_64.zip
tar -xf 80pwner-windows-x86_64.zip
80pwner\80pwner.exe
```

Windows 10+ ships `tar`; you can also just right-click the downloaded `.zip` →
*Extract All* and double-click `80pwner.exe`.

> The bundles are unsigned. If macOS refuses to start one, run
> `xattr -dr com.apple.quarantine ./80pwner`; on Windows SmartScreen choose
> *More info → Run anyway*. The Linux build targets glibc 2.35+ (Ubuntu 22.04
> and newer).
>
> On a minimal Linux install Qt may need its X11/OpenGL runtime libraries:
> `sudo apt install libgl1 libegl1 libxkbcommon-x11-0 libxcb-cursor0`
> (Fedora: `sudo dnf install mesa-libGL libxkbcommon-x11 libxcb`).

### 2. pipx / pip — any OS with Python 3.11+

```bash
pipx install "80pwner[analysis] @ git+https://github.com/the80/80pwner.git"
80pwner
```

Or from a clone, with the engine extras:

```bash
git clone https://github.com/the80/80pwner && cd 80pwner
pipx install '.[analysis]'
80pwner
```

### 3. From source — one command, auto-bootstraps

```bash
git clone https://github.com/the80/80pwner && cd 80pwner
./80pwner                 # Linux/macOS: creates .venv + installs deps on first run
```

```bat
git clone https://github.com/the80/80pwner
cd 80pwner
80pwner.bat               rem Windows: same bootstrap
```

The launchers create `.venv` and install `.[analysis]` the first time, then
just run the app. Set `EIGHTYPWNER_NO_BOOTSTRAP=1` to skip that, or
`EIGHTYPWNER_EXTRAS=all` to also install pwntools.

### Debugger backend

The GUI, disassembler, CFG, heap parser, gadget finder and payload studio work
without a debugger. Live debugging uses GDB/MI:

```bash
sudo apt install gdb        # Debian/Ubuntu/Mint
sudo dnf install gdb        # Fedora
brew install gdb            # macOS (codesign may be required)
```

Windows has no native GDB/MI backend yet; 80PWNER detects this and degrades to
static analysis with install hints instead of failing.

### Options

```
80pwner [--version] [--no-splash] [--theme {dark,light,system}] [--log-level LEVEL]
```

### Engine dependencies

Core needs only PySide6 + platformdirs. The `analysis` extra adds the engine
backends: capstone (disassembly), LIEF (binary parsing), pygdbmi (GDB/MI),
keystone-engine (assembly) and pyelftools (ELF fallback). `pwntools` is *not*
imported by the app — install the `pwntools`/`all` extra only if you want to
run the exploits the Script Generator writes. The About dialog shows what's
present with install hints per missing tool.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,analysis]'
ruff check src tests      # lint
pytest                    # headless (offscreen Qt by default)
./80pwner                 # run from source
```

- CI: GitHub Actions matrix (ubuntu / windows / macos) runs ruff, pytest and an
  offscreen GUI smoke test on every push/PR, plus a PyInstaller bundle build
- Release: pushing a `v*` tag runs `.github/workflows/release.yml`, which builds
  Linux / Windows / macOS standalone bundles and the sdist+wheel, smoke-tests
  each bundle, and attaches them to the GitHub release
- Build a bundle locally:
  `pip install -e '.[analysis]' pyinstaller && pyinstaller --noconfirm --clean packaging/80pwner.spec`
  → `dist/80pwner/80pwner` (or `dist\80pwner\80pwner.exe`)
- Build a wheel/sdist: `python -m build` (assets, fonts and themes are package
  data and are verified by the release workflow)
- Sample targets: `tests/samples/build_samples.sh` compiles `vulnerable.c`
  into three ELF variants — `vuln_none.elf` (no protections),
  `vuln_defaults.elf` (distro defaults), `vuln_full.elf` (all mitigations)

### Publishing a release

The workflows assume the repository is `github.com/the80/80pwner`; update the
URLs in `pyproject.toml` and this README if yours differs. Then:

```bash
git remote add origin https://github.com/<you>/80pwner.git   # once
git push -u origin master

git tag v1.0.0
git push origin v1.0.0        # builds Linux/Windows/macOS bundles + sdist/wheel
```

The tag push runs `.github/workflows/release.yml`; when it finishes, the
release page has the standalone archives and the Python distributions. To
build artifacts without publishing, run the workflow manually from the Actions
tab (`workflow_dispatch`).

## Delivery plan

1. ✅ Scaffold, theme manager, main window, branding, plugin system
2. ✅ Binary Overview + checksec (+ samples)
3. ✅ Disassembler + function list (Capstone)
4. ✅ GDB/MI integration + Debugger GUI
5. ✅ Stack Visualizer
6. ✅ Gadget Finder + Pattern Tool
7. ✅ CFG + Libc helper
8. ✅ Heap Visualizer
9. ✅ Script Generator + Notes/Session Manager
10. ✅ Packaging, tests, polish (plus Payload Studio — shellcode/XOR/format-string workbench)

---

*Made by The 80* — Anas Mahfouz · © 2026
