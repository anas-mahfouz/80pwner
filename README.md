# 80PWNER — by Anas Mahfouz (The80)
# 80PWNER — An Integrated GUI Pwn / Binary Analysis Workbench

```text
 ██████╗  █████╗   ██████╗ ██╗    ██╗ ███╗   ██╗ ███████╗ ██████╗
 ██╔══██╗ ██╔══██╗ ██╔════╝ ██║    ██║ ████╗  ██║ ██╔════╝ ██╔══██╗
 ██████╔╝ ███████║ ██║      ██║ █╗ ██║ ██╔██╗ ██║ █████╗   ██████╔╝
 ██╔══██╗ ██╔══██╗ ██║      ██║███╗██║ ██║╚██╗██║ ██╔══╝   ██╔══██╗
 ██████╔╝ ██║  ██║ ╚██████╗ ╚██╔╝██╔╝ ██║ ╚████║ ███████╗ ██║  ██║
 ╚═════╝  ╚═╝  ╚═╝  ╚═════╝   ╚═╝ ╚═╝  ╚═╝  ╚═══╝ ╚══════╝ ╚═╝  ╚═╝
```

**80PWNER — by Anas Mahfouz (The80)**

A single desktop application that replaces the scattered terminal workflow of CTF pwn
(checksec, objdump, gdb+pwndbg, ROPgadget, cyclic patterns, notes) with one integrated,
modern GUI. Open a binary once — every module works on the same target and stays
synchronized.

> Educational + CTF use (pwn.college, picoCTF, HackTheBox, local labs).
> Analyze and debug binaries you own or are authorized to test.

## Features

- Dark / Light themes (neon-green mono hacker aesthetic), persisted between launches
- Plugin-based modules communicating over an event bus
- Binary Overview + checksec, Capstone disassembler, GDB/MI debugger GUI,
  stack & heap visualizers, ROP gadget finder, pattern/offset tool, libc map helper,
  pwntools script generator, notes/session manager *(delivered step-by-step)*
- Heavy work always runs off the UI thread

## Install

```bash
# System deps (Debian/Mint): gdb for the debugger backend
sudo apt install gdb

# Application
pipx install .            # or: pip install .
80pwner
```

## Launcher

`80pwner [--version] [--no-splash] [--theme {dark,light,system}] [--log-level LEVEL]`

## Status

Delivery plan — **Step 1 of 10 complete**: project scaffold, theme manager
(dark/light/system), main window, branding, plugin system.
Binary Overview & checksec arrive in Step 2.

---

*Made by The80* — Anas Mahfouz
