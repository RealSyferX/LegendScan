# LegendScan — Kernel Cheat Engine Clone

Cheat Engine–style memory scanner for Windows x64, powered by a custom
kernel driver (`amdfend.sys`, `AMD_CrashDefend` cover). All memory access
goes through the driver — zero `OpenProcess` / `ReadProcessMemory` handles
from usermode. Kernel-side AOB/value scan = DMA-style speed without hardware.

> Research / educational project. Use at your own risk.

## Projects

| Project   | Output        | Role                                                     |
| --------- | ------------- | -------------------------------------------------------- |
| `Scanner` | `Scanner.exe` | CE-clone GUI + scan engine + address table + viewer      |
| `Loader`  | `Loader.exe`  | Driver loader (`NtLoadDriver`, EfiGuard edition, no BYOVD) |
| `amdfend` | `amdfend.sys` | Kernel driver: read / write / alloc / module / scan / query + stealth |

## Features

- **Attach** — CE-style Process List (name + PID, sorted, double-click to
  attach) or manual name/PID entry; title bar shows `PID-proc` like CE
- **Value types** — 1/2/4/8 Bytes, Float, Double, String, Array of Byte
  (`??` wildcards), Hex display toggle
- **Scan types** — Exact / Bigger / Smaller / Between (`100 200`) /
  Increased / Decreased / Changed / Unchanged
- **First Scan** — kernel scan per committed region (`ls_scan_code`, 64 KB
  chunks, overlap-safe, 256 hits/IOCTL); generic compare path for the rest
- **Module scope** — Memory Scan Options dropdown lists target modules
  (`notepad.exe`, `ntdll.dll`, …); picking one auto-fills Start/Stop and
  clips the scan to the module range
- **Filters** — Writable (default ON), Executable, CopyOnWrite, Fast Scan +
  Alignment, Start/Stop range, Undo Scan (10 deep)
- **Found list** — Address | Value | Previous; double-click drops the hit
  straight into the address table
- **Address table** — Active (freeze) + Description + Address + Type + Value,
  live in-place refresh (selection never stolen), per-column double-click
  popups: Change Value / Type / Description / Change-address
- **Pointers** — multilevel chains (up to 5 offsets, Add/Remove at will)
  with live chain preview (`base -> … -> final = value`)
- **Static addresses** — `"module.dll"+OFF` syntax, rebased via the driver
  on every refresh (survives ASLR/game restart), shown as `"mod"+OFF`
- **Memory Viewer** — hex dump + WriteBytes, separate window like CE
- **Legend Table (.ltb)** — File → New / Open / Save; tiny XML storing
  active, desc, addr/module, type, signed/hex, pointer chain and bytes
- **Writes that land** — driver `MdlWrite` fallback handles `PAGE_READONLY`
  pages `MmCopyVirtualMemory` refuses; every write is read-back verified

## Quick start

1. Build `LegendScan.sln` → **Release x64** (see [Install.md](Install.md))
2. Boot EfiGuard, run `x64\Release\Scanner.exe` **as Administrator**
   (auto-loads the driver — wait for `Driver OK v00080003`)
3. PC → pick process → First Scan → change value in game → Next Scan →
   double-click hit → tick Active to freeze (see [Guide.md](Guide.md))

## Docs

- [Install.md](Install.md) — requirements, build, driver loading, troubleshooting
- [Guide.md](Guide.md) — UI tour, dialogs, workflows, table format

## Layout

```
amdfend/   kernel driver (driver.cpp, AmdNeed.h, amdfend.inf)
Scanner/   CE GUI + engine (main.cpp, scanner.hpp)
Loader/    driver loader (main.cpp)
x64/Release/  build outputs: Scanner.exe, Loader.exe, amdfend.sys (+ EfiDSEFix.exe)
```

## Driver IOCTLs (`0x19C1`–`0x19CA`, build tag `0x00080003`)

| Code | Op | Notes |
| ---- | -- | ----- |
| `0x19C1` | init | `PsLookupProcessByProcessId` → `PEPROCESS` |
| `0x19C2` | read | `MmCopyVirtualMemory` target → caller |
| `0x19C3` | write | `MmCopyVirtualMemory`, fallback MDL writable map |
| `0x19C4` | module | base via `PsGetProcessPeb` → LDR walk |
| `0x19C5`/`0x19C6` | alloc/free | `ZwAllocateVirtualMemory` / `ZwFreeVirtualMemory` on kernel handle |
| `0x19C7` | version | build tag |
| `0x19C8` | scan | masked pattern scan, 64 KB chunks, 256 hits max |
| `0x19C9` | query | `ZwQueryVirtualMemory` region info (for region walk) |
| `0x19CA` | mods | full PEB/LDR walk — module list even when Toolhelp is stripped (BE) |

Stealth: PiDDB wipe (`amdfend.sys`), `MmUnloadedDrivers` scrub,
SecureBoot/TPM spoof, ETW + ETW-TI patch, `MmCopyVirtualMemory` trampoline,
unload-history wipe, jitter, Chrome-style usermode hygiene (XOR strings,
hidden threads).

## Requirements (short)

- Windows 10/11 x64, Visual Studio 2022 + WDK, admin rights
- Secure Boot OFF (or EfiGuard), HVCI / Memory Integrity OFF
- Details: [Install.md](Install.md)
