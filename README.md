# LegendScan — Kernel Cheat Engine Clone

Dark Win32 scanner for Windows x64, powered by custom kernel driver
`amdfend.sys` (`AMD_CrashDefend` cover). All memory access goes through
the driver — zero `OpenProcess` / `ReadProcessMemory` handles from usermode.
Kernel-side AOB/value scan (`ls_scan_code`) = DMA-style speed without hardware.

> Research / educational project. Use at your own risk.

## Projects

| Project   | Output        | Role                                              |
| --------- | ------------- | ------------------------------------------------- |
| `Scanner` | `Scanner.exe` | CE-clone GUI (dark) + kernel scan engine          |
| `Loader`  | `Loader.exe`  | Driver loader (`NtLoadDriver`, EfiGuard, no BYOVD) |
| `amdfend` | `amdfend.sys` | Kernel driver: read/write/alloc/module+scan/query+stealth |

## Features (Scanner)

- **Attach** by process name or PID (driver `ls_init_code` + `PsLookupProcessByProcessId`)
- **Value types**: U8/U16/U32/U64/I32/I64/Float/Double/String/AOB (`??` wildcards)
- **Scan types**: Exact / Bigger / Smaller / Between / Increased / Decreased / Changed / Unchanged
- **First Scan**: kernel scan per committed RW region (`ls_scan_code`, 64KB chunks, overlap-safe, 256 hits/IOCTL, 32MB splits)
- **Next Scan**: re-read candidates via driver, numeric-aware compare (float/double NaN-safe)
- **Memory View**: hex dump + WriteBytes (hex string) + Read/Write selected row (verified)
- **Dark UI**: midnight + blue accent, Segoe UI + Consolas, standard Win32 controls themed

## Driver (amdfend)

- Device `\\Device\\AMD_CrashDefend` + `\\DosDevices\\AMD_CrashDefend`, service `amdfend`
- `IoCreateDriver(\\Driver\\AmdPpkg)` + spoof to `WdNisDrv`
- IOCTLs `0x19C1..0x19C9`: init/read/write/module/alloc/free/version/**scan/query**
- `scan_req_t`: start/size + pat[32]/msk[32] + patLen + maxHits(256) + hits[256]
- `query_req_t`: addr -> base/size/state/protect/type (via `ZwQueryVirtualMemory` + kernel handle)
- Stealth: PiDDB wipe (`amdfend.sys`), MmUnloaded scrub, SecureBoot/TPM spoof, ETW+ETW-TI patch, MmCopy hook, watcher thread, jitter — same lineage as nv_disp, new build tag `0x00080001`

## Quick start

1. Build `LegendScan.sln` → **Release x64** (VS2022 + WDK)
2. Copy `EfiDSEFix.exe` next to `Loader.exe`/`amdfend.sys` (or reuse from DesAnime `x64/Release`)
3. Run `Scanner.exe` **as Admin** — auto `EfiDSEFix -d` → `Loader.exe amdfend.sys --no-dsefix --keep` → `-e`, polls `\\.\AMD_CrashDefend`
4. Target + Attach → pick type → First Scan → change value in game → Next Scan → select row → Read/Write
5. Manual load (Admin CMD): `EfiDSEFix.exe -d` → `Loader.exe amdfend.sys --no-dsefix --keep` → `EfiDSEFix.exe -e`

## Layout

```
amdfend/   kernel driver (driver.cpp, AmdNeed.h, amdfend.inf)
Scanner/   CE GUI + engine (main.cpp, scanner.hpp)
Loader/    driver loader (main.cpp)
```

## Requirements

- Windows 10/11 x64, VS2022 + WDK, admin rights
- Secure Boot OFF (or EfiGuard), HVCI / Memory Integrity OFF
- `EfiDSEFix.exe` for DSE disable at runtime
