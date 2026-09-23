# Install — LegendScan

## 1. Requirements

| Item | Notes |
| ---- | ----- |
| Windows 10/11 x64 | Tested on Win10/11; driver targets Win10+ |
| Visual Studio 2022 | Desktop C++ workload, MSVC v143, Win10/11 SDK |
| WDK | Required only for `amdfend` (kernel driver) |
| Administrator rights | Driver load + `SeLoadDriverPrivilege` |
| Secure Boot OFF (or EfiGuard) | Otherwise `NtLoadDriver` fails `0xC000010E` |
| HVCI / Memory Integrity OFF | Test-signed driver will not load otherwise |
| `EfiDSEFix.exe` | Ships in `x64/Release/` — disables DSE at runtime |

## 2. Build

1. Open `LegendScan.sln` in Visual Studio 2022
2. Configuration: **Release**, Platform: **x64**
3. Build → Solution. Outputs land in `x64/Release/`:
   `Scanner.exe`, `Loader.exe`, `amdfend.sys`, `amdfend.inf`
   (plus project-local copies under `Scanner\x64\Release` etc.)

> Close a running `Scanner.exe` first, or the linker fails with
> `LNK1104: cannot open file` (file locked — not a code bug). If the
> driver is resident, unload it first (see §3) or the `.sys` link fails
> the same way.
> The `INF verification exception: Unable to load DLL 'x86\InfVerif.dll'`
> error is harmless environment noise — `amdfend.sys` is still produced
> and signed.

## 3. Load the driver

Auto (recommended): just run `x64\Release\Scanner.exe` **as Administrator** —
it runs `EfiDSEFix -d` → `Loader.exe amdfend.sys --no-dsefix --keep` → `-e`
by itself and polls `\\.\AMD_CrashDefend` until `Driver OK v00080004`.

Manual (Admin CMD, from `x64\Release\`):

```cmd
EfiDSEFix.exe -d
Loader.exe amdfend.sys --no-dsefix --keep
EfiDSEFix.exe -e
```

Other `Loader.exe` flags: `--unload-only` (unload a resident driver without
loading — use before replacing `amdfend.sys`), `--unload` (load then unload
after Enter), default (no flag) waits for Enter then unloads.

## 3b. EfiGuard without pendrive (manual, optional)

Same recipe as DesAnime (`Install.md` §3b): mount ESP, copy
`bootx64.efi` + `EfiGuardDxe.efi` to `ESP:\EFI\AnimeBoot\`, create a minimal
`bcdedit` entry (device + path only), keep Secure Boot OFF. To remove later:
`bcdedit /delete {GUID}` + delete `ESP:\EFI\AnimeBoot\`.

## 4. Troubleshooting

| Symptom | Cause / fix |
| ------- | ----------- |
| `NtLoadDriver failed: 0xC000010E` | DSE still on — boot EfiGuard / run `EfiDSEFix -d` properly |
| `NtLoadDriver failed: 0xC0000022` | Not admin |
| `Driver MISSING` pill | Admin + EfiGuard + Secure Boot + HVCI (§1), then manual load §3 |
| `Driver tag xxxxxxxx (update!)` | Resident old driver — `--unload-only` (or reboot), run Scanner again |
| `LNK1104` on rebuild | Close Scanner / unload driver first (file locked) |
| `0 hits` on everything | Attach first; check Writable filter + Start/Stop range + module scope |
| `Write FAILED` | Attach first; MDL fallback covers read-only pages — retry, then report |
| Module list empty | Toolhelp blocked (protected game) — scope stays `All`, scan still works |
| List shows `??` | Unreadable page (freed) or module not rebased yet — re-attach |
| `=???` preview in dialogs | Same as above — attach + valid address first |

## 5. Version tags

- Driver `LS_BUILD_TAG` / Scanner check: current `0x00080004`
  (inject + module-enum). Scanner warns `(update!)`
  (MDL write fallback + kernel module-enum). Scanner warns `(update!)`
  on mismatch — always run matched pairs from the same build.
