# Guide — LegendScan

## Run order (important)

1. Boot EfiGuard (USB or AnimeMode entry)
2. Run `x64\Release\Scanner.exe` **as Administrator**
3. Wait for **`Driver OK v00080003`** in the status bar
4. PC → attach target → scan

> The driver stays loaded (`--keep`) after Scanner closes. After a driver
> update, unload first: `Loader.exe x64\Release\amdfend.sys --unload-only`
> (or reboot), then run Scanner again.

## UI tour (mirrors Cheat Engine)

### Top bar
- **PC button / Process menu** — opens the Process List: sorted
  `Process | PID` rows, **Refresh**, manual `Name or PID` box.
  Double-click a row (or OK) to attach. Target shows in the PC label
  (`name (PID) [drv …]`); the window caption stays a Chrome-cover title.
- **Masquerade** (DesAnime-grade) — PEB ImagePath/CommandLine spoofed to
  Chrome, fake `GoogleChromeIPCMutex`, Chrome `VERSIONINFO` (+ runtime
  patch), `DbgBreakPoint` patched, hidden threads, random window classes.
- **Found:n** — current candidate count (`(capped)` at 500 000).

### Found list — Address | Value | Previous
- Populated by First/Next Scan (max 20 000 rows shown).
- **Double-click** a row → straight into the address table (no dialog).
- **Right-click** → `Add to Address List`.

### Scan panel
- **Value** + **Hex** — Between takes two values in one box: `100 200`
  (space/colon/comma separated).
- **Scan Type** — Exact Value, Bigger/Smaller than, Value Between,
  Increased/Decreased/Changed/Unchanged value.
- **Value Type** — 1/2/4/8 Bytes, Float, Double, String, Array of Byte
  (`89 5F 30 ?? 74 08` — `??` wildcards).
- **First / Next / Undo Scan** — Undo steps back through the last 10 scans.

### Memory Scan Options
- **Scope dropdown** — `All` or one of the target's modules. Picking a
  module auto-fills **Start/Stop** with its range (edit them freely after).
- **Writable** (default ON — CE-like hit counts), **Executable**,
  **CopyOnWrite**, **Fast Scan + Alignment** (1 = unaligned, slower).

### Address table — Active | Description | Address | Type | Value
- Live refresh every 700 ms **in place** — selection, ticks and scroll stay.
- **Active tick** = freeze (rewrites stored bytes every 120 ms).
- **Double-click / right-click per column**:
  - Value → `Change Value` (`what value to change this to?`), verified write
  - Type → `Select the new type` (combo + Hexadecimal + Signed)
  - Description → rename dialog
  - Address → full `Change address` dialog (entry stays put on Cancel)
- **Right-click** → `Delete This Address` (+ the four change actions).
  **Delete key** works too.

### Add / Change address dialog (CE layout)
- `Address:` + live `=value` preview, `Description`, `Type`
- **Hexadecimal**, **Signed** checkboxes
- **Pointer** checkbox → dialog grows: up to **5 offsets**,
  **Add/Remove Offset** at will, live chain preview
  (`base -> … -> final = value`)
- Address accepts plain hex **or** static form `"mod.dll"+OFF`
  (e.g. `"notepad.exe"+10`) — resolved via the driver every refresh.

### Memory View button
Separate viewer window: address + size → **Dump** (hex + ASCII),
hex-string box → **Write** (verified, MDL fallback covers read-only pages).

### File menu — Legend Table (.ltb)
- **New / Open / Save Table** (`*.ltb`, tiny XML: active, desc,
  addr/module, type, len, signed/hex, pointer chain, bytes).
- The CE `.CT` equivalent — share/edit by hand if you like.

## Workflows

- **Exact value**: U32 Exact `100` → First Scan → change to `200` in game →
  Next Scan → repeat to ~1 hit → double-click → tick Active.
- **Unknown value**: First Scan as `Changed value` (snapshot) → change in
  game → Next `Increased value` / `Decreased value` → narrow down.
- **AOB**: type Array of Byte, value `89 5F 30 ?? 74 08` → First Scan.
- **Pointer**: find dynamic address → Change Address → tick Pointer →
  Add Offset as needed → OK → `P->…` entry, freeze-safe across restarts
  (combine with `"mod"+off` base for full ASLR-proofing).
- **Pointer Scan** (auto-find the chain): right-click a table/found row →
  `Pointer Scan for This Address` (or Scan menu) → options
  (`Max different offsets per node` 3, threads 4, `Maximum offset` 4095,
  `Max level` 1–5) → pick `.lps` checkpoint file → watch progress
  (paths evaluated, results, Stop) → results window
  (`Base Address | Offset 0-4 | Points to`) → double-click adds it.
  After a game restart: results window → **Rescan** → enter the new
  address → keeps only surviving paths → saves checkpoint again.
  Level 1 = holders pointing straight at your address; each level walks
  one hop further back until a static module closes the path.
- **Static**: Change Address → `"game.exe"+DA059C` → OK → survives restart.

## Safety rules

1. Driver first (auto), game second, attach third.
2. One load per session — don't reload mid-scan (use `--unload-only` first).
3. Start with writable-only scans; executables are usually code, not values.
4. Freeze sparingly — frozen wrong addresses crash games, not the tool.
