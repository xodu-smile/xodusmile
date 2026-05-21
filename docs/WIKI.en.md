# RansomGuard EDR — Developer Wiki (EN)

A reference for every source file in the repository: what it does, what
its public surface is, and where it sits in the runtime.  For the
Korean edition see [`WIKI.ko.md`](./WIKI.ko.md).

---

## 1. Architecture at a glance

```
                  ┌─────────────────────────────────────────────┐
                  │                ScoringEngine                │
                  │  (sliding-window weighted signal sum)       │
                  └──┬───────────┬────────────────────────┬─────┘
                     │ submit()  │ subscribe(listener)    │
                     │           ▼                        ▼
   ┌─────────────────┴──┐  ┌─────────────┐   ┌──────────────────────┐
   │ Detectors          │  │ EventStore  │   │ ProcessResponder     │
   │  - canary          │  │ (SQLite)    │   │  - quarantine_pid    │
   │  - mass_io         │  └─────────────┘   │  - terminate         │
   │  - process_cmdline │                    └──────────┬───────────┘
   │  - process_watcher │                               │ on_action
   │  - minifilter      │◄──── kernel events ──┐        ▼
   └────────────────────┘                      │   ┌────────────────┐
            ▲                                  │   │ IncidentReport │
            │                                  │   │  - write .md   │
            │                                  │   │  - notify user │
   ┌────────┴────────┐                ┌────────┴──┐└────────────────┘
   │ Flask Dashboard │                │ RansomGuard│
   │  (browser UI)   │                │ minifilter │
   └─────────────────┘                │   (.sys)   │
                                      └────────────┘
```

Signals flow **into** the `ScoringEngine`.  Three listeners are attached:

1. `Agent._on_signal` — pretty-prints to console and persists to
   `EventStore`.
2. `MassIODetector._on_engine_signal` — listens for `canary` trips and
   raises its own entropy / burst thresholds for 30 seconds.
3. `ProcessResponder._dispatch` — when a HIGH/CRITICAL signal names a
   PID, asks the kernel to quarantine and then terminates the process;
   also sweeps PIDs when the rolling score crosses CRITICAL.

The responder fires `on_action(KillAction)` for every action; the
`IncidentReporter` uses that hook to write a Markdown incident report
and surface a desktop notification.

---

## 2. Repository layout

```
ransomware_detector/
├── agent.py                       # CLI entry point + orchestrator
├── scoring.py                     # ScoringEngine, Signal, Severity
├── event_store.py                 # SQLite persistence
├── responder.py                   # Quarantine + process termination
├── incident_report.py             # Markdown report + notifications
├── demo_inproc.py                 # End-to-end demo (no dashboard)
├── __init__.py                    # Marks repo as a package
├── detectors/
│   ├── __init__.py
│   ├── base.py                    # Detector ABC
│   ├── canary.py                  # Canary files
│   ├── mass_io.py                 # File-event burst + entropy
│   ├── process_cmdline.py         # WMI + regex ruleset
│   ├── process_watcher.py         # psutil polling, parent/child chains
│   └── minifilter_bridge.py       # User-mode driver client
├── dashboard/
│   └── app.py                     # Flask app (routes + JSON API)
├── tests/
│   └── simulator.py               # Safe behaviour simulator
├── minifilter/
│   ├── RansomGuard.h              # Driver ↔ user-mode contract
│   ├── RansomGuard.c              # Kernel minifilter
│   ├── RansomGuard.inf / .sln / .vcxproj
├── scripts/
│   ├── _common.ps1                # Shared PS helpers
│   ├── bootstrap.ps1              # Python + venv install
│   ├── build_driver.ps1           # MSBuild wrapper
│   ├── install_driver.ps1         # Load .sys + start service
│   ├── install.ps1                # bootstrap + driver convenience
│   └── uninstall_driver.ps1       # Stop and remove driver
└── reports/                       # (created at runtime) .md incidents
```

---

## 3. Top-level Python

### 3.1 `agent.py`

CLI entry point.  Wires every component together and runs the main
loop.

| Surface | Notes |
|---------|-------|
| `class Agent(watch_dirs, *, db_path, responder_mode, enable_minifilter, reports_dir, notify_user)` | Owns all detectors, the scoring engine, the event store, the responder, and the incident reporter. |
| `Agent.start()` | Deploys canaries and starts every detector thread. |
| `Agent.stop()` | Stops detectors, cleans up canary files. |
| `Agent.status()` | Snapshot of score + level + recent signals + responder + incidents (consumed by `/api/status`). |
| `Agent.processes(limit)` | Pass-through to `ProcessWatcher.snapshot`. |
| `Agent._on_signal(sig, score, level)` | Print + persist. |
| `parse_args()` / `main()` | CLI: `--watch`, `--db`, `--no-dashboard`, `--port`, `--mode`, `--no-minifilter`, `--reports-dir`, `--no-notify`. |

Flow on `python agent.py`: `parse_args` → build `Agent` → `agent.start()`
→ optionally launch Flask dashboard in a daemon thread → install
SIGINT/SIGTERM handlers → idle until shutdown → `agent.stop()`.

---

### 3.2 `scoring.py`

The brain.  A time-windowed weighted sum with named thresholds.

| Surface | Notes |
|---------|-------|
| `class Severity(str, Enum)` | `INFO < LOW < MEDIUM < HIGH < CRITICAL`. |
| `@dataclass Signal` | `detector, name, weight, severity, message, metadata, timestamp`.  `metadata` carries `pid`, `path`, etc. |
| `THRESHOLD_LOW=30, _MEDIUM=60, _HIGH=100, _CRITICAL=150` | Score boundaries. |
| `SIGNAL_WINDOW_SECONDS=120` | Rolling-window length. |
| `ScoringEngine.submit(signal)` | Append, evict expired, then call every listener with `(signal, score, level)`. |
| `ScoringEngine.subscribe(listener)` | Register callback. Listener exceptions are caught so a bad listener cannot brick the engine. |
| `ScoringEngine.current_score()` / `current_level()` / `recent_signals(limit)` / `reset()` | Used by dashboard and responder. |

Listener exceptions print but do not propagate — important for the
responder, which can fail on per-PID actions without taking the engine
down.

---

### 3.3 `event_store.py`

Thin SQLite wrapper.  Schema is `signals(id, timestamp, detector, name,
weight, severity, message, metadata, score_after, level_after)` with
indexes on `(timestamp DESC)` and `(severity)`.

| Surface | Notes |
|---------|-------|
| `EventStore(db_path="detector.db")` | Creates the file and schema if needed. |
| `record(signal, score_after, level_after)` | Insert one row.  `metadata` is `json.dumps`-ed with `default=str` so non-serializable values become strings rather than raising. |
| `recent(limit=100)` | Latest `limit` rows, newest first, with metadata re-parsed to dict. |
| `stats()` | `{total, by_detector, by_severity}`. |

Uses a per-call connection inside a global lock to keep SQLite happy
with multi-threaded writers.

---

### 3.4 `responder.py`

Active-response component.  Subscribes to the scoring engine, decides
who to quarantine/kill, executes it, and records `KillAction` rows.

| Surface | Notes |
|---------|-------|
| `class ResponderMode(str, Enum)` | `OFF, QUARANTINE, KILL`. |
| `NEVER_KILL = {…}` | Hard refusal list — OS processes plus `python.exe`/`py.exe`/`pythonw.exe`. |
| `@dataclass KillAction` | `timestamp, pid, process_name, cmdline, reason, mode, quarantined, terminated, error`. |
| `ProcessResponder(engine, *, mode, minifilter, critical_threshold, on_action)` | Constructor.  `on_action` fires for every recorded action and is how `IncidentReporter` is wired in. |
| `attach()` | Subscribe to the engine. Idempotent. |
| `actions(limit=50)` | History for the dashboard. |
| `manual_kill(pid, reason)` / `manual_release(pid)` | Dashboard buttons land here. |
| `_dispatch(sig, score, level)` | (1) any HIGH/CRITICAL signal naming a PID → `_respond_to_pid`; (2) score ≥ CRITICAL → `_sweep_window`. |
| `_respond_to_pid(pid, reason)` | Self-pid refusal → never-kill check → quarantine via minifilter → terminate via `psutil.kill()` then ctypes `OpenProcess + TerminateProcess`. |
| `_record(action)` | Append, cap history at 1000, console-log, fire `on_action`. |

Termination strategy on Windows: `psutil.kill()` first, then a raw
`OpenProcess(PROCESS_TERMINATE) + TerminateProcess + CloseHandle` via
ctypes as fallback — this defeats stale `psutil` caches on protected
processes when we are running elevated.

---

### 3.5 `incident_report.py`

Hook on `ProcessResponder.on_action`.  Writes one Markdown report per
real action and pushes a desktop notification.

| Surface | Notes |
|---------|-------|
| `@dataclass IncidentRecord` | Index entry (`timestamp, pid, process_name, reason, terminated, quarantined, filename, path`). |
| `IncidentReporter(engine, *, reports_dir="reports", notify=True)` | Creates the reports directory on construction. |
| `on_action(action)` | **Skips no-ops** (both `terminated` and `quarantined` false).  Builds markdown, writes the file, appends to history, spawns a notification thread. |
| `recent(limit=50)` | Newest-first list of `IncidentRecord` dicts. |
| `read_report(filename)` | Defends against path traversal (rejects `/`, `\`, `..`, anything that escapes `reports_dir`). Returns the file body or `None`. |
| `_build_markdown(action)` | Process header → response → threat context → contributing signals for this PID → recent window → raw action JSON. |
| `_notify_user(action, path)` | Background thread; dispatches per platform. |
| `_notify_linux` | `notify-send` via subprocess. |
| `_notify_macos` | `osascript -e 'display notification …'`. |
| `_notify_windows` | Tries `win10toast` → PowerShell `BurntToast` → modal `MessageBoxW`. |

File names: `incident_<YYYYMMDD_HHMMSS>_pid<N>_<safe_name>.md`.

---

### 3.6 `demo_inproc.py`

Single-process end-to-end demo: boot `Agent`, populate dummies, inject
fake VSS / BCD events, touch a canary, run the encryption simulator,
print stats.  Use this to validate detector behaviour without a
dashboard or driver.

---

### 3.7 `__init__.py`

Empty — marks the repo as a package so internal `import scoring`,
`from detectors.base import …` work when run as scripts or modules.

---

## 4. Detectors

All detectors inherit `detectors.base.Detector`, run on a daemon
thread, and call `self.emit(Signal(...))` to push into the engine.

### 4.1 `detectors/base.py`

`Detector` ABC with the threading scaffolding.

| Surface | Notes |
|---------|-------|
| `name: str = "base"` | Subclasses override. |
| `__init__(engine)` | Stores engine + a `threading.Event` for cooperative cancellation. |
| `start()` / `stop()` | Spawn / join the daemon thread (`stop` joins with 3-second timeout). |
| `emit(signal)` | Pass-through to `engine.submit`. |
| `_run_safe()` | Catches exceptions inside `run()` so one detector crashing does not take the others down. |
| `run()` *(abstract)* | Subclass loop body; check `self._stop_event.is_set()` periodically. |

---

### 4.2 `detectors/canary.py`

Deploys "do-not-touch" decoy files in every watch directory and polls
their SHA-256 every 1.5 s.  Any deletion or content change emits a
single CRITICAL signal (weight 80).

| Surface / constant | Notes |
|---|---|
| `CANARY_FILENAMES` | Designed to sort to the top or bottom of an alphabetical scan. Includes `!!_DO_NOT_TOUCH_!!.docx`, `0_important_notes.xlsx`, `00_archive_index.pdf`, `~$confidential_backup.docx`, `zzz_old_records.txt`. |
| `CANARY_WEIGHT = 80` | One trip alone is enough to push the score into HIGH. |
| `CanaryDetector(engine, watch_dirs, poll_interval=1.5)` | Constructor. |
| `deploy()` | Writes each canary if missing, records its baseline hash. |
| `cleanup()` | Removes canaries on shutdown (best-effort). |
| `run()` | Polls; on mismatch emits `canary_modified` or `canary_deleted`, then *updates* the stored hash so the same change is not re-alerted. |

A canary trip cross-signals `MassIODetector` via the engine listener
mechanism (see 4.3) — for 30 seconds afterwards mass_io is more
aggressive.

---

### 4.3 `detectors/mass_io.py`

User-mode file-system watcher (uses `watchdog` if installed; falls back
to mtime polling).  Three signals plus a fan-out bonus:

| Signal | Weight | Severity | Triggered when |
|--------|--------|----------|----------------|
| `magic_bytes_lost` | 12 | HIGH | A file whose previous bytes matched a known magic (PE/PDF/Office/JPEG/…) is now unrecognisable. |
| `high_entropy_write` | 8 | MEDIUM | Shannon entropy ≥ 7.5 (≥ 6.8 in canary-boost mode), magic unrecognised, target extension, and either first observation or Δ entropy ≥ 2.5. |
| `suspicious_extension` | 5 × 3 | HIGH | File renamed to `.encrypted/.locked/.wcry/…`. |
| `modify_burst` | 25 + 20 ×fanout | HIGH | ≥ 15 file events in 10 s.  +20 for ≥ 3 distinct extensions; +20 for ≥ 2 distinct directories. |

Key constants: `BURST_WINDOW_SEC=10`, `BURST_THRESHOLD=15`,
`MAX_SAMPLE_BYTES=4096`, `MAX_TRACKED_FILES=20000` (LRU-ish eviction),
`CANARY_BOOST_WINDOW=30s`, `CANARY_BOOST_MULTIPLIER=1.5`.

Cross-signal: `_on_engine_signal` listens for any `canary` signal; when
one arrives, `_canary_tripped_at = now()`, and `_boost(weight, True)`
multiplies subsequent weights by 1.5 for 30 seconds.

Internal `_Handler(FileSystemEventHandler)` (only defined when
`watchdog` imports) dispatches `on_modified/on_created/on_moved` back
into the detector.

---

### 4.4 `detectors/process_cmdline.py`

Win11-only WMI subscriber for new process creations.  Each new process
runs through `RULES` — a list of regex-based `Rule` objects covering:

- **VSS deletion** — `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, PowerShell `Get-WmiObject … shadowcopy … Remove-…`.
- **BCD tampering** — `bcdedit … safeboot`, `recoveryenabled no`, `bootstatuspolicy ignoreallfailures`.
- **Defender / SmartScreen disable** — `Set-MpPreference -DisableRealtimeMonitoring`, service stop on `WinDefend/Sense/WdNisSvc/WdFilter`, `Add-MpPreference -Exclusion*`, registry edits, SmartScreen disable.
- **Anti-forensics** — `wevtutil cl`, `Clear-EventLog`, `fsutil usn deletejournal`, `cipher /w`.
- **Defence shutdown** — `netsh advfirewall … state off`, `manage-bde -off`, `Disable-BitLocker`.
- **Persistence** — `schtasks /create … /sc onlogon … /ru system`, Run/RunOnce registry writes.
- **PowerShell abuse** — `-EncodedCommand <base64>`, in-memory downloaders, `-ExecutionPolicy bypass -WindowStyle hidden`.

| Surface | Notes |
|---------|-------|
| `@dataclass Rule` | `name, pattern, weight, severity, message`. |
| `RULES: List[Rule]` | Module-level registry — add new entries here to extend detection. |
| `ProcessCmdlineDetector(engine)` | Subscribes via `wmi.WMI().Win32_Process.watch_for("creation")`. |
| `submit_external(process_name, cmdline, pid, ppid)` | Injection point for the simulator (`simulate_vss_deletion` uses this). |
| `run()` | Calls `pythoncom.CoInitialize`, loops on `watcher(timeout_ms=1000)`, gracefully handles `x_wmi_timed_out`. |
| `evaluate_cmdline(detector_name, process_name, cmdline, pid, ppid)` | Module-level helper — shared with `ProcessWatcher` so both code paths apply identical detection logic. |

If `wmi` / `pywin32` are not installed, the detector logs a warning and
sits idle on `_stop_event.wait()` — the rest of the agent continues.

---

### 4.5 `detectors/process_watcher.py`

`psutil`-based polling watcher, used to (a) catch processes WMI may
miss, (b) detect parent/child LOLBin chains, (c) detect per-process I/O
write bursts, and (d) feed the dashboard process table.

| Surface | Notes |
|---------|-------|
| `ProcSnapshot` dataclass | `pid, ppid, name, cmdline, user, started_at, cpu_percent, rss_bytes, write_bytes, last_seen`. |
| `SCRIPT_HOSTS` | Set of LOLBin script-host filenames (powershell, pwsh, cmd, wscript, cscript, mshta, regsvr32, rundll32, bitsadmin, certutil, msbuild, installutil). |
| `SUSPICIOUS_CHAINS` | Map of `parent → set(child)` for Office, Adobe, browsers, explorer, OneDrive, … |
| `ProcessWatcher.snapshot(limit=80)` | Sorted-by-recency dict list for `/api/processes`. |
| `run()` | Initial baseline scan (no signals), then 1 Hz `_scan(initial=False)`. |
| `_on_new_process(snap)` | (1) `evaluate_cmdline` rules; (2) parent/child chain check → `suspicious_parent_child` (weight 40, HIGH); (3) parent fan-out tracker → `child_fanout` (weight 30, MEDIUM) when ≥ 12 children in 5 s. |
| `_check_write_burst(...)` | `process_write_burst` (weight 20, MEDIUM) when a single process writes ≥ 50 MB inside a 2 s window. |

The watcher skips its own PID and drops PIDs no longer present from
`_seen` and `_last_io` so memory stays bounded.

---

### 4.6 `detectors/minifilter_bridge.py`

User-mode client for the `RansomGuard.sys` kernel minifilter.  Speaks
the binary protocol declared in `minifilter/RansomGuard.h`.

| Surface | Notes |
|---------|-------|
| `class RG_EVENT(ctypes.Structure)` | Mirrors the kernel `RG_EVENT` packet. |
| `RG_MESSAGE = FILTER_MESSAGE_HEADER + RG_EVENT` | Single-buffer layout used by `FilterGetMessage`. |
| `RG_COMMAND`, `RG_REPLY` | Outbound control packets for quarantine/release/ping. |
| `_load_fltlib()` | Loads `fltlib.dll` and binds `FilterConnectCommunicationPort`, `FilterGetMessage`, `FilterSendMessage`. Returns `None` off Windows or if the DLL is missing. |
| `MinifilterBridge.is_connected` | True once the port is open. |
| `quarantine_pid(pid)` / `release_pid(pid)` / `ping()` | Send `RG_COMMAND` and check `RG_REPLY.Status == 0`. |
| `run()` | Reconnect loop with exponential backoff (1 s → 30 s). Inside `_receive_loop`, blocks on `FilterGetMessage`, validates `Version == RG_PROTOCOL_VERSION`, dispatches to `_handle_event`. |
| `_handle_event(evt)` | Per kind: `BLOCKED` → emit `kernel_blocked_op` (weight 60, HIGH); `WRITE` → `_account_write`; `SETINFO/RENAME` → `_account_rename`; `SETINFO/DELETE` → emit `file_delete` (LOW, weight 3); `CREATE` → record path only. |
| `_account_write(...)` | Per-PID rolling window (`PID_WRITE_BURST_BYTES=75 MB`, `WINDOW=4 s`). When tripped emits `kernel_write_burst` (weight 35, HIGH), debounced for 4 s. |
| `_account_rename(...)` | Per-PID rolling window (`PID_RENAME_BURST_COUNT=20`, `WINDOW=5 s`). Emits `kernel_rename_burst` (weight 40, HIGH). |

When the driver is missing the bridge stays idle; the user-mode-only
detectors continue to work.

---

## 5. Dashboard — `dashboard/app.py`

A small Flask app, mounted in-process by `agent.py`.

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Render `templates/index.html`. |
| `/api/status` | GET | `agent.status()` JSON. |
| `/api/events` | GET | Last 100 rows from `EventStore`. |
| `/api/processes` | GET | `ProcessWatcher.snapshot(60)`. |
| `/api/actions` | GET | `ProcessResponder.actions(100)`. |
| `/api/reset` | POST | `engine.reset()`. |
| `/api/kill` | POST `{pid, reason?}` | `responder.manual_kill`. |
| `/api/release` | POST `{pid}` | `responder.manual_release`. |
| `/api/reports` | GET | `incident_reporter.recent(100)`. |
| `/api/reports/<filename>` | GET | Raw markdown body (`text/markdown`), 404 on miss/traversal. |

`create_app(agent)` is the factory; the agent thread runs the Flask
server with `use_reloader=False`.

The HTML template adds a fixed-position toast container and polls
`/api/reports` every 2.5 s; new entries spawn a toast that auto-dismisses
after 10 s.

---

## 6. Tests — `tests/simulator.py`

Safe behaviour simulator.  Crucially, it never executes real `vssadmin`
or `bcdedit`; it injects fake command-line events via
`ProcessCmdlineDetector.submit_external` instead.

| Function | What it does |
|----------|--------------|
| `populate_targets(directory, count=30)` | Writes dummy `document_NNN.{docx,xlsx,pdf,jpg,txt}` files with realistic magic bytes so the entropy detector has a believable baseline. |
| `simulate_encryption_pattern(directory, speed=0.05)` | Overwrites each dummy with `os.urandom(size)` (high entropy), then renames to `<name>.encrypted`. |
| `simulate_canary_touch(directory)` | Appends a single NUL byte to the first canary it finds. |
| `simulate_vss_deletion(agent)` | Injects a fake `vssadmin delete shadows /all /quiet` event into the cmdline detector. |
| `simulate_bcd_tamper(agent)` | Same, for `bcdedit /set {default} recoveryenabled no`. |
| `main()` | CLI: `--dir`, `--scenario {populate, encrypt, canary, vss, bcd, full, stealth}`, `--speed`. |

Run it against your own watch directory.  Do not point it at someone
else's filesystem.

---

## 7. Kernel minifilter (C)

### 7.1 `minifilter/RansomGuard.h`

Shared contract.  Both the driver and `detectors/minifilter_bridge.py`
include this layout — keep them in sync.  Highlights:

- `RG_PORT_NAME = L"\\RansomGuardPort"`, altitude `385201`, protocol version `1`, max path 520 WCHARs.
- `RG_EVENT_KIND`: `RgEventCreate(1)`, `RgEventWrite(2)`, `RgEventSetInfo(3)`, `RgEventBlocked(4)`.
- `RG_SETINFO_KIND`: `Other/Rename/Delete`.
- `RG_EVENT` (`#pragma pack(4)`): `Version, Kind, SubKind, ProcessId, ThreadId, Status, WriteBytes (u64), TimestampNs (u64), PathLength, Path[520 WCHAR]`.
- `RG_COMMAND_KIND`: `RgCmdQuarantinePid(1)`, `RgCmdReleasePid(2)`, `RgCmdPing(3)`.
- `RG_COMMAND` / `RG_REPLY`: control plane structures.

### 7.2 `minifilter/RansomGuard.c`

Compact minifilter — keeps logic out of the kernel.

**Global state** (`g_Rg`):
- `Filter`, `ServerPort`, `ClientPort` (single connected listener).
- `ClientLock` (FAST_MUTEX) protects the port.
- `QuarantineLock` (`EX_PUSH_LOCK`) protects `QuarantinedPids[256]`.
- `PerfFrequency` cached at boot for ns conversion.

**Lifecycle**:
- `DriverEntry` — `FltRegisterFilter`, build a default security descriptor, `FltCreateCommunicationPort(RG_PORT_NAME, …, callbacks, max-connections=1)`, `FltStartFiltering`.
- `RgUnload` — close the port, unregister, delete the push-lock.

**Operation callbacks** (`Callbacks[]` registers `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`):
- `RgPostCreate` — emit `RgEventCreate` on user-mode, successful opens (drains and kernel callers are skipped).
- `RgPreWrite` — if requesting PID is quarantined, emit `RgEventBlocked(Write)` and complete the IRP with `STATUS_ACCESS_DENIED`; else continue.
- `RgPostWrite` — for writes ≥ 4096 bytes (sub-page throttled), emit `RgEventWrite` carrying `IoStatus.Information` as `WriteBytes`.
- `RgPreSetInfo` — classify as `Rename`, `Delete`, or `Other`. Skip `Other`. Block quarantined PIDs on rename/delete; otherwise pass `sub` via `CompletionContext`.
- `RgPostSetInfo` — emit `RgEventSetInfo` with the saved sub-kind.

**Quarantine bitmap** (`RgIsQuarantined`, `RgAddQuarantine`, `RgRemoveQuarantine`) — linear scan over a 256-entry array under a push-lock. Capacity-bounded so the kernel side stays trivially safe.

**Port plumbing**:
- `RgPortConnect` — refuse a second listener (`STATUS_ALREADY_REGISTERED`).
- `RgPortDisconnect` — release the port and clear the quarantine list (user mode will rebuild on reconnect).
- `RgPortMessage` — `ProbeForRead/Write` the user buffers under SEH; dispatch on `cmd.Kind` to add/remove/ping.

**Event emission** (`RgSendEvent`):
- Allocate `RG_EVENT` from non-paged pool (tag `'GnsR'`).
- Fill `ProcessId/ThreadId/Status/WriteBytes/TimestampNs` and copy the normalized DOS path via `FltGetFileNameInformation` + `FltParseFileNameInformation`.
- `FltSendMessage` with a **50 ms timeout** — if user mode is wedged we drop the event rather than stall the IRP.

**Throttling discipline**: the kernel never queues, never grows
unbounded, and never blocks I/O for more than 50 ms waiting on user
mode.  Heavy correlation (entropy, fan-out, command-line rules) lives
entirely in user mode.

---

## 8. PowerShell scripts

### 8.1 `scripts/_common.ps1`

Dot-sourced helper module.  `Set-StrictMode -Version Latest`,
`$ErrorActionPreference = 'Stop'`.

| Function | Purpose |
|---|---|
| `Test-Admin` / `Require-Admin` | Detect / require Administrator. |
| `Write-Step`, `Write-Ok`, `Write-Warn2`, `Write-Err2` | Colored status output (cyan / green / yellow / red). |
| `Get-RepoRoot` | Resolves `..` from `$PSScriptRoot`. |
| `Test-Command(name)` | Wrapper for `Get-Command -ErrorAction SilentlyContinue`. |
| `Invoke-CheckedExe -Exe ... -Args ...` | Runs the executable and throws on non-zero exit. |
| `Install-WithWinget -Id -DisplayName` | Wraps `winget install` with the silent + auto-agree flags. |
| `Ensure-Python` | Returns `py` or `python` if present, else installs Python 3.12 via winget. |
| `Find-VsWhere` / `Find-MsBuild` | Locate vswhere and MSBuild. |
| `Test-WdkInstalled` | Probes vswhere for the WDK / Win11 SDK component. |

### 8.2 `scripts/bootstrap.ps1`

Entry point for a fresh machine.  Params: `-BuildDriver`,
`-InstallDriver`, `-SkipPython`.  Steps:

1. `Ensure-Python` → install if absent.
2. Create `.venv` if missing; `pip install --upgrade pip` then `pip install -r requirements.txt`.
3. Run `pywin32_postinstall -install` (warns rather than fails).
4. If `-BuildDriver` / `-InstallDriver` → delegate to `build_driver.ps1` / `install_driver.ps1`.

### 8.3 `scripts/install.ps1`

One-line wrapper: `Require-Admin` then
`bootstrap.ps1 -BuildDriver -InstallDriver`.  Use when you want
everything in one go.

### 8.4 `scripts/build_driver.ps1`

`Find-MsBuild` → fail with explicit winget instructions if missing →
`Test-WdkInstalled` (warn-only) → `msbuild minifilter\RansomGuard.sln
/p:Configuration=Release /p:Platform=x64 /m /nologo`.  Lists
`RansomGuard.sys` / `.inf` at the end.

### 8.5 `scripts/install_driver.ps1`

Admin-only.  Verifies the built artifacts exist, warns if
`bcdedit … testsigning` is off, runs
`rundll32 setupapi.dll,InstallHinfSection DefaultInstall 132 RansomGuard.inf`,
then `sc.exe start RansomGuard` (tolerates exit `1056 =
ERROR_SERVICE_ALREADY_RUNNING`), and prints `fltmc filters` rows that
match `RansomGuard`.

### 8.6 `scripts/uninstall_driver.ps1`

Admin-only.  `sc.exe stop RansomGuard` → `rundll32
setupapi.dll,InstallHinfSection DefaultUninstall 132` (or `sc.exe
delete RansomGuard` as a fallback) → removes
`%windir%\System32\drivers\RansomGuard.sys`.

---

## 9. Extending the system

### Add a new command-line rule
Append a new `Rule(...)` to `RULES` in
`detectors/process_cmdline.py`.  It will automatically be picked up by
both the WMI subscriber and the psutil polling path (both go through
`evaluate_cmdline`).

### Add a new detector
1. Create `detectors/your_detector.py`, subclass `Detector`, set `name`, implement `run()`.
2. Add it to `Agent.__init__` (instantiate + append to `self.detectors`).
3. Pick a `weight`/`severity` consistent with the existing scale (CRITICAL ≈ 70+, HIGH ≈ 35–60, MEDIUM ≈ 10–30, LOW ≈ 1–9).

### Add a new responder mode
Extend `ResponderMode`, branch in `_respond_to_pid`, and update the
`--mode` choices in `agent.parse_args`.

### Add a new dashboard panel
1. Add an endpoint in `dashboard/app.py`.
2. Add a `.panel` block in `dashboard/templates/index.html` and a `tick()` poller in the existing `<script>`.

### Add a new kernel event
1. Add the kind to `RG_EVENT_KIND` in `RansomGuard.h` (bump `RG_PROTOCOL_VERSION` if the layout changes).
2. Add the matching constant in `detectors/minifilter_bridge.py`.
3. Emit it from the appropriate kernel callback in `RansomGuard.c` via `RgSendEvent`.
4. Handle it in `MinifilterBridge._handle_event`.

---

## 10. Operational notes

- **Run as Administrator on Windows** for the responder to terminate non-self processes and for the kernel bridge to attach.
- **Test signing** must be on for the unsigned driver (`bcdedit /set testsigning on`).
- **`NEVER_KILL`** is a defence against operator error — if you add new critical processes, extend the set rather than disabling the check.
- **Reports** land in `./reports/` by default; archive or rotate them out of band — the reporter does not.
- **Cross-platform**: the user-mode agent runs on Linux/macOS too (no WMI, no minifilter), which is useful for developing new detectors against the simulator.
