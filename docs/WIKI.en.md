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
   │  - process_kernel  │◄──── kernel events ──┐        ▼
   │  - registry_kernel │                      │   ┌────────────────┐
   │  - minifilter_bridge│                     │   │ IncidentReport │
   └────────────────────┘                      │   │  - write .md   │
            ▲                                  │   │  - notify user │
            │                                  │   └────────────────┘
   ┌────────┴────────┐                ┌────────┴──┐
   │ Flask Dashboard │                │ RansomGuard│       ┌──────────┐
   │  (browser UI)   │                │ minifilter │       │  tamper  │
   └─────────────────┘                │   (.sys)   │       │ (self-   │
                                      └────────────┘       │ defense) │
                                            ▲              └──────────┘
                                            │ heartbeat / restart
                                      ┌─────┴──────┐
                                      │ watchdog_  │
                                      │  service   │
                                      └────────────┘
```

Signals flow **into** the `ScoringEngine`.  Three listeners are attached:

1. `Agent._on_signal` — pretty-prints to console and persists to
   `EventStore`.
2. `MassIODetector._on_engine_signal` — listens for `canary` trips and
   raises its own entropy / burst thresholds for 30 seconds.
3. `ProcessResponder._dispatch` — when a HIGH/CRITICAL signal names a
   PID *and clears the confidence bar*, asks the kernel to quarantine and
   then terminates that one PID. There is no score-wide sweep: it turned
   isolated false positives into mass kills (see the responder docstring
   and the dispatch row below).

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
├── tamper.py                      # Self-defense (Critical flag + DACL hardening)
├── service.py                     # Windows service host (RansomGuardAgent)
├── watchdog_service.py            # Sidecar service, agent heartbeat / restart
├── demo_inproc.py                 # End-to-end demo (no dashboard)
├── __init__.py                    # Marks repo as a package
├── detectors/
│   ├── __init__.py
│   ├── base.py                    # Detector ABC
│   ├── canary.py                  # Canary files
│   ├── mass_io.py                 # File-event burst + entropy
│   ├── process_cmdline.py         # WMI + regex ruleset
│   ├── process_watcher.py         # psutil polling, parent/child chains
│   ├── process_kernel.py          # Kernel-callback process-create detector (no WMI)
│   ├── registry_kernel.py         # Kernel-callback registry-write detector
│   └── minifilter_bridge.py       # User-mode driver client
├── dashboard/
│   └── app.py                     # Flask app (routes + JSON API)
├── tests/
│   └── simulator.py               # Safe behaviour simulator
├── minifilter/
│   ├── RansomGuard.h              # Driver ↔ user-mode contract (v2)
│   ├── RansomGuard.c              # Kernel minifilter
│   ├── RansomGuard.inf / .sln / .vcxproj
├── scripts/
│   ├── _common.ps1                # Shared PS helpers
│   ├── bootstrap.ps1              # Python + venv install
│   ├── build_driver.ps1           # MSBuild wrapper
│   ├── install_driver.ps1         # Load .sys + start service
│   ├── install_services.ps1       # Register Agent + Watchdog services + DACL lock
│   ├── install.ps1                # bootstrap + driver convenience
│   ├── uninstall_driver.ps1       # Stop and remove driver
│   └── uninstall_services.ps1     # Remove Agent + Watchdog services
└── reports/                       # (created at runtime) .md incidents
```

---

## 3. Top-level Python

### 3.1 `agent.py`

CLI entry point.  Wires every component together and runs the main
loop.

| Surface | Notes |
|---------|-------|
| `class Agent(watch_dirs, *, db_path, responder_mode, enable_minifilter, reports_dir, notify_user, enable_tamper_protection, watchdog_pid)` | Owns all detectors (including kernel-callback ones), the scoring engine, the event store, the responder, the incident reporter, and the tamper-protection hooks. |
| `Agent.start()` | Deploys canaries and starts every detector thread. |
| `Agent.stop()` | Stops detectors, cleans up canary files. |
| `Agent.status()` | Snapshot of score + level + recent signals + responder + incidents (consumed by `/api/status`). |
| `Agent.processes(limit)` | Pass-through to `ProcessWatcher.snapshot`. |
| `Agent._on_signal(sig, score, level)` | Print + persist. |
| `parse_args()` / `main()` | CLI: `--watch`, `--db`, `--no-dashboard`, `--port`, `--mode`, `--no-minifilter`, `--reports-dir`, `--no-notify`, `--no-tamper-protection`, `--watchdog-pid`. |

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
| `GROUND_TRUTH_ENCRYPTION` | **Trust-gate blind-spot fix** — a frozen set of signal names (`canary_modified`, `canary_deleted`, `magic_bytes_lost`, `suspicious_extension`, `ransom_note_spread`, `kernel_blocked_op`) that are **never exempted** by the actor-trust gate. Ransomware injected into (T1055) or masquerading as (T1036) a trusted process still gets scored when it produces these ground-truth encryption signals. |
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
| `@dataclass KillAction` | `timestamp, pid, process_name, cmdline, reason, mode, quarantined, terminated, error` plus **action-time forensic capture** `exe_path, exe_sha256, username, ppid, parent_name, score_at_action, level_at_action, trigger_signal, detect_ts` (all defaulted; reports use this capture as primary evidence instead of re-querying the live engine). |
| `ProcessResponder(engine, *, mode, minifilter, critical_threshold, on_action)` | Constructor.  `on_action` fires for every recorded action and is how `IncidentReporter` is wired in. |
| `attach()` | Subscribe to the engine. Idempotent. |
| `actions(limit=50)` | History for the dashboard. |
| `manual_kill(pid, reason)` / `manual_release(pid)` | Dashboard buttons land here. |
| `_dispatch(sig, score, level)` | Only HIGH/CRITICAL signals naming a PID. If `_is_confident()` passes → `_respond_to_pid`, else `_record_observed` (logged, no action). **The score-wide PID sweep is removed** — it turned isolated false positives into mass kills and relied solely on the never-kill list. |
| `_is_confident(pid, sig)` | CRITICAL acts on its own. HIGH needs corroboration: real encryption activity in the window (`ScoringEngine.has_encryption_activity`) or a second distinct detector naming the same PID. |
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

### 3.6 `tamper.py`

Self-defense helpers applied at agent startup. Best-effort layered
defences; all no-op outside Windows.

| Surface | Notes |
|---------|-------|
| `is_windows()` | Platform guard. |
| `set_process_critical(enable=True)` | Calls `ntdll!RtlSetProcessIsCritical`. Killing a critical process bug-checks the box → silent termination is no longer possible. Requires SeDebugPrivilege (auto-granted under LocalSystem). |
| `harden_paths(paths)` | Restricts the SQLite DB and reports directory to SYSTEM/Administrators via DACL. Blocks non-admin attackers. |

The strongest layer is the kernel-side `ObCallback` (registered by the
driver via `MinifilterBridge.add_protected_pid`) — strips handle access
mask bits even from SYSTEM-level attackers.

---

### 3.7 `service.py`

`RansomGuardAgent` Windows service host. Uses pywin32's
`servicemanager` to register with the SCM and run the agent under
LocalSystem.

| Surface | Notes |
|---------|-------|
| `SERVICE_NAME = "RansomGuardAgent"` | SCM identifier. |
| `_load_params_from_registry()` | Reads `WatchDirs`, `DbPath`, `ReportsDir`, `Mode` from `HKLM\…\Services\RansomGuardAgent\Parameters`, falls back to sensible defaults. |
| `RansomGuardService.SvcDoRun()` | Builds the Agent, calls `start()`, waits on the stop event, calls `stop()`. |
| `install` / `start` / `stop` / `remove` | Standard pywin32 service verbs. |

`scripts/install_services.ps1` invokes this module and also configures
SCM recovery options (auto-restart on failure).

---

### 3.8 `watchdog_service.py`

`RansomGuardWatchdog` sidecar service. Every 5 seconds, verifies the
agent service is running and responsive; if not, restarts it via the
SCM.

| Surface | Notes |
|---------|-------|
| `WATCHDOG_INTERVAL_SECS = 5` | Poll cadence. |
| `HEARTBEAT_MISS_THRESHOLD = 3` | Consecutive misses before a forced restart. |
| `_check_agent_state()` | Queries SCM for the agent service state. If not `RUNNING` / `START_PENDING`, asks the SCM to start it. |
| `_check_heartbeat()` | GETs `http://127.0.0.1:5000/api/heartbeat`. Three consecutive failures → stop the service so the SCM auto-restarts it. |

Mutual protection: at startup the agent registers the watchdog PID
with the kernel `ObCallback` — killing either now requires SCM
privileges or a bug-check.

---

### 3.9 `demo_inproc.py`

Single-process end-to-end demo: boot `Agent`, populate dummies, inject
fake VSS / BCD events, touch a canary, run the encryption simulator,
print stats.  Use this to validate detector behaviour without a
dashboard or driver.

---

### 3.10 `__init__.py`

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

### 4.3b `detectors/ransom_note.py`

Ransom-note detector. Polls watch directories every 2 seconds to find
ransom-note files that malware drops after encrypting (HOW_TO_DECRYPT.txt,
_readme.txt, RESTORE-MY-FILES.txt, *.hta, etc.).

**Content-aware analysis:** Beyond filename pattern matching, the detector
reads file content to check for ① BTC/ETH/Monero crypto wallet addresses,
② `.onion` URLs, ③ "your files have been encrypted" extortion phrases, and
④ payment/contact terms. Notes with arbitrary filenames such as `A7F3C.txt`
are therefore still caught by content.

| Surface / constant | Notes |
|---|---|
| `NOTE_PATTERNS` | Regex list — `how.*to.*decrypt`, `recover.*files`, `your.*files.*encrypted`, `ransom.*note`, `_readme.txt`, etc. (high-specificity patterns only). |
| `CONTENT_PATTERNS` | Content-inspection regexes — crypto wallet addresses, `.onion` URLs, extortion/payment phrases. |
| `SPREAD_DIR_THRESHOLD = 3` | Number of *distinct* directories above which notes count as a spread (raised from 2 to **3**). |
| `SPREAD_WINDOW_SEC = 60` | Time window within which notes are aggregated into a spread. |
| `W_NOTE_SINGLE = 35` | Weight for a single content-confirmed note (HIGH). |
| `W_NOTE_SPREAD = 90` | Weight for multi-directory spread (CRITICAL). |
| `RansomNoteDetector.run()` | First pass: baseline scan (ignore existing files); subsequent polls emit signals for new notes via `_handle_note()`. |
| `_handle_note(path, now)` | Determine content-confirmed status → record path in `_recent_dirs` → count spread. **Content-confirmed notes across ≥ 3 dirs → `ransom_note_spread` (CRITICAL). Name-matched notes across ≥ 3 dirs → CRITICAL only when corroborated by real encryption activity (canary/mass_io).** Single content-confirmed = HIGH; name-only = MEDIUM hint only. |
| `_on_engine_signal(sig, score, level)` | Listens for canary signals — when canary trips, a single note inside the next 30 seconds is upgraded to CRITICAL. |

Cross-signal: canary trip triggers `_boost_active() → True`, which
upgrades `ransom_note_dropped` to CRITICAL (weight `W_NOTE_SPREAD`).

**False-positive suppression:** A name-only single note is deliberately
kept at MEDIUM so a stray README.txt never auto-escalates. Content
confirmation is the key promotion gate.

---

### 4.4 `detectors/process_cmdline.py`

Win11-only WMI subscriber for new process creations.  Each new process
runs through `RULES` — a list of regex-based `Rule` objects. Total rule
count is now **33** (up from 22), covering:

- **VSS deletion / resize** — `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, PowerShell `Get-WmiObject … shadowcopy … Remove-…`, **`vssadmin resize shadowstorage`**.
- **BCD tampering** — `bcdedit … safeboot`, `recoveryenabled no`, `bootstatuspolicy ignoreallfailures`.
- **Defender / SmartScreen disable** — `Set-MpPreference -DisableRealtimeMonitoring`, service stop on `WinDefend/Sense/WdNisSvc/WdFilter`, `Add-MpPreference -Exclusion*`, registry edits, SmartScreen disable.
- **Anti-forensics** — `wevtutil cl`, `Clear-EventLog`, `fsutil usn deletejournal`, `cipher /w`.
- **Defence shutdown** — `netsh advfirewall … state off`, `manage-bde -off`, `Disable-BitLocker`.
- **Persistence** — `schtasks /create … /sc onlogon … /ru system`, Run/RunOnce registry writes.
- **PowerShell abuse** — `-EncodedCommand <base64>`, in-memory downloaders, `-ExecutionPolicy bypass -WindowStyle hidden`.
- **Living-off-the-land / LOLBin (11 new rules)**:
  - `cipher_efs_encrypt` — `cipher /e` (abuse of built-in EFS encryption engine).
  - `bitlocker_abuse_enable` — `manage-bde -on` / `Enable-BitLocker` (forced BitLocker encryption).
  - `vssadmin_resize_shadowstorage` — shrink shadow storage to weaken recovery options.
  - `certutil_download` — `certutil -urlcache -split -f` (file download LOLBin).
  - `certutil_decode_payload` — `certutil -decode` (Base64 payload decode, T1218).
  - `bitsadmin_transfer` — `bitsadmin /transfer` (T1197 BITS Jobs abuse).
  - `esentutl_raw_copy` — `esentutl /y` (raw copy of locked files).
  - `wmic_process_call_create` — `wmic process call create` (process creation bypass, T1047).
  - `kernel_service_create` — `sc create type=kernel` (BYOVD — load a vulnerable kernel driver, T1543.003).
  - `archive_password_staging` — `7z … -p` / `rar … -p` (double-extortion staging, T1560.001).
  - `rclone_exfil` — `rclone copy/sync` (cloud exfiltration, T1567.002).

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
write bursts, (d) **detect system-binary masquerade (T1036.005)**, and
(e) feed the dashboard process table.

| Surface | Notes |
|---------|-------|
| `ProcSnapshot` dataclass | `pid, ppid, name, cmdline, user, started_at, cpu_percent, rss_bytes, write_bytes, last_seen`. |
| `SCRIPT_HOSTS` | Set of LOLBin script-host filenames (powershell, pwsh, cmd, wscript, cscript, mshta, regsvr32, rundll32, bitsadmin, certutil, msbuild, installutil). |
| `CORE_SYSTEM_BINARIES` | Set of core system binary names targeted for masquerade detection (svchost.exe, lsass.exe, csrss.exe, etc.). |
| `SYSTEM32_PATHS` | Expected legitimate execution paths (System32, SysWOW64). |
| `SUSPICIOUS_CHAINS` | Map of `parent → set(child)` for Office, Adobe, browsers, explorer, OneDrive, … |
| `ProcessWatcher.snapshot(limit=80)` | Sorted-by-recency dict list for `/api/processes`. |
| `run()` | Initial baseline scan (no signals), then 1 Hz `_scan(initial=False)`. |
| `_on_new_process(snap)` | (1) `evaluate_cmdline` rules; (2) **`_check_masquerade`** — if a core system binary name runs outside System32/SysWOW64 (e.g., `%TEMP%\svchost.exe`), emits `process_masquerade` (weight 60, HIGH, T1036.005); (3) parent/child chain check → `suspicious_parent_child` (weight 40, HIGH); (4) parent fan-out tracker → `child_fanout` (weight 30, MEDIUM) when ≥ 12 children in 5 s. |
| `_check_masquerade(snap)` | Emits `process_masquerade` when a name from `CORE_SYSTEM_BINARIES` runs from a path not under a `SYSTEM32_PATHS` prefix. |
| `_check_write_burst(...)` | `process_write_burst` (weight 20, MEDIUM) when a single process writes ≥ 50 MB inside a 2 s window. |

The watcher skips its own PID and drops PIDs no longer present from
`_seen` and `_last_io` so memory stays bounded.

---

### 4.6 `detectors/minifilter_bridge.py`

User-mode client for the `RansomGuard.sys` kernel minifilter.  Speaks
the binary protocol declared in `minifilter/RansomGuard.h`.

| Surface | Notes |
|---------|-------|
| `class RG_EVENT(ctypes.Structure)` | Mirrors the kernel `RG_EVENT` packet. v2 adds `ParentProcessId`, `DesiredAccess`, `Extra[1024]`. |
| `RG_MESSAGE = FILTER_MESSAGE_HEADER + RG_EVENT` | Single-buffer layout used by `FilterGetMessage`. |
| `RG_COMMAND`, `RG_REPLY` | Control plane — quarantine/release/ping/protect-pid/unprotect-pid/flush-quarantine. |
| `_load_fltlib()` | Loads `fltlib.dll` and binds `FilterConnectCommunicationPort`, `FilterGetMessage`, `FilterSendMessage`. Returns `None` off Windows or if the DLL is missing. |
| `MinifilterBridge.is_connected` | True once the port is open. |
| `quarantine_pid(pid)` / `release_pid(pid)` / `ping()` | Send `RG_COMMAND` and check `RG_REPLY.Status == 0`. |
| `add_protected_pid(pid)` / `remove_protected_pid(pid)` / `flush_quarantine()` | v2 additions: register/unregister self-protection, bulk-release every quarantined PID. |
| `subscribe_process(cb)` / `subscribe_registry(cb)` | Hooks used by `process_kernel` and `registry_kernel` detectors. |
| `run()` | Reconnect loop with exponential backoff (1 s → 30 s). Inside `_receive_loop`, blocks on `FilterGetMessage`, validates `Version == RG_PROTOCOL_VERSION (=2)`, dispatches to `_handle_event`. |
| `_handle_event(evt)` | Per kind (8 kinds): `CREATE` → record path / `WRITE` → `_account_write` / `SETINFO/RENAME` → `_account_rename` / `SETINFO/DELETE` → emit `file_delete` (LOW, weight 3) / `BLOCKED` → emit `kernel_blocked_op` (weight 60, HIGH) / `PROCESS_START`, `PROCESS_EXIT` → `subscribe_process` callbacks / `REGISTRY` → `subscribe_registry` callbacks / `TAMPER_BLOCKED` → emit `tamper_blocked`. |
| `_account_write(...)` | Per-PID rolling window (`PID_WRITE_BURST_BYTES=75 MB`, `WINDOW=4 s`). When tripped emits `kernel_write_burst` (weight 35, HIGH), debounced for 4 s. |
| `_account_rename(...)` | Per-PID rolling window (`PID_RENAME_BURST_COUNT=20`, `WINDOW=5 s`). Emits `kernel_rename_burst` (weight 40, HIGH). |

When the driver is missing the bridge stays idle; the user-mode-only
detectors continue to work.

---

### 4.7 `allowlist.py`

Operator-managed allowlist for trusted applications. Whitelist backup/
compression/sync software by process **name** or **image path prefix** to
exempt from scoring and auto-termination.

| Surface | Notes |
|---------|-------|
| `AllowEntry(kind, value, note, added_at)` | A single entry. `kind` is either `"name"` (process basename, lowercase) or `"path"` (image path prefix, lowercase-normalized). |
| `Allowlist(path="allowlist.json", autoload=True)` | Main class. Persists to JSON; `load()` on startup, `add/remove()` + `save()` on edits. |
| `add(value, kind="", note="")` | Add entry (duplicates ignored), persist. |
| `remove(value, kind="")` | Remove entry, persist. |
| `entries()` | Return all entries as dict list. |
| `pid_allowed(pid)` | Check if a PID's verified image path or basename matches an allowlist entry. Uses `psutil` to resolve PID → path/name; fail-closed if unreadable. Caches by create_time to defend against PID reuse. |
| `signal_exempt(sig)` | Scoring trust classifier: exempt signals from allowed PIDs from scoring. **However, high-confidence single-shot signals in `_NEVER_EXEMPT_SIGNALS` (canary, ransom_note_spread, defender_self_disable) are never exempted.** |
| `matches(name, exe_path)` | Check if name/path matches any allowlist entry (no PID lookup). |
| `combine_trust(*classifiers)` | Compose multiple trust functions with OR. Used to merge `actor_trust.signal_actor_trusted` + `allowlist.signal_exempt`. |

**Design philosophy:** Path-based entries defeat name spoofing
(`%TEMP%\veeamagent.exe` won't match a path entry), but name-only
entries cannot. To prevent accidental allowlisting of malware
disguised with a trusted name, canary/ransom-note-spread and other
high-confidence single-shot signals cannot be exempted by the allowlist.

---

### 4.8 `attack_map.py`

Pure data + query for mapping all detection signals to **MITRE ATT&CK
technique IDs**.

| Function | Purpose |
|----------|---------|
| `Technique(tid, name, tactic, tactic_ko, url)` | Define a technique. E.g., `T1486 Data Encrypted for Impact`. |
| `techniques_for(signal_name)` | Signal name → list of mapped techniques (empty if none). |
| `technique_dicts_for(signal_name)` | Serialized form (dict list) for dashboard/reports. |
| `primary_technique(signal_name)` | First technique only (for single-badge display). |
| `annotate_signal_dict(sig_dict)` | Add `attack` key (technique list) to a Signal dict. Display-layer only. |
| `label_for(signal_name)` | One-line summary: `"T1490 Inhibit System Recovery (+1)"` style. |

**Mapping examples:**
- `high_entropy_write`, `canary_modified` → `T1486 Data Encrypted for Impact`
- `vssadmin_delete_shadows` → `T1490 Inhibit System Recovery`
- `defender_disable_realtime` → `T1562.001 Impair Defenses` + `T1489 Service Stop`
- `wevtutil_clear_log` → `T1070.001 Indicator Removal: Clear Windows Event Logs`
- `schtasks_persistence` → `T1053.005 Scheduled Task/Job`
- `powershell_downloader` → `T1059.001 PowerShell` + `T1105 Ingress Tool Transfer`
- `process_masquerade` → `T1036.005 Masquerading: Match Legitimate Name or Location`
- `trusted_process_encrypting` → `T1055 Process Injection`
- `certutil_download`, `certutil_decode_payload` → `T1218 System Binary Proxy Execution`
- `bitsadmin_transfer` → `T1197 BITS Jobs`
- `kernel_service_create` → `T1543.003 Create or Modify System Process: Windows Service`
- `wmic_process_call_create` → `T1047 Windows Management Instrumentation`
- `archive_password_staging` → `T1560.001 Archive Collected Data: Archive via Utility`
- `rclone_exfil` → `T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage`

The dashboard and incident reports use this mapping to present
standard technique names to SOC/IR teams.

---

### 4.10 `detectors/process_kernel.py`

Subscribes to the bridge's `PROCESS_START` / `PROCESS_EXIT` events
(sourced from `PsSetCreateProcessNotifyRoutineEx`) and detects process
creation without WMI. Shares the regex `RULES` from
`process_cmdline.py` via `evaluate_cmdline`.

| Surface | Notes |
|---------|-------|
| `ProcessKernelDetector(engine, bridge)` | On construction, registers via `bridge.subscribe_process(self._on_process_event)`. No own thread — invoked from the bridge's receive thread. |
| `_on_process_event(evt)` | Reads the command line from `RG_EVENT.Extra`, calls `evaluate_cmdline(...)`, emits a `Signal` on match. |
| `run()` | No-op — callback-driven, just waits on the stop event. |

**Why over WMI**: (1) WMI polling has 50–500 ms latency and is lossy
under load, (2) the kernel callback fires synchronously before the new
process executes a single instruction, (3) command line comes from
kernel memory, so PEB tampering cannot hide it, (4) short-lived
processes that die faster than WMI's polling window are no longer
invisible.

When `process_cmdline` is also active the same rule may fire twice —
harmless because scoring is keyed by signal `name` + `weight`.

---

### 4.8 `detectors/registry_kernel.py`

Subscribes to the bridge's `REGISTRY` events (sourced from
`CmRegisterCallbackEx`). The driver pre-filters against a watch list,
so the detector's job is just to map a key path to a labelled signal.

| Pattern (lower-case substring match) | Signal | weight | severity |
|---------------------------------------|--------|-------:|----------|
| `\system\currentcontrolset\services\ransomguard` | `ransomguard_service_tamper` | 80 | CRITICAL |
| `\windefend`, `\wdfilter`, `\sense` etc. | `defender_*_tamper` | 70 | CRITICAL |
| `\image file execution options` | `ifeo_hijack` | 60 | HIGH |
| `\currentversion\run(once)?` | `run_key_persistence` | 30 | MEDIUM |
| `\schedule\taskcache` | `schtasks_persistence` | 35 | MEDIUM |
| no match | `registry_other` | 1 | LOW (telemetry) |

First match wins. Unmatched events still emit a LOW telemetry signal
so we don't silently drop them.

---

## 5. Dashboard — `dashboard/app.py`

A small Flask app, mounted in-process by `agent.py`.

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Render `templates/index.html`. |
| `/api/status` | GET | `agent.status()` JSON. |
| `/api/heartbeat` | GET | Liveness probe used by `watchdog_service` (200 OK). **Always open** — no auth required even when a token is set. |
| `/api/events` | GET | Last 100 rows from `EventStore`. |
| `/api/processes` | GET | `ProcessWatcher.snapshot(60)`. |
| `/api/actions` | GET | `ProcessResponder.actions(100)`. |
| `/api/reset` | POST | `engine.reset()`. **Auth required when token set.** |
| `/api/kill` | POST `{pid, reason?}` | `responder.manual_kill`. **Auth required when token set.** |
| `/api/release` | POST `{pid}` | `responder.manual_release`. **Auth required when token set.** |
| `/api/reports` | GET | `incident_reporter.recent(100)`. |
| `/api/reports/<filename>` | GET | Raw markdown body (`text/markdown`), 404 on miss/traversal. |
| `/api/admin/health` | GET | System health snapshot — responder mode, driver connected, uptime, watch dirs, allowlist count, **`auth_enabled`**, **integrations stats**. **Auth required when token set.** |
| `/api/admin/mode` | POST `{mode:"off\|quarantine\|kill"}` | Change responder mode on-the-fly. **Auth required when token set.** |
| `/api/admin/threats` | GET | Per-PID threat analysis (signals + ATT&CK techniques + score contribution). **Auth required when token set.** |
| `/api/admin/allowlist` | GET | All allowlist entries. **Auth required when token set.** |
| `/api/admin/allowlist` | POST `{value, kind:"name\|path", note?}` | Add allowlist entry. **Auth required when token set.** |
| `/api/admin/allowlist` | DELETE `{value, kind:"name\|path"}` | Remove allowlist entry. **Auth required when token set.** |

**Authentication:** When `auth_token` is configured, every endpoint marked
"Auth required" must present one of:
- Header: `X-API-Key: <token>`
- Header: `Authorization: Bearer <token>`

Read-only endpoints (`/api/status`, `/api/events`, etc.) are open by
default; set `auth_required_for_reads = true` in the config to gate them
too. `/api/heartbeat` is always open (watchdog liveness probe).

**Administrator panel** — new collapsible "Administrator" section in the Flask UI:
- **System health** — responder mode (off/quarantine/kill), minifilter connected, uptime, watch directory list, allowlist item count, auth/integration status.
- **Mode switcher** — POST `/api/admin/mode` to change mode on-the-fly (no restart needed).
- **Per-PID threat breakdown** — which processes drove the score, each signal's ATT&CK technique, aggregated contribution.
- **Allowlist editor** — UI form to add/remove entries, or manually edit `allowlist.json` and reload.

`create_app(agent)` is the factory; the agent thread runs the Flask
server with `use_reloader=False`.

The HTML template adds a fixed-position toast container and polls
`/api/reports` every 2.5 s; new entries spawn a toast that auto-dismisses
after 10 s.

---

## 5b. Enterprise modules

### `config.py`

Central policy file loader. Auto-detects `ransomguard.toml` (Python 3.11+
`tomllib`) or `ransomguard.json` in the working directory, or uses the
path supplied by `--config <path>`.

**Precedence: CLI flag > config file > built-in default.**

| Section | Key fields |
|---------|-----------|
| `[general]` | `watch_dirs`, `responder_mode`, `enable_minifilter` |
| `[dashboard]` | `host`, `port`, `auth_token`, `auth_required_for_reads` |
| `[syslog]` | `enabled`, `host`, `port`, `protocol` (udp/tcp), `min_severity` |
| `[webhook]` | `enabled`, `url`, `min_severity` |

Secret environment variables (always win over the file):
- `RANSOMGUARD_AUTH_TOKEN` — dashboard API token.
- `RANSOMGUARD_WEBHOOK_URL` — enables webhook and sets the URL.
- `RANSOMGUARD_SYSLOG_HOST` — enables syslog and sets the host.

### `integrations.py`

Async SIEM/alert forwarding worker. **Fail-open** design — an integration
failure is logged but never propagates to the detection hot-path.

| Integration | Protocol | Notes |
|-------------|----------|-------|
| **SIEM** | CEF over syslog (UDP or TCP) | Streams events in the standard format parsed by Splunk/QRadar/ArcSight/Sentinel. Only events at or above `min_severity` (default HIGH) are forwarded. |
| **Webhook** | HTTPS JSON POST | Instant JSON push to Slack/Teams/PagerDuty/SOAR. `min_severity` default CRITICAL. |

Zero external dependencies (standard library only). Integration failures
are logged; the agent continues detecting normally.

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

- `RG_PORT_NAME = L"\\RansomGuardPort"`, altitude `385201`, **protocol version `2`**, max path 520 WCHARs, auxiliary `Extra[1024]` buffer.
- `RG_EVENT_KIND` (8 kinds): `RgEventCreate(1)`, `RgEventWrite(2)`, `RgEventSetInfo(3)`, `RgEventBlocked(4)`, **`RgEventProcessStart(5)`**, **`RgEventProcessExit(6)`**, **`RgEventRegistry(7)`**, **`RgEventTamperBlocked(8)`**.
- `RG_SETINFO_KIND`: `Other/Rename/Delete`.
- `RG_REGISTRY_KIND`: `Other/SetValue/DeleteValue/CreateKey/DeleteKey/RenameKey`.
- `RG_TAMPER_KIND`: `Process(1)/Thread(2)`.
- `RG_EVENT` (`#pragma pack(4)`, v2): `Version, Kind, SubKind, ProcessId, ParentProcessId, ThreadId, Status, DesiredAccess, WriteBytes (u64), TimestampNs (u64), PathLength, ExtraLength, Path[520 WCHAR], Extra[1024 WCHAR]` (command line or registry value name).
- `RG_COMMAND_KIND` (6 kinds): `RgCmdQuarantinePid(1)`, `RgCmdReleasePid(2)`, `RgCmdPing(3)`, **`RgCmdProtectPid(4)`**, **`RgCmdUnprotectPid(5)`**, **`RgCmdFlushQuarantine(6)`**.
- `RG_COMMAND` / `RG_REPLY`: control plane structures.

v1 → v2 summary: added process create/exit, registry, and self-protection
events; added `ParentProcessId` and a secondary `Extra` buffer; added
`ProtectPid`/`UnprotectPid`/`FlushQuarantine` commands; adopted a
"sticky quarantine" model (the quarantine list is preserved when the
user-mode bridge disconnects).

### 7.2 `minifilter/RansomGuard.c`

Compact minifilter — keeps logic out of the kernel.

**Global state** (`g_Rg`):
- `Filter`, `ServerPort`, `ClientPort` (single connected listener).
- `ClientLock` (FAST_MUTEX) protects the port.
- `QuarantineLock` (`EX_PUSH_LOCK`) protects `QuarantinedPids[256]`.
- **`ProtectLock` (`EX_PUSH_LOCK`)** protects `ProtectedPids[16]` (v2).
- **`CmCallbackCookie`** — `CmRegisterCallbackEx` registration handle (v2, registry callback).
- **`ObCallbackHandle`** — `ObRegisterCallbacks` handle (v2, handle-access stripping).
- `PerfFrequency` cached at boot for ns conversion.

**Lifecycle**:
- `DriverEntry` — `FltRegisterFilter`, build a default security descriptor, `FltCreateCommunicationPort(RG_PORT_NAME, …, callbacks, max-connections=1)`, `FltStartFiltering`, **`PsSetCreateProcessNotifyRoutineEx`**, **`CmRegisterCallbackEx`**, **`ObRegisterCallbacks`**.
- `RgUnload` — close the port, unregister every callback, delete the push-locks.

**Operation callbacks** (`Callbacks[]` registers `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`):
- `RgPostCreate` — emit `RgEventCreate` on user-mode, successful opens (drains and kernel callers are skipped).
- `RgPreWrite` — if requesting PID is quarantined, emit `RgEventBlocked(Write)` and complete the IRP with `STATUS_ACCESS_DENIED`; else continue.
- `RgPostWrite` — for writes ≥ 4096 bytes (sub-page throttled), emit `RgEventWrite` carrying `IoStatus.Information` as `WriteBytes`.
- `RgPreSetInfo` — classify as `Rename`, `Delete`, or `Other`. Skip `Other`. Block quarantined PIDs on rename/delete; otherwise pass `sub` via `CompletionContext`.
- `RgPostSetInfo` — emit `RgEventSetInfo` with the saved sub-kind.

**v2 additional callbacks**:
- **`RgCreateProcessNotify`** (`PsSetCreateProcessNotifyRoutineEx`) — synchronously detects process create/exit in the kernel. On create, fills `RG_EVENT.Extra` with the command line and emits `RgEventProcessStart`. On exit, emits `RgEventProcessExit` and auto-removes the PID from the quarantine list.
- **`RgCmRegistryCallback`** (`CmRegisterCallbackEx`) — pre-filters high-value key changes (Defender / Run / RansomGuard service) against a watch list and emits `RgEventRegistry`.
- **`RgObPreOperation`** (`ObRegisterCallbacks`, `ObjectType=PsProcessType/PsThreadType`) — strips dangerous access rights (`PROCESS_TERMINATE`, `PROCESS_VM_*`, `THREAD_TERMINATE` etc.) from handles opened to protected PIDs by other callers. Self-callers pass through. Emits `RgEventTamperBlocked` on strip.

**Quarantine bitmap** (`RgIsQuarantined`, `RgAddQuarantine`, `RgRemoveQuarantine`) — linear scan over a 256-entry array under a push-lock. Capacity-bounded so the kernel side stays trivially safe.

**Protected bitmap (v2)** (`RgIsProtected`, `RgAddProtected`, `RgRemoveProtected`) — separate `ProtectedPids[16]` under its own push-lock. Queried by `ObCallback` on handle-open. v2 also introduces the "sticky" model: the quarantine list is preserved when user mode disconnects and is only cleared on an explicit `FlushQuarantine` command (anti-tamper default).

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
then `fltmc load RansomGuard`, and treats presence in `fltmc filters` as
the source of truth (a nonzero load exit when already loaded is fine as
long as the filter is listed).

### 8.6 `scripts/uninstall_driver.ps1`

Admin-only.  `fltmc unload RansomGuard` → `rundll32
setupapi.dll,InstallHinfSection DefaultUninstall 132` (or `sc.exe
delete RansomGuard` as a fallback) → removes
`%windir%\System32\drivers\RansomGuard.sys`.

### 8.7 `scripts/install_services.ps1`

Admin-only.  Parameters: `-WatchDirs`, `-Mode`, `-DashboardPort`,
`-NoHeartbeat`.  Steps:

1. `service.py install` registers `RansomGuardAgent`; `watchdog_service.py install` registers `RansomGuardWatchdog`.
2. Configures SCM recovery options on both services — first/second/subsequent failures all trigger an immediate auto-restart.
3. Writes `WatchDirs`, `Mode`, `DashboardPort` etc. under `HKLM\…\Services\RansomGuardAgent\Parameters`.
4. Creates the `C:\ProgramData\RansomGuard\` data directory and locks the DACL to SYSTEM/Administrators only.
5. `sc.exe start` for both services.

### 8.8 `scripts/uninstall_services.ps1`

Admin-only.  Stops both services in order, then removes them via
`service.py remove` / `watchdog_service.py remove`.
`C:\ProgramData\RansomGuard\` is intentionally preserved (manual
cleanup, protects incident reports).

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
