# RansomGuard EDR (Windows 11)

> 🌐 한국어 버전: [README.md](./README.md)

A small ransomware-focused EDR for Windows 11.  It pairs a kernel-mode
file-system **minifilter** with user-mode behavioural detectors and an
**active responder** that can quarantine and terminate a suspicious
process the moment it crosses a threshold.

> This is a research/training prototype.  Run only on machines you own,
> ideally an isolated VM.  Loading the driver requires test signing or a
> trusted signature.

## Features

- **Kernel minifilter** (`minifilter/RansomGuard.sys`) — observes
  `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION` on every
  volume; streams `(pid, path, op, bytes)` events to user mode over a
  filter communication port; and can block subsequent writes/renames
  from a quarantined PID inside the kernel.
- **Per-PID burst detection in user mode** — the bridge accumulates
  write bytes and rename counts per PID; large bursts inside a short
  window produce HIGH-severity signals independent of which directory
  the writes hit.
- **Canary files** — high-confidence trip-wire; any modification yields
  a CRITICAL signal.
- **Process command-line rules** — VSS shadow-copy deletion, BCD
  tampering, Defender disablement, log wiping, BitLocker disable, common
  PowerShell obfuscation patterns.
- **Process tree heuristics** — LOLBin parent/child chains (Office →
  PowerShell, browser → script host), child fan-out from one parent,
  user-mode disk-write bursts from psutil.
- **Active responder** — three modes: `off`, `quarantine`, `kill`.  In
  `kill` mode, any HIGH/CRITICAL signal that carries a PID immediately
  triggers a kernel quarantine and a `TerminateProcess`.  Critical
  processes (lsass, csrss, etc.) are on a hard-coded refuse list.
- **Flask dashboard** at `http://127.0.0.1:5000` — live score, recent
  events, process table, responder log, manual kill/release.

## Architecture

```
                       +-----------------------------+
                       |     RansomGuard.sys         |  (kernel minifilter)
                       |  IRP file ops · Ps callback |
                       |  Cm callback  · Ob callback |
                       +--------------+--------------+
                                      | filter port (\RansomGuardPort)
                                      v
   +-----------------+      +---------------------+      +-------------------+
   |  user-mode      |      |  minifilter_bridge  |      |    responder      |
   |  detectors:     |      |  (ctypes -> fltlib) |<---> |  - quarantine     |
   |   canary        |----->+----------+----------+      |  - terminate      |
   |   mass_io       |                 |                 +---------+---------+
   |   process_*     |                 v                           |
   +--------+--------+      +---------------------+                |
            |               |  process_kernel     |                |
            |               |  registry_kernel    |                |
            |               +----------+----------+                |
            |                          |                           |
            +-----------+------------- v --------------------------+
                        v       +---------------------+
                 +------+-----+ |   ScoringEngine     |<--+
                 |   tamper   | |   (rolling 120s)    |   |
                 +------------+ +----------+----------+   |
                                           |              |
                                           v              |
                                +---------------------+   |
                                |  EventStore (SQLite)|   |
                                +----------+----------+   |
                                           |              |
                              +------------+------------+ |
                              v                         v |
                +---------------------+    +---------------------+
                |   Flask dashboard   |    |   incident_report   |
                +---------------------+    |  (markdown + notif) |
                            ^              +---------------------+
                            |
                            +--- watchdog_service (heartbeat / restart)
```

| Component                        | Role                                            |
|----------------------------------|-------------------------------------------------|
| `minifilter/RansomGuard.c`       | Kernel minifilter driver                        |
| `minifilter/RansomGuard.h`       | Shared event/command layout                     |
| `detectors/minifilter_bridge.py` | User-mode connector (`ctypes` → `fltlib.dll`)   |
| `detectors/canary.py`            | Canary file SHA-256 trip wires                  |
| `detectors/mass_io.py`           | Watchdog-based bulk I/O + entropy + magic-byte  |
| `detectors/process_cmdline.py`   | WMI process-create rules (VSS/BCD/Defender/…)   |
| `detectors/process_watcher.py`   | psutil polling, LOLBin chains, fan-out          |
| `detectors/process_kernel.py`    | Kernel-callback process-create detector (no WMI)|
| `detectors/registry_kernel.py`   | Kernel-callback registry-write detector         |
| `scoring.py`                     | Weighted, time-windowed signal aggregation      |
| `responder.py`                   | Quarantine + terminate suspicious PIDs          |
| `incident_report.py`             | Markdown incident reports + desktop notification|
| `tamper.py`                      | Critical-process flag + DACL hardening          |
| `event_store.py`                 | SQLite persistence                              |
| `dashboard/app.py`               | Flask UI + `/api/*`                             |
| `service.py`                     | Windows service host (`RansomGuardAgent`)       |
| `watchdog_service.py`            | Sidecar service that restarts the agent on hang |

## Requirements

- **OS:** Windows 11 (22H2 or newer), x64.
- **User-mode:** Python 3.10+ x64.
- **Kernel-mode build:** Visual Studio 2022 Build Tools with the C++
  workload + Windows Driver Kit (WDK 10.0.26100 or compatible).
- **Driver load:** test signing enabled, *or* an attestation-signed
  catalog for `RansomGuard.sys`.

The user-mode agent alone runs without the WDK or the driver — you just
lose the kernel-level file I/O signal source.

## Install

From an elevated PowerShell at the repo root:

```powershell
# Option A — everything: Python deps + build + install the driver.
.\scripts\install.ps1

# Option B — user-mode only.  Python, venv, requirements.
.\scripts\bootstrap.ps1

# Option C — bootstrap and also build/install the driver.
.\scripts\bootstrap.ps1 -BuildDriver -InstallDriver
```

`bootstrap.ps1` will:

1. install Python 3.12 via `winget` if missing,
2. create `.venv\` in the repo root,
3. install `requirements.txt`,
4. run `pywin32_postinstall -install`,
5. optionally build and install the driver.

The driver build script (`scripts/build_driver.ps1`) calls `msbuild`
located via `vswhere` and produces `minifilter\build\x64\Release\
RansomGuard.sys` plus `.inf` and `.cat`.

If the WDK or VS Build Tools are missing, the script prints the exact
`winget` lines to install them rather than attempting an unattended
multi-GB install.

## Run

### As a service (recommended for any real test)

```powershell
# Installs RansomGuardAgent + RansomGuardWatchdog services, configures
# SCM auto-restart on failure, locks service + data-dir DACLs to
# SYSTEM/Admins, starts both.
.\scripts\install_services.ps1 -WatchDirs 'C:\Users'

# Uninstall.
.\scripts\uninstall_services.ps1
```

The agent runs under LocalSystem with `RtlSetProcessIsCritical` set
and is registered with the kernel driver's `ObCallback` for handle-
access stripping; the watchdog polls the agent every 5 s and restarts
it on crash or missed heartbeat.  Data lives at
`C:\ProgramData\RansomGuard\`.

### As a CLI (dev / one-off)

```powershell
.\.venv\Scripts\Activate.ps1

# Default: minifilter on, responder will quarantine + kill.
python agent.py --watch C:\Users\you\Documents

# Headless observer (no killing) — useful while tuning.
python agent.py --mode off --no-dashboard

# Quarantine but do not terminate.
python agent.py --mode quarantine

# Dev convenience: skip tamper hardening so taskkill works.
python agent.py --no-tamper-protection
```

CLI flags:

| Flag                            | Effect                                                                                 |
|---------------------------------|----------------------------------------------------------------------------------------|
| `--watch <dir>`                 | Directory to monitor (repeatable). Default: `./test_watch_dir`.                        |
| `--mode {off,quarantine,kill}`  | Responder mode. Default `kill`.                                                        |
| `--no-minifilter`               | Skip the kernel bridge (user-mode-only detection).                                     |
| `--no-dashboard`                | Don't start the Flask UI.                                                              |
| `--port N`                      | Dashboard port (default `5000`).                                                       |
| `--db PATH`                     | SQLite path (default `detector.db`).                                                   |
| `--reports-dir PATH`            | Where to write markdown incident reports (default `./reports`).                        |
| `--no-notify`                   | Suppress desktop notifications when a process is killed.                               |
| `--no-tamper-protection`        | Disable `RtlSetProcessIsCritical` + DACL hardening (useful in dev so you can taskkill).|
| `--watchdog-pid <PID>`          | PID of the companion watchdog; will be kernel-tamper-protected alongside the agent.    |

The dashboard exposes:

- `GET  /api/status`             — current score, level, recent signals, responder state
- `GET  /api/heartbeat`          — liveness probe used by `watchdog_service` (200 OK)
- `GET  /api/events`             — last 100 persisted signals
- `GET  /api/processes`          — live process snapshot from the watcher
- `GET  /api/actions`            — responder action log
- `GET  /api/reports`            — list markdown incident reports under `--reports-dir`
- `GET  /api/reports/<filename>` — fetch a single incident report by filename
- `POST /api/kill`               — `{ "pid": 1234, "reason": "..." }` manual kill
- `POST /api/release`            — `{ "pid": 1234 }` release a quarantined PID
- `POST /api/reset`              — reset the scoring window

## Validation

```powershell
# In-process demo: spins up the agent and injects safe simulated events.
python demo_inproc.py

# Standalone simulator: writes random bytes to dummy files in the watch dir
# and renames them with .encrypted — NO real cryptography is performed.
# vss / bcd inject fake cmdline events through ProcessCmdlineDetector.submit_external
# (no real vssadmin/bcdedit is ever spawned).  stealth uses a slow encryption
# pace to evade the burst threshold but still trips magic/entropy/extension.
python tests\simulator.py --scenario {populate|encrypt|canary|vss|bcd|full|stealth}
```

Neither runs real `vssadmin` / `bcdedit` commands; cmdline rules are
exercised through `ProcessCmdlineDetector.submit_external`.

## Uninstall

```powershell
.\scripts\uninstall_driver.ps1
Remove-Item -Recurse -Force .\.venv
```

## Safety

The responder will terminate processes.  In an automated lab the
default `kill` mode is what you want; on a desktop you may prefer
`--mode quarantine` while you tune thresholds.  The hard never-kill
list in `responder.py:NEVER_KILL` protects `lsass`, `csrss`, etc. — do
not relax it.

Do not run the simulator on a machine with real user data; it overwrites
its dummy files with high-entropy noise.

## Known gaps

- No Authenticode whitelist; the responder can in principle terminate
  signed user processes that look noisy.  Tune `--mode` and watch the
  responder log on first deploy.
- The minifilter only observes; it does not write any context to disk
  for offline forensics.  Use the SQLite event store for that.
- Intermittent encryption (slow writes spread over hours) is not
  specifically modelled — the 120s scoring window will not catch it.
