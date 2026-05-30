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

## Scoring

No single signal decides anything. Scores from every signal inside a
**rolling 120-second window** are summed to pick a level. (Use this table
when reading postmortem / dashboard output.)

| Score   | Level    | Meaning           |
|---------|----------|-------------------|
| 0–29    | INFO     | normal            |
| 30–59   | LOW      | mildly suspicious |
| 60–99   | MEDIUM   | watch             |
| 100–149 | HIGH     | dangerous         |
| 150+    | CRITICAL | respond now       |

Old signals age out after two minutes, so a past event won't keep the
alarm ringing.

## Requirements

- **OS:** Windows 11 (22H2 or newer), x64 or ARM64.
- **User-mode:** Python 3.10+ (x64 or ARM64).
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
located via `vswhere`, restores the WDK/SDK NuGet packages first, and
**auto-detects the host architecture** — building x64 on an x64 host and
ARM64 on an ARM64 host. Output lands at `minifilter\build\<arch>\Release\
RansomGuard.sys` plus `.inf` and `.cat` (override with `-Platform x64|ARM64`).

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

## Lab testing with real samples

> ⚠ **The simulators above exercise most of the detection logic.** Real
> ransomware samples are only needed to observe extra behaviours (privilege
> escalation, propagation, anti-VM), and must be detonated **only in a
> dedicated VM with the network isolated and a snapshot taken**. A real
> sample encrypts the whole system beyond the watch dir and can leave the
> VM unbootable.

Two helpers bracket the detonation.

**Before — readiness check (`scripts/lab_preflight.ps1`)**

Verifies isolation and prints GO / NO-GO. Any BLOCKER (physical machine,
real internet reachable, snapshot unconfirmed) exits `1`.

```powershell
# Elevated PowerShell, inside the isolated VM
.\scripts\lab_preflight.ps1 -WatchDir C:\Users\you\Documents -Count 500
```

Checks: VM detection · network isolation · host share channels · testsigning
· driver/agent loaded · decoy file population · snapshot confirmation.

**After — scorecard (`postmortem.py`)**

Reads only disk-persisted evidence (`detector.db`, `reports/`, the watch
dir) so it still works if the agent was killed or the VM bugchecked.

```powershell
# Run before reverting the snapshot
python postmortem.py --watch C:\Users\you\Documents --out postmortem.md
```

Reports: detection/response latency timeline · detector & severity
breakdown · quarantine/kill tally · decoy damage ratio (= pre-detection
loss) · files damaged after first response · ransom-note candidates.

**Full flow**

```powershell
python agent.py --watch C:\Users\you\Documents                 # 1) agent (tamper ON)
.\scripts\lab_preflight.ps1 -WatchDir C:\Users\you\Documents   # 2) confirm GO -> snapshot
#                                                              # 3) detonate the sample (isolated VM)
python postmortem.py --watch C:\Users\you\Documents --out postmortem.md  # 4) collect
#                                                              # 5) revert snapshot
```

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
