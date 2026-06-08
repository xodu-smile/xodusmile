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
- **Ransom note detector** — polls watch directories for ransom-note
  filenames (HOW_TO_DECRYPT.txt, _readme.txt, RESTORE-MY-FILES.txt,
  *.hta, etc.). A single note triggers HIGH; **notes spreading across
  2+ directories within 60 seconds trigger CRITICAL**. Boosted if canary
  already tripped. Multi-dir spread requirement keeps false positives low.
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
- **Operator allowlist** — register trusted third-party apps (Veeam,
  Acronis, 7-Zip, etc.) by process name or image path prefix to prevent
  false-positive kills. High-confidence signals (canary, ransom note
  spread) bypass the allowlist to prevent abuse.
- **MITRE ATT&CK technique tagging** — every signal maps to standard
  ATT&CK technique IDs (T1486, T1490, etc.). Appears in incident reports
  and admin dashboard for SOC/IR integration with external SIEM/EDR.
- **Administrator dashboard panel** — collapsible "Administrator" section
  with system health, responder-mode switcher (off/quarantine/kill),
  per-PID threat breakdown (with ATT&CK tags), and allowlist editor.
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
| `--allowlist <path>`            | Operator allowlist JSON file (default `allowlist.json`). Register trusted apps to reduce false positives. |
| `--no-minifilter`               | Skip the kernel bridge (user-mode-only detection).                                     |
| `--no-dashboard`                | Don't start the Flask UI.                                                              |
| `--port N`                      | Dashboard port (default `5000`).                                                       |
| `--db PATH`                     | SQLite path (default `detector.db`).                                                   |
| `--reports-dir PATH`            | Where to write markdown incident reports (default `./reports`).                        |
| `--no-notify`                   | Suppress desktop notifications when a process is killed.                               |
| `--no-tamper-protection`        | Disable `RtlSetProcessIsCritical` + DACL hardening (useful in dev so you can taskkill).|
| `--watchdog-pid <PID>`          | PID of the companion watchdog; will be kernel-tamper-protected alongside the agent.    |

## Validation

### Simulators and demos

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

### Automated tests

```powershell
# Run pytest suite (logic-level unit tests)
pytest

# Or explicitly
python -m pytest
```

A pytest test suite lives under `tests/`:
- `test_scoring.py` — scoring engine and signal weights
- `test_attack_map.py` — MITRE ATT&CK technique mapping
- `test_allowlist.py` — operator allowlist logic
- `test_mass_io.py` — entropy / burst detector
- `test_ransom_note.py` — ransom note detector
- `test_responder.py` — active responder (quarantine / kill)
- `test_incident_report.py` — incident report generation
- `test_dashboard_api.py` — Flask REST API

**Note:** Windows-dependent parts (psutil, WMI, Flask) are skipped on non-Windows
platforms; pure logic tests run everywhere. See `pytest.ini` and `tests/conftest.py`.

## Lab testing with real samples

> ⚠ **The simulators above exercise most of the detection logic.** Real
> ransomware samples are only needed to observe extra behaviours (privilege
> escalation, propagation, anti-VM), and must be detonated **only in a
> dedicated VM with the network isolated and a snapshot taken**. A real
> sample encrypts the whole system beyond the watch dir and can leave the
> VM unbootable.

### Quick run — `scripts\lab.ps1`

Instead of typing every command below, an orchestrator wraps the flow into
short subcommands. Register the watch dir **once**; later phases reuse it.
The safety gates stay in place — **you take the snapshot and launch the
sample yourself**, and `detonate` only disables Defender + extracts the
archive (it never runs the sample).

```powershell
.\scripts\lab.ps1 set -WatchDir C:\Users\you\Documents  # register watch dir once
.\scripts\lab.ps1 driver        # (optional) build+install+verify driver, after testsigning reboot
.\scripts\lab.ps1 run           # start the agent (e.g. lab.ps1 run --no-minifilter)
.\scripts\lab.ps1 preflight     # GO/NO-GO check + decoys (-Count default 500)
#   --> take the VM snapshot here (manually) <--
.\scripts\lab.ps1 detonate -SampleZip C:\in\s.zip -Password infected -OutDir C:\sample
#   --> extract only; verify snapshot, then launch the sample yourself <--
.\scripts\lab.ps1 postmortem    # score -> postmortem.md
#   --> restore the snapshot <--
.\scripts\lab.ps1 help          # full flow / current watch dir
```

The detailed steps below explain what each phase does.

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

**Detonate — disable Defender first**

```powershell
# (a) Get Defender out of the way — if you don't, the sample is deleted the
#     instant you extract it (the cause of "empty folder + no password prompt").
#     Turn OFF Tamper Protection in the Windows Security UI first, then:
Set-MpPreference -DisableRealtimeMonitoring $true   # or -ExclusionPath 'C:\sample'

# (a-1) Confirm it actually took — if Tamper Protection (IsTamperProtected) is
#       on, the command above is silently ignored. RealTimeProtectionEnabled
#       must read False.
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected, AntivirusEnabled
#   RealTimeProtectionEnabled=True or IsTamperProtected=True means it is NOT off
#   yet — disable Tamper Protection in the UI and re-run (a). (If the sample was
#   already deleted, restore it from "Security > Protection history > Quarantined
#   items" or MpCmdRun.exe -Restore -ListAll.)

# (b) Extract the sample *outside* the watch dir (e.g. C:\sample), then run it.
#     ⚠ Do NOT use Windows Explorer for password-protected zips. Modern
#        password archives are AES-encrypted, which Explorer can't decrypt — it
#        gives no password prompt and leaves an "empty folder" (even for a .zip).
#        Use 7-Zip:
#        winget install -e --id 7zip.7zip   # if not installed
# format: & 'C:\Program Files\7-Zip\7z.exe' x '<path to the .zip>' -o'<folder to extract into>' -p<password>
& 'C:\Program Files\7-Zip\7z.exe' x '<path to the .zip>' -o'<folder to extract into>' -p<password>
#   No space after -o / -p. A "CRC failed"/"Data error" means the archive was
#   truncated during download → re-download.
```

> ⚠ Disabling Defender is **for the isolated VM only**; always revert the
> snapshot afterwards. Note that RansomGuard's responder only terminates
> processes (`responder.py`) — it never deletes files, so an emptied folder
> is Defender, not this tool.

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

## False-positive prevention

RansomGuard is designed to reduce false positives on multiple layers:

- **Native high-entropy format exclusion:** `.zip`, `.rar`, `.7z`, `.jpg`,
  `.mp3`, `.mp4`, `.avi` and other natively high-entropy files are excluded
  from static entropy signals. Reduces false positives from normal photo
  editing, video transcoding, and archive updates.
- **Ransom note multi-directory spread requirement:** A single README.txt
  triggers HIGH; spreading across **2+ directories within 60 seconds**
  triggers CRITICAL. Protects legitimate single documents.
- **Operator allowlist:** Whitelist backup/compression/sync software by
  process **name** or **image path prefix**. Path-based entries defeat
  name spoofing (`%TEMP%\veeamagent.exe` won't match a path entry).
  **However, high-confidence single-shot signals (canary, ransom note
  spread) bypass the allowlist to prevent abuse.**
- **Trust-based score exemption:** System processes (Defender, WMI,
  servicing) are excluded from scoring.

## Safety

The responder will terminate processes.  In an automated lab the
default `kill` mode is what you want; on a desktop you may prefer
`--mode quarantine` while you tune thresholds.  The hard never-kill
list in `responder.py:NEVER_KILL` protects `lsass`, `csrss`, etc. — do
not relax it.

Do not run the simulator on a machine with real user data; it overwrites
its dummy files with high-entropy noise.

## MITRE ATT&CK technique tagging

All detection signals are tagged with standard **MITRE ATT&CK technique
IDs** (T1486, T1490, etc.). The dashboard reports and admin panel display
standard names like "T1486 Data Encrypted for Impact", "T1490 Inhibit
System Recovery", enabling SOC/IR teams to immediately integrate with
internal SIEM rules, threat intelligence, and external EDR platforms.

## Known gaps

- No Authenticode whitelist; the responder can in principle terminate
  signed user processes that look noisy.  Tune `--mode` and watch the
  responder log on first deploy.
- The minifilter only observes; it does not write any context to disk
  for offline forensics.  Use the SQLite event store for that.
- Intermittent encryption (slow writes spread over hours) is not
  specifically modelled — the 120s scoring window will not catch it.
