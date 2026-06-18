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

Detection is handled by **one kernel driver + eight user-mode detectors**, all
feeding a single scoring engine (120-second sliding window). When the evidence
crosses the threshold, the responder quarantines/kills the process and the
incident is written up automatically as a readable report.

### Detection

| Detector | What it does, concretely |
|---|---|
| **Kernel minifilter** (`minifilter/RansomGuard.sys`) | Intercepts `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION` on every volume and streams `(pid, path, op, bytes)` events to user mode over a filter communication port. Also forwards **process create/exit** (`PsSetCreateProcessNotifyRoutineEx`) and **registry writes** (`CmRegisterCallbackEx`) on the same channel. Writes/renames from a quarantined PID are **rejected pre-op, inside the kernel**. |
| **Per-PID burst detection** (`minifilter_bridge`) | Accumulates kernel events per PID — **75 MB+ written within 4 s** or **20+ renames within 5 s** raises HIGH (`kernel_write_burst` / `kernel_rename_burst`). Keyed on the **process**, not the path, so encryption outside the watch dirs is still caught. |
| **Kernel process watch** (`process_kernel`) | Applies the 33 command-line rules at process-creation time — via the kernel callback, **before the new process runs a single instruction** and without WMI. The command line comes from kernel memory, so **PEB tampering can't hide it**, and short-lived processes that WMI (50–500 ms latency, lossy under load) used to miss are now visible. |
| **Kernel registry watch** (`registry_kernel`) | Scores writes/deletes against high-value keys: Defender services (`WinDefend`/`WdFilter`/`Sense`), Defender settings/policy keys, SafeBoot, Run/RunOnce persistence, System policy (UAC/SmartScreen), and **RansomGuard's own service key** (driver-unload attempts = self-protection). Known-benign writes (ctfmon's `internat.exe`, Defender's own telemetry timestamps) are excluded per value name. |
| **Process command-line rules (33)** (`process_cmdline`) | Regex-checks every new process's command line from both WMI and kernel sources. VSS shadow-copy deletion/resize, BCD tampering, Defender/SmartScreen disablement, event-log & USN-journal wiping, firewall-off, BitLocker disable — plus living-off-the-land rules that abuse built-in/signed tools as encryption engines: `cipher /e` (EFS), forced BitLocker encryption (`manage-bde -on` / `Enable-BitLocker`), LOLBin proxy execution (`certutil` / `bitsadmin` / `esentutl` / `wmic process call create`), BYOVD (`sc create type=kernel`), double-extortion staging (`7z -p` / `rclone`), and obfuscated PowerShell (encoded commands, in-memory downloaders, policy bypass). |
| **Ransom note detector (content-aware)** (`ransom_note`) | 12 filename patterns (`HOW_TO_DECRYPT*`, `_readme.txt`, …) **plus content analysis**: crypto wallet addresses (BTC/ETH/XMR) and `.onion` URLs are *strong* indicators; extortion phrases, decryption instructions, payment terms, contact channels, and threat language are *weak* ones. Confirmation requires **≥ 1 strong indicator and a total score ≥ 3** — so **randomly named notes (`A7F3C.txt`) are caught by content**. Single content-confirmed note = HIGH; name-only match = MEDIUM hint. **CRITICAL spread**: content-confirmed notes in ≥ 3 directories within 60 s, or name-matched notes in ≥ 3 dirs with corroborating real encryption activity. Files over 64 KB and symlinks are excluded. |
| **Canary files** (`canary`) | Five decoy files named to sort first/last (`!!_DO_NOT_TOUCH_!!.docx`, …) deployed in every watch directory, SHA-256-polled every 1.5 s. Any modification/deletion = **standalone CRITICAL**. For 30 s after a trip, a **cross-detector boost** lowers the mass_io entropy bar 7.5→6.8, multiplies weights ×1.5, and escalates a single ransom note to CRITICAL. |
| **Mass I/O analysis** (`mass_io`) | Samples the first 4 KB of changed files: Shannon entropy (≥ 7.5) + 10 magic-byte signatures (PE/PDF/Office/ZIP/JPEG …). Signals: **magic bytes lost** (HIGH — known format became unrecognizable), **high-entropy write** (MEDIUM), **ransom-extension rename** (HIGH — `.encrypted`/`.lockbit`/…), and a **burst** when 15+ encryption-pattern events land within 10 s (HIGH). |
| **Process tree heuristics** (`process_watcher`) | psutil-based: LOLBin parent/child chains (Office → PowerShell, browser → script host), **fan-out of 12+ children within 5 s**, **50 MB+ disk-write burst within 2 s**, and **system-binary masquerade detection** — a core system name (svchost.exe, lsass.exe, …) running from outside System32/SysWOW64 (e.g. `%TEMP%\svchost.exe`, T1036.005) scores immediately. |

### Scoring & trust model

| Feature | Description |
|---|---|
| **Windowed accumulation** | No single signal decides anything: weights are summed over a **120-second window** into five levels (INFO→CRITICAL); old signals age out naturally. |
| **Two-tier actor trust** (`actor_trust`) | Trust is decided by the **verified on-disk image path**, never the bare name (`C:\Temp\MsMpEng.exe` fails). FULL trust (Defender, servicing, WMI — all activity exempt) is distinct from REGISTRY_ONLY trust (svchost — registry/housekeeping exempt, **bulk file mutation still scored**), so svchost-hosted ransomware is caught while boot-time OS housekeeping no longer inflates an idle machine to CRITICAL. Unresolvable paths **fail closed** (untrusted). |
| **Trust-gate blind-spot closure** | *Ground-truth* encryption evidence — canary trips, magic-byte loss, ransom-extension renames, note spread, kernel-blocked writes — is **always scored even from a trusted actor**: a genuine system component never does these, so they are evidence of injection (T1055) or masquerade (T1036). |
| **Correlation gating** | Common benign behavior like `file_delete` contributes zero on its own — it is weighted **only when the same PID also shows real encryption activity**. |
| **Threat-level auto-recovery** | When the responder terminates a PID, its signals are purged from the live scoring window (`forget_pid`) — once all active attackers are gone the dashboard **returns to "safe" on its own**, no operator reset needed. Other PIDs' scores and the permanent audit trail (SQLite, reports) are untouched. |

### Active responder

| Feature | Description |
|---|---|
| **Three modes** | `off` (observe), `quarantine` (kernel blocks file I/O), `kill` (block + `TerminateProcess`, the default). Switchable at runtime from the dashboard. |
| **Targeted response (no score-sweep)** | Reacts **only to HIGH/CRITICAL signals that name a PID** — a high aggregate score never sweeps every PID in the window. CRITICAL acts immediately; **a HIGH heuristic needs corroboration** (real encryption activity in the window, or a second distinct detector naming the same PID). Otherwise it is recorded as `observed only` for the operator to judge. |
| **Parent escalation** | Destruction usually runs through transient LOLBins (vssadmin, powershell, cmd — 19 names); killing the tool is too late or refused, so **the parent that issued the command — the actual malware body — is terminated too**. |
| **Never-kill safeguard** | **47 hard-coded processes** (OS core, browsers, shell/UI, dev tools) are never terminated. 19 core system binaries among them are **path-verified**: an impostor carrying the name from outside System32 loses the immunity. |
| **At-action forensic capture** | Image path, owning user, parent PID/name, trigger signal, and score/level are captured at kill time (unavailable once the process is gone). The image SHA-256 is computed **after** quarantine/termination so hashing never delays the block. |

### Reporting & forensics

| Feature | Description |
|---|---|
| **SQLite event store** | Every signal persisted to `detector.db` (timestamp, detector, weight, score/level after). INFO signals go to the DB only, keeping the console quiet. |
| **Plain-language incident reports** | Each response action generates a **non-expert-readable Korean markdown report**: what program did what, an explanation of its command line, ATT&CK techniques, and a damage summary. Identical states are deduped within a 60 s window. |
| **Campaign (consolidated) reports** | Incidents arriving within **120 s of the last one are merged into a single attack campaign report** — a multi-PID attack no longer scatters into dozens of files. Finalized automatically once the scoring window drains. |
| **On-disk damage verification** | Report damage counts are verified **against the actual disk** (`verify_damage_on_disk`), not just inferred from signal metadata. A standalone tool, `scan_damage.py`, post-scans the watch tree by suspicious extensions/magic bytes — **no decoys required**. |
| **Postmortem tool** | `postmortem.py` reads only disk-persisted data (DB + reports + decoys) to compute the timeline, detect→respond latency, and decoy survival — **works even after a BSOD killed the agent**. |
| **Desktop notifications** | Toast on every termination, capped at 3 per 30 s. |

### Operations & enterprise

| Feature | Description |
|---|---|
| **Operator allowlist** | Register trusted third-party apps (Veeam, Acronis, 7-Zip, etc.) by process name or image-path prefix to prevent false-positive kills. High-confidence signals (canary, ransom-note spread) bypass the allowlist to prevent abuse. Editable from the dashboard. |
| **MITRE ATT&CK technique tagging** | Every signal maps to standard ATT&CK technique IDs (T1486, T1490, T1055, T1218, etc.). Appears in incident reports and the admin dashboard for SOC/IR integration. |
| **SIEM / Webhook integration** | HIGH+ events forwarded asynchronously via **CEF over syslog** (Splunk/QRadar/ArcSight/Sentinel) and a **generic JSON webhook** (Slack/Teams/PagerDuty/SOAR). Zero external dependencies; fail-open (an integration failure never stops detection). |
| **Dashboard authentication** | When a token is configured, mutating and admin endpoints (`/api/reset`, `/api/kill`, `/api/admin/*`) require `X-API-Key` or `Authorization: Bearer` (constant-time compare). The watchdog `/api/heartbeat` is always open; `auth_required_for_reads` extends protection to read APIs. |
| **Central config file** | `ransomguard.toml` / `.json` for deploying policy (watch paths, mode, integrations, auth) to fleets via GPO/Intune/Ansible. Secrets (token, webhook URL) are injected via environment variables which always win over the file. |

### Flask dashboard

`http://127.0.0.1:5000` — monitoring, response, and reporting in one page:

- **Status hero banner** showing the current threat level at a glance, with blocked/signal counters
- **Live score gauge + history sparkline** (synced to the 120 s window)
- **Event feed** with severity/detector filters, search, and pause
- **Incident report panel**: report list + **modal viewer (rendered markdown) + PDF export**
- **Response-action audit log**: trigger signal, SHA-256 + VirusTotal link, parent process, detect→respond latency
- **MITRE ATT&CK summary**, process table (filter, threat-PID highlighting), manual kill/release
- **Administrator panel**: health grid (driver, watch dirs, integration/auth status), mode switcher, per-PID threat breakdown with ATT&CK tags, allowlist editor
- Dark (SOC) / light theme toggle; operator token (X-API-Key) entry via the 🔑 header button

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
alarm ringing. Three gates apply before summation — **trusted-actor
exemption** (verified system components score zero for normal activity),
**correlation gating** (`file_delete` only counts alongside encryption
activity from the same PID), and **post-kill auto-recovery** (a terminated
PID's signals are purged from the window). See "Scoring & trust model" above.

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
| `--config <path>`               | Policy file (`ransomguard.toml` / `.json`) path. Omit to auto-detect in the working directory. **Precedence: CLI flag > config file > built-in default.** |
| `--watch <dir>`                 | Directory to monitor (repeatable). Default: `./test_watch_dir`.                        |
| `--mode {off,quarantine,kill}`  | Responder mode. Default `kill`.                                                        |
| `--auth-token <token>`          | Dashboard API token. **Prefer `RANSOMGUARD_AUTH_TOKEN` env var or config file** (keeps the token out of process listings). When set, mutating and admin endpoints require authentication. |
| `--allowlist <path>`            | Operator allowlist JSON file (default `allowlist.json`). Register trusted apps to reduce false positives. |
| `--no-minifilter`               | Skip the kernel bridge (user-mode-only detection).                                     |
| `--no-dashboard`                | Don't start the Flask UI.                                                              |
| `--port N`                      | Dashboard port (default `5000`).                                                       |
| `--db PATH`                     | SQLite path (default `detector.db`).                                                   |
| `--reports-dir PATH`            | Where to write markdown incident reports (default `./reports`).                        |
| `--no-notify`                   | Suppress desktop notifications when a process is killed.                               |
| `--no-tamper-protection`        | Disable `RtlSetProcessIsCritical` + DACL hardening (useful in dev so you can taskkill).|
| `--watchdog-pid <PID>`          | PID of the companion watchdog; will be kernel-tamper-protected alongside the agent.    |

> **Secret injection via environment variables:** `RANSOMGUARD_AUTH_TOKEN` (dashboard token),
> `RANSOMGUARD_WEBHOOK_URL` (enables webhook + sets URL), `RANSOMGUARD_SYSLOG_HOST` (enables
> syslog + sets host). Environment variables always override the config file.

### Config file example (`ransomguard.toml`)

```toml
[general]
watch_dirs = ["C:\\Users"]
responder_mode = "kill"          # off | quarantine | kill
enable_minifilter = true

[dashboard]
host = "127.0.0.1"
port = 5000
auth_token = ""                  # leave empty to disable auth — use env var in production
auth_required_for_reads = false  # true = read-only APIs also require the token

[syslog]                         # SIEM (CEF over syslog)
enabled = true
host = "siem.corp.local"
port = 514
protocol = "udp"                 # udp | tcp
min_severity = "HIGH"

[webhook]                        # Slack / Teams / PagerDuty / SOAR
enabled = true
url = "https://hooks.example.com/services/XXX"
min_severity = "CRITICAL"
```

> `.toml` requires Python 3.11+ (`tomllib`). On Python 3.10 use `ransomguard.json`
> with the same structure.

## Enterprise Deployment

Features added to bridge the gap between a research prototype and a production enterprise product.

**Implemented in this version:**

- **Central policy file** (`config.py`) — `ransomguard.toml` / `.json` deploys policy to hundreds of endpoints in one file. Secrets are resolved from environment variables first (no tokens stored on disk).
- **SIEM integration** (`integrations.py`) — CEF over syslog. Streams threat events to a central SIEM in the standard format every SOC already parses (Splunk, QRadar, ArcSight, Sentinel).
- **Alert / SOAR webhook** — instant JSON alerts to Slack/Teams/PagerDuty/SOAR. Async worker + fail-open so the detection hot-path is never blocked.
- **Dashboard authentication** — token-gates the unauthenticated admin API surface (disable responder, kill processes, edit allowlist). Watchdog `/api/heartbeat` stays open.
- **Audit / forensics** *(existing)* — SQLite event store, Markdown incident reports, responder action log, ATT&CK mapping.
- **High-availability / tamper-resistance** *(existing)* — watchdog service auto-restart, `RtlSetProcessIsCritical`, DACL hardening, kernel `ObCallback` handle protection.

**Roadmap — additional work needed for a full enterprise product:**

- **Fleet management console** — single pane for status, policy, and alerts across many agents. Currently each endpoint pushes via syslog/webhook.
- **RBAC + SSO** — multi-role dashboard (analyst / admin), SAML/OIDC. Currently single token.
- **Signed MSI packaging + auto-update channel** — winget/Intune packaging, staged rollout.
- **Remote policy push + drift detection** — centrally enforce policy changes.
- **Quarantine file vault + one-click recovery** — VSS/backup-integrated rollback.
- **Licensing / telemetry opt-in**, **per-tenant multi-tenancy**.

---

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
  editing, video transcoding, and archive updates. (If they actually get
  encrypted, *change*-based signals — magic-byte loss, extension rename —
  still catch it.)
- **Noise path/extension exclusion:** Browser caches, packaged-app caches,
  `\Temp\`, and churn extensions (`.tmp`/`.log`/`.etl`/…) that normal
  software writes constantly never count as encryption events.
- **Conservative ransom-note verdicts:** A name-only match is a MEDIUM hint;
  HIGH requires content confirmation (a strong indicator — crypto wallet or
  `.onion` address — is mandatory). CRITICAL requires spread across **3+
  directories within 60 s** with content confirmation or corroborating real
  encryption activity — two legitimate `readme.txt` files can no longer
  escalate to the top level.
- **Operator allowlist:** Whitelist backup/compression/sync software by
  process **name** or **image path prefix**. Path-based entries defeat
  name spoofing (`%TEMP%\veeamagent.exe` won't match a path entry).
  **However, high-confidence single-shot signals (canary, ransom note
  spread) bypass the allowlist to prevent abuse.**
- **Two-tier trust-based score exemption:** System processes with verified
  image paths (Defender, WMI, servicing) are excluded from scoring; svchost
  is exempt only for registry/housekeeping — its bulk file mutation is still
  scored, guarding against injected svchost-hosted ransomware.
- **Correlation gating:** Common benign behavior (a lone `file_delete`)
  contributes only when the same PID also shows real encryption activity.
- **Benign registry value filter:** Known-good writes observed in live runs
  (ctfmon's `internat.exe` Run-key refresh, Defender's own telemetry
  timestamps) are excluded per value name.
- **Uncorroborated HIGH = record only:** The responder does not act on a
  lone HIGH heuristic — it is logged as `observed only` and a kill happens
  only with a second detector or real encryption activity.

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

## Further reading

- Korean README: [`README.md`](./README.md)
- Developer wiki: [`docs/WIKI.en.md`](./docs/WIKI.en.md) / [`docs/WIKI.ko.md`](./docs/WIKI.ko.md)
- Capstone report (Korean): [`docs/CAPSTONE_REPORT.ko.md`](./docs/CAPSTONE_REPORT.ko.md)
- Design rationale — why each signal weight/threshold has its value (Korean): [`docs/DESIGN_RATIONALE.ko.md`](./docs/DESIGN_RATIONALE.ko.md)
