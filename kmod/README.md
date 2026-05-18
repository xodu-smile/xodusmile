# RmDetectorFlt — Ransomware Detection Minifilter (EDR alternative)

A Windows file-system minifilter that gives the user-mode Python agent
the sensor set you'd get from a commercial EDR's file/process telemetry:

1. **Ground-truth PID + parent PID** for every file open / write /
   rename / delete, plus full process tree from
   `PsSetCreateProcessNotifyRoutineEx` (image path + command line).
2. **Image load callbacks** (`PsSetLoadImageNotifyRoutine`) — Sysmon
   EID 7 equivalent: every DLL/EXE mapped into a process is reported
   with its full image path.
3. **Pre-callback blocking.** Canary writes/renames/deletes are denied
   at the kernel boundary. Renames into ransomware-style extensions
   (`.locked`, `.crypt`, ...) are denied without a user-mode roundtrip.
   A quarantined PID's writes are dropped immediately.
4. **In-kernel entropy guard.** First 256 bytes of every watched write
   are sampled and scored (distinct-byte heuristic ≈ Shannon, no FP).
   High-entropy writes accumulate against the originating PID.
5. **In-kernel scoring + auto-terminate.** The driver keeps a per-PID
   rolling score (entropy hits + new-extension touches + susp-ext
   rename attempts + canary blocks + cumulative write burst). When the
   score crosses `ScoreCritical` the driver queues a work item that
   calls `ZwOpenProcess` + `ZwTerminateProcess` itself — no dependence
   on user-mode being responsive.

The driver is still a PoC: it loads under **test-signing only**, and
does not have a Microsoft-issued altitude. Do not deploy it to a
machine you care about.

## Layout

```
kmod/
├── RmDetectorFlt/
│   ├── RmDetectorFlt.c        ← driver source
│   ├── RmDetectorFlt.h        ← shared kernel ↔ user contract
│   ├── RmDetectorFlt.inf      ← install script
│   ├── RmDetectorFlt.rc       ← version resource
│   ├── RmDetectorFlt.vcxproj  ← MSBuild project (VS 2022 + WDK)
│   └── resource.h
├── build.ps1                  ← build, test-sign, stage
├── install.ps1                ← install service, load filter
└── uninstall.ps1              ← unload, delete service
```

User-mode side: `../detectors/minifilter.py` connects to the comm port,
mirrors the `RM_EVENT` / `RM_COMMAND` structs via ctypes, surfaces every
kernel event as a `Signal`, and exposes `block_pid`, `terminate_pid`,
`set_suspicious_extensions`, `set_thresholds`.

## Prerequisites (one time, on the Windows 11 machine)

1. **Visual Studio 2022** — Community edition is fine.
   Workloads: *Desktop development with C++* + *Windows Driver Kit*.
2. **Windows Driver Kit (WDK)** matching the SDK installed by VS.
   <https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk>
3. Open an **elevated** PowerShell (Run as administrator).

## Build

Run from an **elevated** PowerShell (admin) — the script writes the
self-signed cert into `LocalMachine\Root` and `LocalMachine\TrustedPublisher`,
both of which require admin.

```powershell
cd C:\path\to\ransomware_detector\kmod
.\build.ps1                     # Debug | x64 by default
# or
.\build.ps1 -Configuration Release
```

What this does:

1. Locates `MSBuild` via `vswhere` (VS 2022 with WDK workload required).
2. Compiles `RmDetectorFlt\RmDetectorFlt.vcxproj` (`/p:Configuration=Debug
   /p:Platform=x64`). Artifacts land in `kmod\x64\<Configuration>\`
   (`RmDetectorFlt.sys`, `.inf`, `.pdb`).
3. Generates a self-signed cert `CN=RmDetectorFltTestCert` if missing,
   imports it into `LocalMachine\Root` and `LocalMachine\TrustedPublisher`
   so the OS will load a binary signed with it under test-signing.
4. Signs `RmDetectorFlt.sys` with that cert + a timestamp from
   `timestamp.digicert.com`.
5. Runs `inf2cat /driver:<outdir> /os:10_x64` → `RmDetectorFlt.cat`, signs
   that too.
6. Copies `sys + inf + cat + pdb` into `kmod\install\`.

Re-running the script is idempotent: pass `-SkipBuild` to re-sign existing
artifacts without invoking MSBuild.

Verify:

```powershell
Get-ChildItem .\install\
# RmDetectorFlt.sys / .inf / .cat / .pdb
Get-AuthenticodeSignature .\install\RmDetectorFlt.sys
# Status: Valid    SignerCertificate: CN=RmDetectorFltTestCert
```

## Install

```powershell
.\install.ps1
```

The first run will detect that **test-signing is off**, flip it via
`bcdedit /set testsigning on`, and ask you to reboot.

After reboot, run `.\install.ps1` again. It will:

1. `rundll32 SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 …\install\RmDetectorFlt.inf`
   — creates the `RmDetectorFlt` kernel service.
2. `fltmc load RmDetectorFlt` — actually loads the driver.
3. `fltmc instances -f RmDetectorFlt` — shows it attached to your
   NTFS / ReFS volumes.

## Default policy on load

`DriverEntry` enables the full EDR sensor set out of the box:

```
RM_POLICY_BLOCK_CANARY      ← canary writes/rename/delete -> ACCESS_DENIED
RM_POLICY_EMIT_CREATES      ← create events upcalled
RM_POLICY_EMIT_CLEANUPS     ← per-handle write summary upcalled
RM_POLICY_TRACK_PROCESSES   ← process start/exit upcalled
RM_POLICY_ENTROPY_GUARD     ← entropy sampling on watched writes
RM_POLICY_BLOCK_SUSP_EXT    ← rename guard active
RM_POLICY_AUTO_TERMINATE    ← ZwTerminateProcess on score breach
```

`RM_POLICY_EMIT_IMAGE_LOADS` is **off** by default (a busy box produces
hundreds of image loads per second). User-mode flips it on via
`RmCmdSetPolicy` when the dashboard subscribes.

Default thresholds (override via `RmCmdSetThresholds`):

| Knob | Default | Meaning |
|---|---|---|
| `ScoreCritical` | 100 | per-PID kernel score that triggers auto-terminate |
| `EntropyThreshold` | 750 (≈ 7.50/8) | distinct-byte heuristic above this counts as high-entropy |
| `DistinctExtAlert` | 6 | distinct extensions touched by a PID |
| `WriteBurstBytes` | 50 MB | cumulative bytes by a PID across watch roots |

In-kernel score deltas:

| Trigger | Delta |
|---|---|
| Canary write / rename / delete blocked | +60 |
| Rename into suspicious extension | +30 |
| Write-burst threshold crossed | +15 |
| High-entropy write | +5 each |
| First time PID writes a new extension | +3 each |

## Run the agent

```powershell
cd ..
python agent.py --watch C:\Users\<you>\test_watch_dir
```

The agent prints one of:

```
[agent] RmDetectorFlt ACTIVE — EDR mode (process tree + image load +
        entropy guard + susp-ext rename guard + auto-terminate)
```
or, if the driver isn't loaded:
```
[agent] RmDetectorFlt inactive (driver not loaded) — user-mode watchers
        only (no in-kernel kill)
```

Smoke tests in active mode:

```powershell
# Canary direct touch
echo "wipe" > C:\Users\<you>\test_watch_dir\0_important_notes.xlsx
# → STATUS_ACCESS_DENIED + minifilter/canary_blocked CRITICAL

# Suspicious-extension rename
ren test.docx test.docx.locked
# → STATUS_ACCESS_DENIED + minifilter/blocked_susp_ext CRITICAL

# Mass encryption simulation
python tests\simulator.py --scenario encrypt
# → entropy_spike accumulation -> kernel_score_critical -> auto_terminated
```

## Uninstall

```powershell
.\uninstall.ps1
```

To also disable test-signing once you're done:

```powershell
bcdedit /set testsigning off
# reboot
```

## Troubleshooting

- **`build.ps1` says `Build artifact missing: ...\x64\Debug\RmDetectorFlt.sys`**
  → MSBuild succeeded but emitted to a different folder. The vcxproj pins
  `OutDir` to `$(MSBuildThisFileDirectory)..\x64\$(Configuration)\` so this
  should not happen — confirm you're on a clean checkout and the `.user`
  property sheet isn't overriding `OutDir`.
- **`signtool` complains the timestamp server is unreachable** → re-run
  with the workstation online. The build script always timestamps; if you
  intentionally want to skip, pass `-SkipBuild` and re-sign manually.
- **`fltmc load` returns 0x80070002** → `.sys` not in `system32\drivers`.
  Re-run `install.ps1`; `InstallHinfSection` copies it there.
- **`fltmc load` returns 0x800705B4** → catalog signature not trusted.
  The build script must have copied the cert into `LocalMachine\Root`;
  check `Get-ChildItem Cert:\LocalMachine\Root | ? Subject -match RmDetectorFlt`.
- **Driver loads but `fltmc instances` is empty** → altitude collision.
  Look at `HKLM\System\CurrentControlSet\Control\FltMgr\Altitudes` and
  change the `Altitude` string in `RmDetectorFlt.inf`.
- **Driver loads but no process telemetry** → check the System log for
  `PsSetCreateProcessNotifyRoutineEx` failures. Some HVCI configurations
  or third-party AVs claim the slot table; the driver continues without
  process events in that case.
- **`auto_terminated` never fires** → the per-PID score reset on the
  process exit notify, or `RM_POLICY_AUTO_TERMINATE` was cleared.
  `RmCmdResetPidStats` from user-mode clears all rolling counters.
- **BSOD on load** → `!analyze -v` in WinDbg. The driver is a PoC; expect
  to iterate. Common offender is path normalization at high IRQL.
- **Event Viewer → System log** — FltMgr logs every load/unload with
  detailed status codes (source `FltMgr`).

## Internals quick map

| Where | What |
|---|---|
| `DriverEntry` | `FltRegisterFilter` + `PsSetCreateProcessNotifyRoutineEx` + `PsSetLoadImageNotifyRoutine` + `\RmDetectorPort` + `FltStartFiltering`. Defaults policy to the full EDR sensor set. |
| `RmProcessNotifyEx` | Process create / exit. Allocates / frees the per-PID stats slot, records parent PID + system-process heuristic, emits `RmEventProcessStart` / `RmEventProcessExit`. |
| `RmImageNotify` | DLL/EXE image load — emits `RmEventImageLoad` when `RM_POLICY_EMIT_IMAGE_LOADS` is on. |
| `RmPostCreate` | Resolve normalized path, classify watched / canary, attach `RM_STREAM_HANDLE_CTX`. |
| `RmPreWrite` | Canary block → ACCESS_DENIED. Blocked-PID block → ACCESS_DENIED. Otherwise sample entropy, update per-PID stats (write count, distinct-ext bitmap, byte total, entropy hits), apply score delta, maybe trigger auto-terminate. |
| `RmPreSetInformation` | Canary rename/delete → deny. Rename whose new name ends in a suspicious extension → deny + `RmEventBlockedSuspExt` + score +30. |
| `RmPostCleanup` | Emit per-handle write summary, free StreamHandle context. |
| `RmPortMessage` | User-mode commands: set watch / canary / susp-ext paths, block / unblock / terminate PID, set policy, set thresholds, reset PID stats. |
| `RmPidApplyScore` | Per-PID score accumulator. On crossing `ScoreCritical` emits `RmEventScoreCritical` and (if policy allows) queues a `DelayedWorkQueue` work item that runs `RmTerminateWorker` → `ZwOpenProcess(PROCESS_TERMINATE)` + `ZwTerminateProcess(STATUS_UNSUCCESSFUL)`. |
| `RmSampleEntropyX100` | 256-byte sample, distinct-byte count → entropy x100 (0..800). No floats. |

Altitude **385201** is in the `FSFilter Activity Monitor` range
(370000–389998). For a shipping product ask Microsoft for a real one.

## What this still isn't

This driver intentionally stops short of a few things real EDRs include
and the user-mode agent papers over them where it can:

- **No registry / network filter.** File + process sensors only.
- **No pre-write rollback** (copy-on-write of the original bytes before
  letting a write through). Auto-terminate is the only undo today.
- **No object-callback self-protection** (`ObRegisterCallbacks`) so a
  motivated attacker can `OpenProcess(PROCESS_TERMINATE)` the user-mode
  agent. The kernel-side termination path doesn't care, but the agent
  losing the comm port means new PIDs stop being scored in user-mode.
- **No WHCP signature.** Test-signing only.
- **No intermittent-encryption stream context** (per-file pattern of
  high-entropy chunks interleaved with original bytes).

Roadmap notes are in the top-level `README.md`.
