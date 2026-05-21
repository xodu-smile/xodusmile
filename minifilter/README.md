# RansomGuard Minifilter

A small Windows file-system minifilter that the user-mode EDR uses as its
primary file-I/O signal source. The driver hooks `IRP_MJ_CREATE`,
`IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION`; forwards each event over a
filter communication port; and can block writes/renames for any PID that
user mode has marked as quarantined.

## Files

| File              | Purpose                                                  |
|-------------------|----------------------------------------------------------|
| `RansomGuard.c`   | Minifilter implementation                                |
| `RansomGuard.h`   | Shared message layout (kernel + user mode)               |
| `RansomGuard.inf` | Driver install file (registers as ActivityMonitor class) |
| `RansomGuard.vcxproj` / `.sln` | MSBuild project for the WDK                |

## Build

```powershell
# from the repo root
.\scripts\build_driver.ps1
```

The script locates `msbuild.exe` via `vswhere`, verifies the WDK is
installed, and produces `minifilter\build\x64\Release\RansomGuard.sys`
(plus `.inf` and `.cat`).

## Install

```powershell
.\scripts\install_driver.ps1
```

Requires test signing to be enabled (`bcdedit /set testsigning on`, then
reboot) unless the `.sys` carries an attestation-signed catalog. The
script copies the driver to `%windir%\system32\drivers`, installs the
`.inf`, and starts the filter (`sc start RansomGuard`).

To uninstall:

```powershell
.\scripts\uninstall_driver.ps1
```

## Protocol

User mode talks to the driver over `\RansomGuardPort` using
`FilterConnectCommunicationPort`.

* **Events (kernel → user):** `RG_EVENT` records describing
  create/write/setinfo/blocked operations. `Path` is the normalized DOS
  path, capped at 520 WCHARs.
* **Commands (user → kernel):** `RG_COMMAND` with `Kind = Quarantine /
  Release / Ping` and a target PID. Replies are `RG_REPLY` with an
  `NTSTATUS`.

The exact structures live in `RansomGuard.h` and are mirrored in
`detectors/minifilter_bridge.py` via `ctypes`.
