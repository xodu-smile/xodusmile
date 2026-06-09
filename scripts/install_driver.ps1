<#
.SYNOPSIS
    Install and start the RansomGuard minifilter driver.

.DESCRIPTION
    Copies the built .sys to %windir%\system32\drivers, installs the .inf
    via setupapi, and loads the filter (`fltmc load RansomGuard`).

    Requires:
      - Elevated PowerShell (Run as Administrator).
      - The driver already built by scripts\build_driver.ps1.
      - Test signing enabled on the target machine, *unless* the .sys
        carries an attestation-signed catalog.  Enable with:
            bcdedit /set testsigning on
            shutdown /r /t 0
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')]
    [string] $Configuration = 'Release',
    [ValidateSet('x64','ARM64')]
    [string] $Platform
)

. "$PSScriptRoot\_common.ps1"
Require-Admin

# Default to the host architecture so the path matches what
# build_driver.ps1 produced (e.g. build\ARM64\Release on an ARM64 host).
if (-not $Platform) {
    $Platform = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'ARM64' } else { 'x64' }
}

$repoRoot = Get-RepoRoot
$buildDir = Join-Path $repoRoot "minifilter\build\$Platform\$Configuration"
$sys      = Join-Path $buildDir 'RansomGuard.sys'
$inf      = Join-Path $buildDir 'RansomGuard.inf'

if (-not (Test-Path $sys) -or -not (Test-Path $inf)) {
    Write-Err2 "Built driver artifacts not found under $buildDir."
    Write-Host  "  Build first: .\scripts\build_driver.ps1"
    exit 1
}

Write-Step 'Checking test signing state'
$bcd = bcdedit /enum '{current}' 2>$null
if ($bcd -match 'testsigning\s+Yes') {
    Write-Ok 'testsigning is enabled'
} else {
    Write-Warn2 'testsigning appears to be OFF.'
    Write-Host  '  Unsigned drivers will fail to load.  Enable with:'
    Write-Host  '      bcdedit /set testsigning on'
    Write-Host  '      shutdown /r /t 0'
    Write-Host  '  (Continuing; the fltmc load below will fail clearly'
    Write-Host  '   if the driver cannot be loaded.)'
}

Write-Step 'Installing the .inf'
$rundll = "$env:windir\System32\rundll32.exe"
Invoke-CheckedExe $rundll @('setupapi.dll,InstallHinfSection', 'DefaultInstall', '132', $inf)
Write-Ok 'inf installed'

Write-Step 'Loading the minifilter (fltmc load)'
& fltmc.exe load RansomGuard | Out-Host
$loadExit = $LASTEXITCODE

# fltmc load returns nonzero if the filter is already loaded; rather than
# whitelist HRESULTs, treat "shows up in fltmc filters" as the source of truth.
Write-Step 'Filter status'
$loaded = & fltmc.exe filters | Select-String -Pattern 'RansomGuard'
if ($loaded) {
    $loaded | ForEach-Object { Write-Ok $_ }
} else {
    Write-Err2 "fltmc load failed (exit=$loadExit); RansomGuard is not listed in 'fltmc filters'."
    exit ($(if ($loadExit -ne 0) { $loadExit } else { 1 }))
}

Write-Host ''
Write-Host '  Driver is loaded.  Start the user-mode agent with:'
Write-Host '      .\.venv\Scripts\python.exe agent.py --watch C:\Users\you\Documents'
Write-Host ''
