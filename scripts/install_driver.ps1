<#
.SYNOPSIS
    Install and start the RansomGuard minifilter driver.

.DESCRIPTION
    Copies the built .sys to %windir%\system32\drivers, installs the .inf
    via setupapi, and starts the filter (`sc start RansomGuard`).

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
    [string] $Platform = 'x64'
)

. "$PSScriptRoot\_common.ps1"
Require-Admin

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
    Write-Host  '  (Continuing; the SC start call below will fail clearly'
    Write-Host  '   if the driver cannot be loaded.)'
}

Write-Step 'Installing the .inf'
$rundll = "$env:windir\System32\rundll32.exe"
Invoke-CheckedExe $rundll @('setupapi.dll,InstallHinfSection', 'DefaultInstall', '132', $inf)
Write-Ok 'inf installed'

Write-Step 'Starting filter'
& sc.exe start RansomGuard | Out-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) {
    # 1056 = ERROR_SERVICE_ALREADY_RUNNING; harmless.
    Write-Err2 "sc start exited with code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Step 'Filter status'
& fltmc.exe filters | Select-String -Pattern 'RansomGuard' | ForEach-Object { Write-Ok $_ }

Write-Host ''
Write-Host '  Driver is loaded.  Start the user-mode agent with:'
Write-Host '      .\.venv\Scripts\python.exe agent.py --watch C:\Users\you\Documents'
Write-Host ''
