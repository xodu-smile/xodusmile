<#
.SYNOPSIS
Install (or refresh) the RmDetectorFlt minifilter on the local machine.

.DESCRIPTION
Run from an elevated PowerShell after build.ps1 has staged install\.

Steps:
  1. Verify testsigning is on. If not, enable it via bcdedit and warn
     that a reboot is required. (Test-signed driver loads fail until
     testsigning + reboot is done.)
  2. Run InstallHinfSection on RmDetectorFlt.inf to create the service.
  3. Start the filter via `fltmc load RmDetectorFlt`.
  4. Show `fltmc instances` so the operator can confirm it attached.

.PARAMETER NoStart
Install but don't load (useful when running pre-reboot).
#>

[CmdletBinding()]
param(
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'

$root       = Split-Path -Parent $PSCommandPath
$installDir = Join-Path $root 'install'
$inf        = Join-Path $installDir 'RmDetectorFlt.inf'

if (-not (Test-Path $inf)) {
    throw "Run build.ps1 first; missing $inf"
}

# --- check elevation ---
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]::new($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell (admin)."
}

# --- check testsigning ---
$bcd = (bcdedit /enum '{current}') -join "`n"
if ($bcd -notmatch 'testsigning\s+Yes') {
    Write-Host "[install] enabling Test Signing (bcdedit /set testsigning on)" -ForegroundColor Yellow
    bcdedit /set testsigning on | Out-Null
    Write-Warning "REBOOT required for testsigning to take effect, then re-run install.ps1."
    return
}

# --- install via InstallHinfSection ---
Write-Host "[install] running InstallHinfSection on $inf"
$rundllArgs = "SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 $inf"
Start-Process -FilePath 'rundll32.exe' -ArgumentList $rundllArgs -Wait -Verb runAs

# --- load filter ---
if (-not $NoStart) {
    Write-Host "[install] loading filter"
    fltmc load RmDetectorFlt
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "fltmc load returned $LASTEXITCODE - check Event Viewer (System log, source FltMgr)."
        return
    }
}

Write-Host ""
Write-Host "[install] done" -ForegroundColor Green
fltmc instances -f RmDetectorFlt
