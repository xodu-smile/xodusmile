<#
.SYNOPSIS
    Stop and remove the RansomGuard agent + watchdog services.

.DESCRIPTION
    Stops the watchdog first (so it won't fight us by restarting the
    agent), then the agent.  Removes both services from the SCM.  Does
    NOT delete C:\ProgramData\RansomGuard so forensic data is retained
    — delete that path manually if you really want a clean slate.
#>

[CmdletBinding()]
param()

. "$PSScriptRoot\_common.ps1"
Require-Admin

$repoRoot = Get-RepoRoot
$venvPy   = Join-Path $repoRoot '.venv\Scripts\python.exe'

function Stop-And-Remove($svc, $script) {
    if (-not (Get-Service $svc -ErrorAction SilentlyContinue)) {
        Write-Ok "$svc not installed"
        return
    }
    Write-Step "Stopping $svc"
    & sc.exe stop $svc | Out-Null
    Start-Sleep -Seconds 2
    Write-Step "Removing $svc"
    if (Test-Path $venvPy -and Test-Path $script) {
        & $venvPy $script remove
    } else {
        & sc.exe delete $svc | Out-Null
    }
    Write-Ok "$svc removed"
}

Stop-And-Remove 'RansomGuardWatchdog' (Join-Path $repoRoot 'watchdog_service.py')
Stop-And-Remove 'RansomGuardAgent'    (Join-Path $repoRoot 'service.py')

Write-Host ''
Write-Host '  Services removed.  Data dir C:\ProgramData\RansomGuard left in place.'
Write-Host '  To also remove the kernel driver:  .\scripts\uninstall_driver.ps1'
