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

function Wait-ServiceStopped($svc, [int]$timeoutSec = 45) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $s = Get-Service $svc -ErrorAction SilentlyContinue
        if (-not $s)                  { return $true }
        if ($s.Status -eq 'Stopped')  { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Stop-And-Remove($svc, $script) {
    if (-not (Get-Service $svc -ErrorAction SilentlyContinue)) {
        Write-Ok "$svc not installed"
        return
    }
    Write-Step "Stopping $svc"
    # Ask the SCM to stop and WAIT until the service actually reaches
    # STOPPED.  The agent clears its RtlSetProcessIsCritical flag during a
    # clean stop; deleting the service or tearing the process down before
    # that completes would kill a still-critical process and bugcheck the
    # box (CRITICAL_PROCESS_DIED -> reboot).  Never force-kill here.
    & sc.exe stop $svc | Out-Null
    if (-not (Wait-ServiceStopped $svc 45)) {
        Write-Warn2 "$svc did not reach STOPPED within 45s; NOT removing it (removing a still-critical process can bugcheck the machine).  Investigate, then re-run."
        return
    }
    Write-Ok "$svc stopped cleanly"

    Write-Step "Removing $svc"
    if ((Test-Path $venvPy) -and (Test-Path $script)) {
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
