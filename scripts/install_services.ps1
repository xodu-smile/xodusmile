<#
.SYNOPSIS
    Install, configure, and start the RansomGuard agent + watchdog services.

.DESCRIPTION
    Installs two Windows services:

      - RansomGuardAgent     hosts the EDR agent under LocalSystem
      - RansomGuardWatchdog  monitors and restarts the agent

    Both are configured with SCM recovery (restart-on-failure after 5s
    every time, no reset window).  A restrictive service SDDL is
    applied so non-administrators cannot query, start, stop, or change
    the configuration of either service.

    Service parameters (watch dirs, db path, etc.) are written under
    HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters so the
    service binary reads them without needing CLI args.

    Requires:
      - Elevated PowerShell.
      - bootstrap.ps1 (or install.ps1) already ran so .venv is populated.
      - The driver (RansomGuard.sys) loaded; see install_driver.ps1.

.PARAMETER WatchDirs
    Semicolon-separated list of directories the agent should watch.
    Default: %USERPROFILE% of every loaded user profile.

.PARAMETER Mode
    Responder mode: off | quarantine | kill (default kill).

.PARAMETER DashboardPort
    Local dashboard port (default 5000).

.PARAMETER NoHeartbeat
    Disable the watchdog's HTTP heartbeat check (it'll still restart
    the agent if the SCM reports it stopped).
#>

[CmdletBinding()]
param(
    [string]   $WatchDirs       = 'C:\Users',
    [ValidateSet('off','quarantine','kill')]
    [string]   $Mode            = 'kill',
    [int]      $DashboardPort   = 5000,
    [switch]   $NoHeartbeat
)

. "$PSScriptRoot\_common.ps1"
Require-Admin

$repoRoot = Get-RepoRoot
$venvPy   = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    Write-Err2 ".venv not found at $venvPy.  Run scripts\bootstrap.ps1 first."
    exit 1
}

$agentScript    = Join-Path $repoRoot 'service.py'
$watchdogScript = Join-Path $repoRoot 'watchdog_service.py'
foreach ($s in @($agentScript, $watchdogScript)) {
    if (-not (Test-Path $s)) { throw "Missing service script: $s" }
}

# --------------------------------------------------------------------------
# 1) Install the two services via the pywin32 ServiceFramework install path.
# --------------------------------------------------------------------------

Write-Step 'Installing RansomGuardAgent service'
& $venvPy $agentScript --startup auto install
if ($LASTEXITCODE -ne 0) { throw "agent service install failed ($LASTEXITCODE)" }

Write-Step 'Installing RansomGuardWatchdog service'
& $venvPy $watchdogScript --startup auto install
if ($LASTEXITCODE -ne 0) { throw "watchdog service install failed ($LASTEXITCODE)" }

# --------------------------------------------------------------------------
# 2) Write configuration to each service's Parameters subkey.
# --------------------------------------------------------------------------

Write-Step 'Writing service parameters'

$dataDir    = 'C:\ProgramData\RansomGuard'
$reportsDir = Join-Path $dataDir 'reports'
$dbPath     = Join-Path $dataDir 'detector.db'

New-Item -ItemType Directory -Force -Path $dataDir, $reportsDir | Out-Null

$agentParams = "HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardAgent\Parameters"
New-Item -Path $agentParams -Force | Out-Null
Set-ItemProperty -Path $agentParams -Name 'WatchDirs'   -Value $WatchDirs       -Type String
Set-ItemProperty -Path $agentParams -Name 'DbPath'      -Value $dbPath          -Type String
Set-ItemProperty -Path $agentParams -Name 'ReportsDir'  -Value $reportsDir      -Type String
Set-ItemProperty -Path $agentParams -Name 'Mode'        -Value $Mode            -Type String
Set-ItemProperty -Path $agentParams -Name 'Dashboard'   -Value 1                -Type DWord
Set-ItemProperty -Path $agentParams -Name 'Port'        -Value $DashboardPort   -Type DWord
Set-ItemProperty -Path $agentParams -Name 'WatchdogPid' -Value 0                -Type DWord
Write-Ok "configured $agentParams"

$wdParams = "HKLM:\SYSTEM\CurrentControlSet\Services\RansomGuardWatchdog\Parameters"
New-Item -Path $wdParams -Force | Out-Null
Set-ItemProperty -Path $wdParams -Name 'DashboardPort'  -Value $DashboardPort -Type DWord
Set-ItemProperty -Path $wdParams -Name 'HeartbeatCheck' -Value ([int](-not $NoHeartbeat)) -Type DWord
Write-Ok "configured $wdParams"

# --------------------------------------------------------------------------
# 3) Configure recovery: restart-on-every-failure after 5s, no reset window.
# --------------------------------------------------------------------------

Write-Step 'Configuring SCM recovery options'
foreach ($svc in @('RansomGuardAgent','RansomGuardWatchdog')) {
    & sc.exe failure $svc reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warn2 "sc failure on $svc returned $LASTEXITCODE" }
    & sc.exe failureflag $svc 1 | Out-Null  # treat unclean exits as failures
    Write-Ok "$svc recovery: restart x3 @ 5s"
}

# --------------------------------------------------------------------------
# 4) Restrict service ACL — only SYSTEM + Administrators may control.
#    SDDL: D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)
#    Granting: all the SERVICE_* access bits SCM uses, to SYSTEM and
#    BUILTIN\Administrators only.  No INTERACTIVE / Authenticated Users.
# --------------------------------------------------------------------------

Write-Step 'Locking service ACLs (SYSTEM + Administrators only)'
$svcSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)'
foreach ($svc in @('RansomGuardAgent','RansomGuardWatchdog')) {
    & sc.exe sdset $svc $svcSddl | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warn2 "sc sdset on $svc returned $LASTEXITCODE" }
    Write-Ok "$svc ACL locked"
}

# --------------------------------------------------------------------------
# 5) Restrict data directory — only SYSTEM + Admins may read or modify.
# --------------------------------------------------------------------------

Write-Step "Locking down $dataDir"
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetSecurityDescriptorSddlForm('D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
Set-Acl -Path $dataDir -AclObject $acl
Write-Ok "$dataDir locked"

# --------------------------------------------------------------------------
# 6) Start the services.  Start watchdog first so it observes the agent
#    coming up; restart of the agent is a no-op if it's already running.
# --------------------------------------------------------------------------

Write-Step 'Starting services'
& sc.exe start RansomGuardWatchdog | Out-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) {
    Write-Warn2 "sc start RansomGuardWatchdog returned $LASTEXITCODE"
}
& sc.exe start RansomGuardAgent | Out-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) {
    Write-Err2 "sc start RansomGuardAgent returned $LASTEXITCODE"
    exit 1
}

Write-Step 'Status'
Get-Service RansomGuardAgent, RansomGuardWatchdog | Format-Table -AutoSize

Write-Host ''
Write-Host '  Services are running.  Dashboard: http://127.0.0.1:' -NoNewline
Write-Host $DashboardPort
Write-Host '  Manage with:  sc.exe start|stop|query RansomGuardAgent'
Write-Host '  Uninstall:    .\scripts\uninstall_services.ps1'
Write-Host ''
