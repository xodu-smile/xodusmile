<#
.SYNOPSIS
    Stop and uninstall the RansomGuard minifilter driver.
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

# Default to the host architecture so the .inf path matches the build.
if (-not $Platform) {
    $Platform = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'ARM64' } else { 'x64' }
}

$repoRoot = Get-RepoRoot
$inf = Join-Path $repoRoot "minifilter\build\$Platform\$Configuration\RansomGuard.inf"

Write-Step 'Stopping the filter (if running)'
& sc.exe stop RansomGuard | Out-Host

Write-Step 'Uninstalling .inf'
if (Test-Path $inf) {
    $rundll = "$env:windir\System32\rundll32.exe"
    & $rundll @('setupapi.dll,InstallHinfSection', 'DefaultUninstall', '132', $inf)
    Write-Ok 'inf uninstalled'
} else {
    Write-Warn2 "Built .inf not present at $inf; deleting service via sc.exe instead"
    & sc.exe delete RansomGuard | Out-Host
}

Write-Step 'Removing .sys from drivers store'
$sysPath = Join-Path $env:windir 'System32\drivers\RansomGuard.sys'
if (Test-Path $sysPath) {
    Remove-Item -Force $sysPath
    Write-Ok "deleted $sysPath"
}

Write-Ok 'Uninstall complete'
