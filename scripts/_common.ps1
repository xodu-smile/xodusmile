#
# _common.ps1
#
# Shared helpers for the RansomGuard build/install scripts.  Dot-source
# from any script in this directory:
#
#     . "$PSScriptRoot\_common.ps1"
#

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Require-Admin {
    if (-not (Test-Admin)) {
        throw "This script must be run from an elevated PowerShell window (Run as Administrator)."
    }
}

function Write-Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Write-Ok($msg)    { Write-Host "  + $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }
function Write-Err2($msg)  { Write-Host "  x $msg" -ForegroundColor Red }

function Get-RepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Test-Command($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function Invoke-CheckedExe {
    param(
        [Parameter(Mandatory)] [string] $Exe,
        [Parameter(ValueFromRemainingArguments=$true)] [string[]] $Args
    )
    & $Exe @Args
    if ($LASTEXITCODE -ne 0) {
        throw "$Exe exited with code $LASTEXITCODE"
    }
}

function Install-WithWinget {
    param(
        [Parameter(Mandatory)] [string] $Id,
        [string] $DisplayName = $Id
    )
    if (-not (Test-Command winget)) {
        throw "winget is unavailable; install $DisplayName manually and re-run."
    }
    Write-Step "Installing $DisplayName via winget"
    & winget install --id $Id --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "winget install of $Id failed with exit code $LASTEXITCODE"
    }
}

function Ensure-Python {
    if (Test-Command py)     { return 'py' }
    if (Test-Command python) { return 'python' }
    Write-Warn2 "Python not found on PATH; attempting winget install."
    Install-WithWinget -Id 'Python.Python.3.12' -DisplayName 'Python 3.12'
    if (Test-Command py)     { return 'py' }
    if (Test-Command python) { return 'python' }
    throw "Python install completed but neither py nor python is on PATH; open a new shell and retry."
}

function Find-VsWhere {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Find-MsBuild {
    $vswhere = Find-VsWhere
    if (-not $vswhere) {
        return $null
    }
    $path = & $vswhere -latest -prerelease -products * `
        -requires Microsoft.Component.MSBuild `
        -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    if ($path -and (Test-Path $path)) { return $path }
    return $null
}

function Test-WdkInstalled {
    # The WDK installs as a VS workload component; vswhere will report it.
    $vswhere = Find-VsWhere
    if (-not $vswhere) { return $false }
    $found = & $vswhere -latest -prerelease -products * `
        -requires Microsoft.VisualStudio.Component.Windows11SDK.22621 `
        -property installationPath 2>$null
    if (-not $found) {
        $found = & $vswhere -latest -prerelease -products * `
            -requires Microsoft.VisualStudio.ComponentGroup.WindowsDriverKit `
            -property installationPath 2>$null
    }
    return [bool]$found
}
