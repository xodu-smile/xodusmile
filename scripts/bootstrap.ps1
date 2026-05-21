<#
.SYNOPSIS
    Install every dependency the RansomGuard EDR needs and prepare a venv.

.DESCRIPTION
    This script is the single entry point for a fresh Windows 11 machine:

      - ensures Python 3.10+ is on PATH (installs via winget if missing)
      - creates .venv in the repo root
      - installs requirements.txt + runs pywin32_postinstall
      - optionally builds and installs the kernel minifilter driver
        (skipped by default; pass -BuildDriver or -InstallDriver to opt in)

    The driver path requires the Windows Driver Kit and an elevated shell.
    The user-mode agent works without it (you just lose the kernel-level
    file I/O signal source).

.EXAMPLE
    .\scripts\bootstrap.ps1
        Install Python, set up venv, install Python dependencies only.

.EXAMPLE
    .\scripts\bootstrap.ps1 -BuildDriver -InstallDriver
        Also build and install the minifilter (requires admin + WDK).
#>

[CmdletBinding()]
param(
    [switch] $BuildDriver,
    [switch] $InstallDriver,
    [switch] $SkipPython
)

. "$PSScriptRoot\_common.ps1"

$repoRoot = Get-RepoRoot
Push-Location $repoRoot
try {
    if (-not $SkipPython) {
        Write-Step 'Ensuring Python is installed'
        $py = Ensure-Python
        Write-Ok "Using $py"

        Write-Step 'Creating virtual environment (.venv)'
        if (-not (Test-Path '.venv')) {
            & $py -m venv .venv
            if ($LASTEXITCODE -ne 0) { throw 'venv creation failed' }
            Write-Ok '.venv created'
        } else {
            Write-Ok '.venv already exists'
        }

        $venvPy = Join-Path $repoRoot '.venv\Scripts\python.exe'
        if (-not (Test-Path $venvPy)) {
            throw "Expected $venvPy after venv creation."
        }

        Write-Step 'Upgrading pip + installing requirements'
        & $venvPy -m pip install --upgrade pip
        if ($LASTEXITCODE -ne 0) { throw 'pip upgrade failed' }
        & $venvPy -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) { throw 'pip install -r requirements.txt failed' }

        Write-Step 'Running pywin32 post-install'
        $postInstall = Join-Path $repoRoot '.venv\Scripts\pywin32_postinstall.py'
        if (Test-Path $postInstall) {
            & $venvPy $postInstall -install
            if ($LASTEXITCODE -ne 0) {
                Write-Warn2 "pywin32_postinstall exited $LASTEXITCODE; continuing"
            } else {
                Write-Ok 'pywin32 post-install complete'
            }
        } else {
            Write-Warn2 'pywin32_postinstall.py not present; skipping'
        }
    }

    if ($BuildDriver -or $InstallDriver) {
        Write-Step 'Building kernel minifilter driver'
        & "$PSScriptRoot\build_driver.ps1"
        if ($LASTEXITCODE -ne 0) { throw 'driver build failed' }
    }

    if ($InstallDriver) {
        Write-Step 'Installing kernel minifilter driver'
        & "$PSScriptRoot\install_driver.ps1"
        if ($LASTEXITCODE -ne 0) { throw 'driver install failed' }
    }

    Write-Step 'Bootstrap complete'
    Write-Host ''
    Write-Host '  Activate the venv with:'
    Write-Host '      .\.venv\Scripts\Activate.ps1'
    Write-Host '  Run the agent with:'
    Write-Host '      python agent.py --watch C:\path\to\watch_dir'
    Write-Host ''
}
finally {
    Pop-Location
}
