<#
.SYNOPSIS
Unload and uninstall the RmDetectorFlt minifilter.

Run from elevated PowerShell.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = [Security.Principal.WindowsPrincipal]::new($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell (admin)."
}

Write-Host "[uninstall] fltmc unload RmDetectorFlt"
fltmc unload RmDetectorFlt 2>&1 | Out-Host

$installInf = Join-Path (Split-Path -Parent $PSCommandPath) 'install\RmDetectorFlt.inf'
if (Test-Path $installInf) {
    Write-Host "[uninstall] running DefaultUninstall on $installInf"
    Start-Process -FilePath 'rundll32.exe' `
        -ArgumentList "SETUPAPI.DLL,InstallHinfSection DefaultUninstall 132 $installInf" `
        -Wait -Verb runAs
} else {
    Write-Host "[uninstall] no staged inf at $installInf; deleting service directly"
    sc.exe delete RmDetectorFlt
}

Write-Host "[uninstall] done"
