<#
.SYNOPSIS
Build, test-sign, and stage the RmDetectorFlt minifilter for install.

.DESCRIPTION
Requires VS 2022 with the "Windows Driver Kit (WDK)" workload + WDK
matching the installed SDK. Run from an elevated PowerShell.

The script:
  1. Locates MSBuild + WDK signing tools (signtool, inf2cat).
  2. Builds Debug|x64.
  3. Ensures a local self-signed test cert exists (CN=RmDetectorFltTestCert)
     in Cert:\LocalMachine\My and copies it into Root + TrustedPublisher
     so the test-signed binary is trusted at load time.
  4. Signs RmDetectorFlt.sys.
  5. Runs inf2cat to produce RmDetectorFlt.cat and signs it.
  6. Copies the four install artifacts (sys, inf, cat, +pdb) into .\install\.

After this, run install.ps1 (also in this folder) to enable test-signing
and load the driver. Reboot once after enabling testsigning.

.PARAMETER Configuration
Debug (default) or Release.

.PARAMETER SkipBuild
Skip MSBuild step; sign existing artifacts only.
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root        = Split-Path -Parent $PSCommandPath
$projectDir  = Join-Path $root 'RmDetectorFlt'
$vcxproj     = Join-Path $projectDir 'RmDetectorFlt.vcxproj'
$outDir      = Join-Path $root "x64\$Configuration"
$installDir  = Join-Path $root 'install'
$certSubject = 'CN=RmDetectorFltTestCert'

if (-not (Test-Path $vcxproj)) {
    throw "vcxproj not found at $vcxproj"
}

function Find-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe not found. Install Visual Studio 2022 with the WDK workload."
    }
    $msbuild = & $vswhere -latest -prerelease -products '*' `
        -requires Microsoft.Component.MSBuild `
        -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
    if (-not $msbuild) {
        throw "MSBuild not found via vswhere."
    }
    return $msbuild
}

function Find-WDKTool {
    param([string]$Name)
    # Search common WDK kits paths.
    $kitsRoot = Get-ItemPropertyValue `
        'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' `
        -Name 'KitsRoot10' -ErrorAction SilentlyContinue
    if (-not $kitsRoot) {
        throw "Win10/11 SDK not registered (Windows Kits\Installed Roots missing)."
    }
    $candidates = Get-ChildItem -Path "$kitsRoot\bin" -Directory `
        | Where-Object { $_.Name -match '^10\.' } `
        | Sort-Object Name -Descending
    foreach ($d in $candidates) {
        $p = Join-Path $d.FullName "x64\$Name"
        if (Test-Path $p) { return $p }
    }
    throw "$Name not found under $kitsRoot\bin\10.*\x64."
}

function Ensure-TestCert {
    $existing = Get-ChildItem Cert:\LocalMachine\My `
        | Where-Object { $_.Subject -eq $certSubject } `
        | Select-Object -First 1
    if (-not $existing) {
        Write-Host "[build] generating self-signed test cert: $certSubject"
        $existing = New-SelfSignedCertificate `
            -Subject $certSubject `
            -Type CodeSigningCert `
            -KeyUsage DigitalSignature `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -NotAfter (Get-Date).AddYears(3) `
            -KeyExportPolicy Exportable
    }
    foreach ($store in 'Root', 'TrustedPublisher') {
        $present = Get-ChildItem "Cert:\LocalMachine\$store" `
            | Where-Object { $_.Thumbprint -eq $existing.Thumbprint }
        if (-not $present) {
            Write-Host "[build] copying cert into LocalMachine\$store"
            $tmp = [IO.Path]::GetTempFileName() + '.cer'
            Export-Certificate -Cert $existing -FilePath $tmp | Out-Null
            Import-Certificate -FilePath $tmp `
                -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
    }
    return $existing.Thumbprint
}

# ---------- build ----------
if (-not $SkipBuild) {
    $msbuild = Find-MSBuild
    Write-Host "[build] msbuild: $msbuild"
    & $msbuild $vcxproj `
        "/p:Configuration=$Configuration" `
        '/p:Platform=x64' `
        '/p:SignMode=Off' `
        '/m' `
        '/nologo'
    if ($LASTEXITCODE -ne 0) { throw "msbuild failed ($LASTEXITCODE)" }
}

$sys = Join-Path $outDir 'RmDetectorFlt.sys'
$inf = Join-Path $outDir 'RmDetectorFlt.inf'
if (-not (Test-Path $sys)) { throw "Build artifact missing: $sys" }
if (-not (Test-Path $inf)) {
    # Some WDK versions don't auto-copy the .inf; pull from source tree.
    Copy-Item (Join-Path $projectDir 'RmDetectorFlt.inf') $outDir -Force
}

# ---------- sign + cat ----------
$thumb    = Ensure-TestCert
$signtool = Find-WDKTool 'signtool.exe'
$inf2cat  = Find-WDKTool 'inf2cat.exe'

Write-Host "[build] signing $sys"
& $signtool sign /fd SHA256 /a `
    /s 'My' /sha1 $thumb `
    /tr 'http://timestamp.digicert.com' /td SHA256 `
    $sys
if ($LASTEXITCODE -ne 0) { throw "signtool sys failed ($LASTEXITCODE)" }

Write-Host "[build] building catalog"
& $inf2cat /driver:$outDir /os:10_x64 /uselocaltime
if ($LASTEXITCODE -ne 0) { throw "inf2cat failed ($LASTEXITCODE)" }

$cat = Join-Path $outDir 'RmDetectorFlt.cat'
Write-Host "[build] signing $cat"
& $signtool sign /fd SHA256 /a `
    /s 'My' /sha1 $thumb `
    /tr 'http://timestamp.digicert.com' /td SHA256 `
    $cat
if ($LASTEXITCODE -ne 0) { throw "signtool cat failed ($LASTEXITCODE)" }

# ---------- stage ----------
if (-not (Test-Path $installDir)) { New-Item -ItemType Directory $installDir | Out-Null }
foreach ($f in 'RmDetectorFlt.sys','RmDetectorFlt.inf','RmDetectorFlt.cat') {
    Copy-Item (Join-Path $outDir $f) $installDir -Force
}
$pdb = Join-Path $outDir 'RmDetectorFlt.pdb'
if (Test-Path $pdb) { Copy-Item $pdb $installDir -Force }

Write-Host ""
Write-Host "[build] staged artifacts in $installDir" -ForegroundColor Green
Write-Host "        next: run .\install.ps1 (admin)"
