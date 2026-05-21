<#
.SYNOPSIS
    Build the RansomGuard kernel minifilter (.sys + .inf + .cat).

.DESCRIPTION
    Locates msbuild via vswhere, verifies the WDK is installed, and builds
    minifilter\RansomGuard.sln in Release|x64.  Output lands under
    minifilter\build\x64\Release\.

    If the WDK is missing, prints exact install instructions and exits 1
    rather than attempting an unattended VS install (the Build Tools +
    WDK download is several GB and requires interactive consent).
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')]
    [string] $Configuration = 'Release',
    [string] $Platform = 'x64'
)

. "$PSScriptRoot\_common.ps1"

$repoRoot = Get-RepoRoot
$sln = Join-Path $repoRoot 'minifilter\RansomGuard.sln'
if (-not (Test-Path $sln)) {
    throw "Solution not found: $sln"
}

Write-Step 'Locating MSBuild'
$msbuild = Find-MsBuild
if (-not $msbuild) {
    Write-Err2 'MSBuild was not found.'
    Write-Host ''
    Write-Host '  Install Visual Studio 2022 Build Tools with the C++ workload:'
    Write-Host '      winget install --id Microsoft.VisualStudio.2022.BuildTools --silent ^'
    Write-Host '          --override "--add Microsoft.VisualStudio.Workload.VCTools --quiet --wait"'
    Write-Host ''
    Write-Host '  Then install the Windows Driver Kit (WDK):'
    Write-Host '      winget install --id Microsoft.WindowsWDK.10.0.26100 --silent'
    Write-Host ''
    exit 1
}
Write-Ok "MSBuild at $msbuild"

Write-Step 'Verifying WDK presence'
if (-not (Test-WdkInstalled)) {
    Write-Warn2 'WDK / Windows SDK component not detected via vswhere.'
    Write-Host '  Install with:'
    Write-Host '      winget install --id Microsoft.WindowsWDK.10.0.26100 --silent'
    Write-Host '  ...then re-run this script.'
    Write-Host ''
    Write-Host '  (Continuing anyway; the build will fail explicitly if'
    Write-Host '   the WDK targets are unavailable.)'
} else {
    Write-Ok 'WDK detected'
}

Write-Step "Building $($sln | Split-Path -Leaf) ($Configuration|$Platform)"
& $msbuild $sln `
    "/p:Configuration=$Configuration" `
    "/p:Platform=$Platform" `
    /m /nologo /verbosity:minimal
if ($LASTEXITCODE -ne 0) {
    Write-Err2 "msbuild exited with code $LASTEXITCODE"
    exit $LASTEXITCODE
}

$outDir = Join-Path $repoRoot "minifilter\build\$Platform\$Configuration"
$sys    = Join-Path $outDir 'RansomGuard.sys'
$inf    = Join-Path $outDir 'RansomGuard.inf'

Write-Step 'Build summary'
foreach ($f in @($sys, $inf)) {
    if (Test-Path $f) {
        Write-Ok $f
    } else {
        Write-Warn2 "missing: $f"
    }
}
