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
    [ValidateSet('x64','ARM64')]
    [string] $Platform
)

. "$PSScriptRoot\_common.ps1"

# Default to the host architecture.  The kernel-mode driver toolset
# (WindowsKernelModeDriver10.0) is only registered for the arch whose VS
# build components are installed; on an ARM64 host, forcing x64 yields
# MSB8020 ("build tools ... cannot be found").
if (-not $Platform) {
    $Platform = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'ARM64' } else { 'x64' }
    Write-Ok "Platform not specified; defaulting to host arch: $Platform"
}

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

Write-Step 'Restoring NuGet packages (WDK/SDK)'
# packages.config 방식이라 'msbuild -t:restore' 로는 복원되지 않고 nuget.exe
# 가 필요하다. nuget.exe 는 .gitignore 로 저장소에서 빠지므로, 없으면 공식
# 배포본을 minifilter\nuget.exe 로 부트스트랩 다운로드한다. 복원물(packages\)
# 역시 커밋 대상이 아니므로 각 머신에서 이 단계로 생성된다.
$nuget = Join-Path $repoRoot 'minifilter\nuget.exe'
if (-not (Test-Path $nuget)) {
    if (Test-Command nuget) {
        $nuget = (Get-Command nuget).Source
        Write-Ok "PATH 의 nuget 사용: $nuget"
    } else {
        Write-Warn2 'nuget.exe 가 없음 — 공식 배포본을 내려받습니다.'
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest `
                -Uri 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe' `
                -OutFile $nuget -UseBasicParsing
            Write-Ok "nuget.exe 부트스트랩: $nuget"
        } catch {
            Write-Err2 "nuget.exe 다운로드 실패: $($_.Exception.Message)"
            Write-Host '  수동 설치 후 재실행: winget install --id Microsoft.NuGet'
            exit 1
        }
    }
}
& $nuget restore $sln -PackagesDirectory (Join-Path $repoRoot 'minifilter\packages')
if ($LASTEXITCODE -ne 0) {
    Write-Err2 "nuget restore exited with code $LASTEXITCODE"
    exit $LASTEXITCODE
}
Write-Ok 'NuGet packages restored'

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
