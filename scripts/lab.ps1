<#
.SYNOPSIS
    실검체 랩 테스트 오케스트레이터 — README "실검체 테스트" 8단계의 반복·다줄
    명령을 짧은 한 단어 서브커맨드로 묶는다.  watch 디렉터리는 한 번만 설정하면
    이후 단계에서 재입력할 필요가 없다 (repo 루트 .lab.json 에 저장).

    안전 게이트는 그대로 유지한다:
      - 격리/스냅샷/Defender 확인은 여전히 lab_preflight.ps1 이 GO/NO-GO 로 막는다.
      - 이 스크립트는 절대 검체(악성 실행 파일)를 자동 실행하지 않는다.
        'detonate' 는 Defender 비켜주기 + 압축 해제까지만 하고, 실행은 사람이 직접.

.EXAMPLE
    # 0) watch 경로 한 번만 등록
    .\scripts\lab.ps1 set -WatchDir C:\Users\you\Documents

    .\scripts\lab.ps1 driver       # (선택) testsigning 재부팅 후 드라이버 빌드+설치+확인
    .\scripts\lab.ps1 run          # 에이전트 실행 (검체보다 먼저)
    .\scripts\lab.ps1 preflight    # GO/NO-GO 사전 점검 + 디코이 배치
    #   --> 여기서 VM 스냅샷을 찍는다 (사람이 직접) <--
    .\scripts\lab.ps1 detonate -SampleZip C:\in\s.zip -Password infected -OutDir C:\sample
    #   --> 스냅샷 확인 후, 압축 푼 검체를 사람이 직접 실행 <--
    .\scripts\lab.ps1 postmortem   # 성적 집계 (스냅샷 복원 전에)
#>
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'set', 'driver', 'run', 'preflight', 'detonate', 'postmortem')]
    [string] $Phase = 'help',

    [string] $WatchDir,
    [int]    $Count = 500,

    # detonate 전용
    [string] $SampleZip,
    [string] $Password,
    [string] $OutDir = 'C:\sample',

    # run 등에 그대로 넘길 추가 인자 (예: --no-minifilter)
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Rest
)

. "$PSScriptRoot\_common.ps1"

$root    = Get-RepoRoot
$cfgPath = Join-Path $root '.lab.json'

function Load-Cfg {
    if (Test-Path $cfgPath) {
        try { return (Get-Content $cfgPath -Raw | ConvertFrom-Json) } catch { return $null }
    }
    return $null
}

function Resolve-WatchDir {
    if ($WatchDir) { return $WatchDir }
    $c = Load-Cfg
    if ($c -and $c.WatchDir) { return $c.WatchDir }
    throw "watch 경로가 없습니다. 먼저:  .\scripts\lab.ps1 set -WatchDir <경로>"
}

function Get-PyExe {
    $venv = Join-Path $root '.venv\Scripts\python.exe'
    if (Test-Path $venv) { return $venv }
    if (Test-Command py)     { return 'py' }
    if (Test-Command python) { return 'python' }
    throw "Python 을 찾을 수 없습니다 (.venv 도 없음). scripts\bootstrap.ps1 로 먼저 설치하세요."
}

function Show-Help {
    Write-Host ""
    Write-Host "RansomGuard 실검체 랩 — lab.ps1" -ForegroundColor Cyan
    Write-Host "사용법:  .\scripts\lab.ps1 <단계> [옵션]" -ForegroundColor Gray
    Write-Host ""
    $c = Load-Cfg
    $wd = if ($c -and $c.WatchDir) { $c.WatchDir } else { '(미설정)' }
    Write-Host "  현재 watch 경로: $wd" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  set         watch 경로 저장   예) lab.ps1 set -WatchDir C:\Users\you\Documents"
    Write-Host "  driver      (선택) 드라이버 빌드+설치+적재확인  ※ testsigning 재부팅 이후"
    Write-Host "  run         에이전트 실행 (검체보다 먼저). 추가옵션 그대로 전달: lab.ps1 run --no-minifilter"
    Write-Host "  preflight   GO/NO-GO 사전 점검 + 디코이 배치 (-Count 기본 $Count)"
    Write-Host "  detonate    Defender 비켜주기 + 압축 해제까지만 (실행은 직접). -SampleZip/-Password/-OutDir"
    Write-Host "  postmortem  성적 집계 -> postmortem.md (스냅샷 복원 전에)"
    Write-Host ""
    Write-Host "  권장 순서: set -> (driver) -> run -> preflight -> [스냅샷] -> detonate -> [검체 실행] -> postmortem -> [스냅샷 복원]" -ForegroundColor Gray
    Write-Host ""
}

switch ($Phase) {

    'help' { Show-Help }

    'set' {
        if (-not $WatchDir) { throw "사용법:  .\scripts\lab.ps1 set -WatchDir <경로>" }
        @{ WatchDir = $WatchDir; Count = $Count } | ConvertTo-Json | Set-Content -Encoding UTF8 $cfgPath
        Write-Ok "watch 경로 저장됨: $WatchDir  (.lab.json)"
    }

    'driver' {
        Require-Admin
        Write-Step "드라이버 빌드"
        & (Join-Path $PSScriptRoot 'build_driver.ps1')
        Write-Step "드라이버 설치 + 시작"
        & (Join-Path $PSScriptRoot 'install_driver.ps1')
        Write-Step "적재 확인 (fltmc)"
        $loaded = fltmc filters | Select-String 'RansomGuard'
        if ($loaded) { Write-Ok "미니필터 적재됨: $loaded" }
        else { Write-Warn2 "fltmc 목록에 RansomGuard 가 없습니다. testsigning/재부팅/빌드 로그를 확인하세요." }
    }

    'run' {
        $wd = Resolve-WatchDir
        $py = Get-PyExe
        Write-Step "에이전트 실행 (watch: $wd)"
        Write-Warn2 "detonate 중 이 VM 에서 브라우저를 띄우지 마세요 (오탐 오염)."
        & $py (Join-Path $root 'agent.py') --watch $wd @Rest
    }

    'preflight' {
        $wd = Resolve-WatchDir
        Write-Step "사전 점검 (GO/NO-GO) + 디코이 $Count 개 배치 (watch: $wd)"
        & (Join-Path $PSScriptRoot 'lab_preflight.ps1') -WatchDir $wd -Count $Count @Rest
    }

    'detonate' {
        # 이 스크립트는 검체를 실행하지 않는다. Defender 비켜주기 + 압축 해제까지만.
        if (-not $SampleZip) { throw "사용법:  .\scripts\lab.ps1 detonate -SampleZip <zip경로> [-Password <암호>] [-OutDir C:\sample]" }
        if (-not (Test-Path $SampleZip)) { throw "검체 zip 을 찾을 수 없습니다: $SampleZip" }

        Write-Host ""
        Write-Warn2 "경고: 실제 랜섬웨어를 다룹니다. 격리된 일회용 VM + 스냅샷이 반드시 있어야 합니다."
        Write-Warn2 "이 단계는 압축 해제까지만 합니다. 검체 실행은 스냅샷 확인 후 직접 하세요."
        $ans = Read-Host "스냅샷을 찍었고 격리 VM 입니다. 계속하려면 'DETONATE' 입력"
        if ($ans -ne 'DETONATE') { Write-Err2 "취소되었습니다."; break }

        Write-Step "Defender 실시간 보호 비켜주기 (격리 VM 전용)"
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        } catch {
            Write-Warn2 "Set-MpPreference 실패: $($_.Exception.Message)"
        }
        $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($st) {
            Write-Host ("    RealTimeProtectionEnabled={0}  IsTamperProtected={1}" -f `
                $st.RealTimeProtectionEnabled, $st.IsTamperProtected)
            if ($st.RealTimeProtectionEnabled -or $st.IsTamperProtected) {
                Write-Warn2 "아직 보호가 켜져 있습니다. 보안 UI 에서 '변조 방지'부터 끈 뒤 다시 실행하세요. (안 끄면 압축 해제 순간 검체가 삭제됩니다.)"
            } else {
                Write-Ok "실시간 보호 OFF — 검체가 보존됩니다."
            }
        }

        Write-Step "검체 압축 해제 -> $OutDir"
        $sevenZip = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
        if (-not (Test-Path $sevenZip)) {
            throw "7-Zip 이 없습니다. 비번/ AES zip 은 탐색기로 안 풀립니다. 설치:  winget install -e --id 7zip.7zip"
        }
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        $args7 = @('x', $SampleZip, "-o$OutDir", '-y')
        if ($Password) { $args7 += "-p$Password" }
        & $sevenZip @args7
        if ($LASTEXITCODE -ne 0) {
            throw "7-Zip 압축 해제 실패(코드 $LASTEXITCODE). 'CRC failed'/'Data error' 면 다운로드가 잘린 것 — 재다운로드."
        }

        Write-Ok "압축 해제 완료: $OutDir"
        Write-Host ""
        Write-Host "  다음(사람이 직접):" -ForegroundColor Cyan
        Write-Host "   1) 스냅샷이 있는지 마지막으로 확인" -ForegroundColor Gray
        Write-Host "   2) watch dir *밖* 인 아래 폴더에서 검체를 직접 실행" -ForegroundColor Gray
        Write-Host "   3) 콘솔 로그에서 잡힌 PID 가 브라우저가 아니라 검체인지 확인" -ForegroundColor Gray
        Get-ChildItem -Path $OutDir -Recurse -Include *.exe, *.scr, *.js, *.bat, *.cmd, *.ps1 -ErrorAction SilentlyContinue |
            Select-Object -First 20 -ExpandProperty FullName | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow }
    }

    'postmortem' {
        $wd  = Resolve-WatchDir
        $py  = Get-PyExe
        $out = Join-Path $root 'postmortem.md'
        Write-Step "성적 집계 (watch: $wd) -> $out"
        & $py (Join-Path $root 'postmortem.py') --watch $wd --out $out @Rest
        if (Test-Path $out) { Write-Ok "리포트: $out" }
    }
}
