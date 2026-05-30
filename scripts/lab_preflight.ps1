<#
.SYNOPSIS
    격리 랩 detonate 전 준비 상태 점검 (real-ransomware pre-flight).

.DESCRIPTION
    실제 랜섬웨어 검체를 터뜨리기 직전에 "이 머신에서 터뜨려도 되는가"를
    확인하는 readiness 체커.  파일을 만들거나 점검만 할 뿐, 검체를 받거나
    실행하지는 않는다 (검체는 사용자가 연구 저장소에서 직접 넣는다).

    GO / NO-GO 를 출력한다:
      - BLOCKER 가 하나라도 있으면 NO-GO 로 종료(exit 1).  물리 머신,
        진짜 인터넷 연결, 스냅샷 미확인 등 "터지면 호스트까지 번지는"
        조건들.
      - WARNING 은 진행은 가능하지만 결과 해석에 영향을 주는 항목
        (testsigning off, 드라이버 미로드, 에이전트 미실행 등).

    점검 항목:
      1. (BLOCKER) 가상머신 여부 — 물리 머신이면 중단
      2. (BLOCKER) 네트워크 격리 — 진짜 인터넷에 닿으면 중단
      3. (WARN)    호스트 공유 채널(VMware/VirtualBox shared folders)
      4. (WARN)    testsigning 상태 (미니필터 로드용)
      5. (WARN)    RansomGuard 필터/서비스 로드 여부
      6. (WARN)    에이전트 프로세스 실행 여부
      7. (INFO)    대시보드 응답 여부
      8.           watch dir 에 디코이 더미 파일 생성
      9. (BLOCKER) 스냅샷 확인 — 사용자가 직접 타이핑으로 확인

.PARAMETER WatchDir
    에이전트가 감시하는 디렉터리. 디코이 파일을 여기 채운다.
    기본 .\test_watch_dir (프로젝트 기본값과 동일).

.PARAMETER Count
    생성할 디코이 더미 파일 수. 기본 300.

.PARAMETER Port
    대시보드 포트. 기본 5000.

.PARAMETER SkipPopulate
    디코이 파일 생성을 건너뛴다 (이미 채워둔 경우).

.PARAMETER AssumeSnapshot
    스냅샷 확인 프롬프트를 건너뛴다. CI/무인 실행용 — 수동 테스트에서는
    쓰지 말 것.

.EXAMPLE
    .\scripts\lab_preflight.ps1 -WatchDir C:\Users\you\Documents -Count 500
#>

[CmdletBinding()]
param(
    [string] $WatchDir = ".\test_watch_dir",
    [int]    $Count = 300,
    [int]    $Port = 5000,
    [switch] $SkipPopulate,
    [switch] $AssumeSnapshot
)

. "$PSScriptRoot\_common.ps1"

# 점검 자체는 부수효과가 없어야 하므로, 외부 exe/CIM 의 비정상 종료가
# 스크립트를 죽이지 않게 Continue 로 낮춘다 (각 항목을 개별 try/catch).
$ErrorActionPreference = 'Continue'

$blockers = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

function Add-Blocker($msg) { $script:blockers.Add($msg); Write-Err2 $msg }
function Add-Warning($msg) { $script:warnings.Add($msg); Write-Warn2 $msg }

Write-Host ""
Write-Host "############################################################" -ForegroundColor Magenta
Write-Host "#  RansomGuard 랩 PRE-FLIGHT — real-ransomware detonate 준비  #" -ForegroundColor Magenta
Write-Host "############################################################" -ForegroundColor Magenta

# ---------------------------------------------------------------------------
# 0. 권한 (점검은 가능하지만, 실제 실행엔 관리자 필요)
# ---------------------------------------------------------------------------
Write-Step "권한 확인"
if (Test-Admin) {
    Write-Ok "관리자 권한으로 실행 중"
} else {
    Add-Warning "관리자 권한이 아님 — 드라이버/서비스/에이전트 상태 점검이 부정확할 수 있고, 실제 에이전트 실행은 관리자 PowerShell이 필요합니다."
}

# ---------------------------------------------------------------------------
# 1. (BLOCKER) 가상머신 여부
# ---------------------------------------------------------------------------
Write-Step "가상머신 여부 확인  [BLOCKER]"
try {
    $cs  = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $hay = @($cs.Manufacturer, $cs.Model, $bios.Manufacturer,
             $bios.SerialNumber, $bios.Version) -join ' '
    Write-Host "  ID: $($cs.Manufacturer) / $($cs.Model)"
    $vmHints = 'VMware|VirtualBox|innotek|QEMU|KVM|Xen|Bochs|Virtual Machine|Microsoft Corporation.*Virtual|Parallels|Hyper-V'
    if ($hay -match $vmHints) {
        Write-Ok "가상머신으로 식별됨"
    } else {
        Add-Blocker "가상머신으로 식별되지 않음 — 물리 머신일 가능성. 실제 랜섬웨어는 호스트 전체를 암호화합니다. 격리 VM에서만 진행하세요."
    }
} catch {
    Add-Blocker "VM 여부를 확인할 수 없음 ($($_.Exception.Message)). 안전을 위해 NO-GO 처리."
}

# ---------------------------------------------------------------------------
# 2. (BLOCKER) 네트워크 격리 — 진짜 인터넷에 닿으면 안 됨
# ---------------------------------------------------------------------------
Write-Step "네트워크 격리 확인  [BLOCKER]"
try {
    # ICMP 보다 TCP 가 방화벽에 덜 막히므로 53/443 으로 실제 인터넷 도달성 확인.
    $reachable = $false
    foreach ($probe in @(@{Host='8.8.8.8'; Port=53}, @{Host='1.1.1.1'; Port=443})) {
        $r = Test-NetConnection -ComputerName $probe.Host -Port $probe.Port `
                -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction Stop
        if ($r) { $reachable = $true; break }
    }
    if ($reachable) {
        Add-Blocker "진짜 인터넷에 도달 가능함 — 검체가 C2 통신/전파를 할 수 있습니다. 어댑터를 Host-only/Internal 로 바꾸거나 연결을 끊으세요."
    } else {
        Write-Ok "외부 인터넷 도달 불가 (격리됨)"
    }

    # 활성 어댑터 + 기본 게이트웨이 정보 (참고용)
    $up = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
          Where-Object { $_.NetAdapter.Status -eq 'Up' }
    foreach ($n in $up) {
        $gw = ($n.IPv4DefaultGateway | Select-Object -First 1).NextHop
        Write-Host "  어댑터: $($n.InterfaceAlias)  GW: $(if($gw){$gw}else{'없음'})"
        if ($gw) {
            Add-Warning "어댑터 '$($n.InterfaceAlias)' 에 기본 게이트웨이($gw)가 있음 — 브리지/NAT 가 아닌지 확인하세요."
        }
    }
} catch {
    Add-Warning "네트워크 격리 자동 확인 실패 ($($_.Exception.Message)) — 수동으로 어댑터가 Host-only/Internal 인지 확인하세요."
}

# ---------------------------------------------------------------------------
# 3. (WARN) 호스트 공유 채널
# ---------------------------------------------------------------------------
Write-Step "호스트 공유 채널 확인"
$sharePaths = @('\\vmware-host\Shared Folders', '\\VBOXSVR')
$foundShare = $false
foreach ($s in $sharePaths) {
    if (Test-Path $s -ErrorAction SilentlyContinue) {
        Add-Warning "공유 폴더 채널이 열려 있음: $s — 검체가 호스트 파일에 닿거나 전파할 수 있습니다. VM 설정에서 끄세요."
        $foundShare = $true
    }
}
if (-not $foundShare) { Write-Ok "감지된 호스트 공유 폴더 없음 (클립보드/드래그앤드롭은 VM 설정에서 직접 확인)" }

# ---------------------------------------------------------------------------
# 4. (WARN) testsigning — 미니필터 로드 전제
# ---------------------------------------------------------------------------
Write-Step "testsigning 상태 확인 (미니필터용)"
try {
    $bcd = bcdedit /enum '{current}' 2>$null
    if ($bcd -match 'testsigning\s+Yes') {
        Write-Ok "testsigning ON"
    } else {
        Add-Warning "testsigning OFF — 서명 안 된 미니필터는 로드되지 않습니다. 켜려면: bcdedit /set testsigning on  후 재부팅 (커널 차단 경로를 테스트할 때만 필요)."
    }
} catch {
    Add-Warning "testsigning 상태를 읽을 수 없음 ($($_.Exception.Message))."
}

# ---------------------------------------------------------------------------
# 5. (WARN) RansomGuard 필터 / 서비스
# ---------------------------------------------------------------------------
Write-Step "RansomGuard 드라이버 로드 확인"
try {
    $filters = fltmc.exe filters 2>$null
    if ($filters -match 'RansomGuard') {
        Write-Ok "미니필터 'RansomGuard' 로드됨"
    } else {
        Add-Warning "미니필터가 로드되어 있지 않음 — 커널 차단(quarantine write block)을 테스트하려면 .\scripts\install_driver.ps1 로 로드하세요. 사용자 모드 탐지만 볼 거면 무시 가능."
    }
} catch {
    Add-Warning "fltmc 실행 실패 ($($_.Exception.Message))."
}

# ---------------------------------------------------------------------------
# 6. (WARN) 에이전트 프로세스
# ---------------------------------------------------------------------------
Write-Step "에이전트 프로세스 확인"
try {
    $agentProcs = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='py.exe'" -ErrorAction Stop |
                  Where-Object { $_.CommandLine -match 'agent\.py' }
    if ($agentProcs) {
        foreach ($p in $agentProcs) {
            Write-Ok "에이전트 실행 중 (PID $($p.ProcessId)): $($p.CommandLine)"
            if ($p.CommandLine -notmatch '--no-tamper-protection') {
                Add-Warning "에이전트가 변조 방지 ON 으로 실행 중 — 검체가 죽이려 하면 BSOD 가 날 수 있습니다(의도된 동작). 스냅샷이 반드시 있어야 합니다."
            }
        }
    } else {
        Add-Warning "agent.py 프로세스를 찾지 못함 — detonate 전에 관리자 PowerShell에서 에이전트를 먼저 띄우세요."
    }
} catch {
    Add-Warning "프로세스 목록 조회 실패 ($($_.Exception.Message))."
}

# ---------------------------------------------------------------------------
# 7. (INFO) 대시보드
# ---------------------------------------------------------------------------
Write-Step "대시보드 응답 확인 (127.0.0.1:$Port)"
try {
    $dash = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port `
                -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction Stop
    if ($dash) {
        Write-Ok "대시보드 포트 열림 — http://127.0.0.1:$Port 에서 점수 관찰/녹화"
    } else {
        Write-Warn2 "대시보드 포트가 닫혀 있음 (에이전트를 --no-dashboard 로 띄웠거나 미실행). 콘솔/녹화로 관찰하세요."
    }
} catch {
    Write-Warn2 "대시보드 확인 실패 ($($_.Exception.Message))."
}

# ---------------------------------------------------------------------------
# 8. 디코이 더미 파일 생성
# ---------------------------------------------------------------------------
Write-Step "디코이 파일 준비: $WatchDir"
$resolvedWatch = $null
try {
    $null = New-Item -ItemType Directory -Force -Path $WatchDir -ErrorAction Stop
    $resolvedWatch = (Resolve-Path $WatchDir).Path
} catch {
    Add-Warning "watch 디렉터리를 만들 수 없음: $WatchDir ($($_.Exception.Message))"
}

if ($resolvedWatch -and -not $SkipPopulate) {
    # simulator.py 와 동일한 정상 매직바이트로 디코이를 만든다 — 검체가
    # 이걸 깨뜨리면 magic/entropy/extension 신호가 자연스럽게 발생.
    function New-Payload([byte[]]$Magic, [string]$Body, [int]$Repeat) {
        $bodyBytes = [Text.Encoding]::ASCII.GetBytes(($Body * $Repeat))
        return $Magic + $bodyBytes
    }
    $payloads = @(
        (New-Payload ([byte[]](0x50,0x4B,0x03,0x04))            'normal office data ' 80),  # .docx (PK)
        (New-Payload ([byte[]](0x25,0x50,0x44,0x46,0x2D,0x31,0x2E,0x34,0x0A)) 'normal pdf content ' 80),  # .pdf
        (New-Payload ([byte[]](0xFF,0xD8,0xFF,0xE0))            'normal image data '  80),  # .jpg
        (New-Payload ([byte[]]@())                              'normal user document content ' 50)        # .txt
    )
    $exts = @('.docx', '.pdf', '.jpg', '.txt')
    $made = 0
    for ($i = 0; $i -lt $Count; $i++) {
        $ext = $exts[$i % $exts.Count]
        $payload = $payloads[$i % $payloads.Count]
        $name = "document_{0:D3}{1}" -f $i, $ext
        $path = Join-Path $resolvedWatch $name
        try {
            [System.IO.File]::WriteAllBytes($path, $payload)
            $made++
        } catch {
            # 파일 하나 실패가 전체를 막지 않게.
        }
    }
    Write-Ok "$made / $Count 개 디코이 파일 생성 ($resolvedWatch)"
    Write-Warn2 "실제 랜섬웨어는 이 폴더 밖 시스템 파일까지 암호화합니다. VM 자체가 부팅 불능이 될 수 있으니 스냅샷이 필수입니다."
} elseif ($SkipPopulate) {
    Write-Ok "디코이 생성 건너뜀 (-SkipPopulate)"
}

# ---------------------------------------------------------------------------
# 9. (BLOCKER) 스냅샷 확인 — 게스트 안에서는 자동 확인 불가
# ---------------------------------------------------------------------------
Write-Step "스냅샷 확인  [BLOCKER]"
if ($AssumeSnapshot) {
    Write-Warn2 "-AssumeSnapshot 으로 스냅샷 확인을 건너뜀. 무인 실행이 아니면 쓰지 마세요."
} else {
    Write-Host "  실제 검체를 터뜨리면 이 VM 은 복구 불능이 될 수 있습니다." -ForegroundColor Yellow
    Write-Host "  지금 '깨끗한 상태 + 에이전트 준비' 스냅샷을 찍었습니까?" -ForegroundColor Yellow
    $ans = Read-Host "  확인하려면 정확히  I HAVE A SNAPSHOT  를 입력하세요"
    if ($ans -ne 'I HAVE A SNAPSHOT') {
        Add-Blocker "스냅샷 미확인 — detonate 금지. 스냅샷을 찍고 다시 실행하세요."
    } else {
        Write-Ok "스냅샷 확인됨"
    }
}

# ---------------------------------------------------------------------------
# 최종 GO / NO-GO
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
if ($warnings.Count -gt 0) {
    Write-Host " WARNING ($($warnings.Count)):" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "   ! $_" -ForegroundColor Yellow }
}
if ($blockers.Count -gt 0) {
    Write-Host ""
    Write-Host " BLOCKER ($($blockers.Count)):" -ForegroundColor Red
    $blockers | ForEach-Object { Write-Host "   x $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host " 결과:  NO-GO  — 위 BLOCKER 를 먼저 해결하세요." -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Magenta
    exit 1
} else {
    Write-Host ""
    Write-Host " 결과:  GO  — 격리/스냅샷 확인됨. detonate 후 반드시 스냅샷 복원." -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Magenta
    exit 0
}
