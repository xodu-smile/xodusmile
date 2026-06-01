# RansomGuard EDR (Windows 11)

> 영문 버전: [README.en.md](./README.en.md)

Windows 11용 **랜섬웨어 전용 소형 EDR** 입니다.
커널 모드 **파일시스템 미니필터** 와 사용자 모드 **행동 기반 탐지기들** 을
조합하고, 점수가 임계치를 넘는 순간 의심 프로세스를 **격리(quarantine)** 하거나
**즉시 종료(kill)** 할 수 있는 **자동 대응(active responder)** 까지 갖췄어요.

> **이건 연구/학습용 프로토타입입니다.**
> 본인 소유의 머신, 가급적이면 격리된 VM에서만 돌리세요.
> 드라이버를 로드하려면 테스트 서명이 활성화돼 있거나 정식 서명된 카탈로그가 있어야 합니다.

---

## 주요 기능 (Features)

| 분류 | 설명 |
|---|---|
| **커널 미니필터** | `minifilter/RansomGuard.sys` 드라이버가 모든 볼륨에서 `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` 을 가로채요. `(pid, path, op, bytes)` 형식 이벤트를 필터 통신 포트로 사용자 모드에 스트리밍하고, 격리된 PID 의 후속 쓰기/이름변경을 **커널 안에서 차단** 합니다. |
| **PID 단위 폭발 감지** | minifilter_bridge 가 PID 별로 쓰기 바이트와 rename 횟수를 누적해요. 짧은 시간 안에 폭증하면 어느 폴더든 상관없이 HIGH 신호 발생. |
| **카나리 파일** | 사용자가 절대 안 건드릴 미끼 파일을 깔아두고 해시로 감시. 변경 시 **단발로 CRITICAL** 발사. |
| **프로세스 명령어 룰** | VSS 섀도카피 삭제, BCD 변조, Defender 비활성화, 로그 삭제, BitLocker 해제, 흔한 PowerShell 난독화 패턴 등 22개 룰. |
| **프로세스 트리 휴리스틱** | LOLBin 부모-자식 체인(Office → PowerShell, 브라우저 → 스크립트 호스트), 한 부모가 짧은 시간 안에 자식을 다수 spawn 하는 fan-out, psutil 기반 디스크 쓰기 burst. |
| **자동 대응 (Active Responder)** | 3가지 모드 — `off` / `quarantine` / `kill`. `kill` 모드에서 PID 가 명시된 HIGH/CRITICAL 신호가 발생하면 즉시 커널 격리 + `TerminateProcess`. **lsass, csrss 같은 시스템 핵심 프로세스는 절대 안 죽이는 하드코딩 목록** 으로 보호. |
| **Flask 대시보드** | `http://127.0.0.1:5000` — 실시간 점수, 최근 이벤트, 프로세스 목록, 자동 대응 로그, 수동 kill/release 버튼. |

---

## 점수 / 등급 (Scoring)

신호 하나로 결론 내지 않아요. **120초 슬라이딩 윈도우** 안의 모든 신호 점수를
합산해서 등급을 판정합니다. (postmortem·대시보드 결과를 읽을 때 이 표를 참고)

| 점수 | 등급 | 의미 |
|---|---|---|
| 0~29 | INFO | 정상 |
| 30~59 | LOW | 약간 의심 |
| 60~99 | MEDIUM | 주의 |
| 100~149 | HIGH | 위험 |
| 150+ | CRITICAL | 즉시 대응 |

오래된 신호는 2분 뒤 자동으로 사라져서 "옛날 일 때문에 계속 경보 울리는" 일이 없어요.

---

## 실행 환경 (Requirements)

- **OS:** Windows 11 (22H2 이상), x64 또는 ARM64
- **사용자 모드:** Python 3.10+ (x64 / ARM64)
- **커널 빌드:** Visual Studio 2022 Build Tools (C++ 워크로드) + Windows Driver Kit (WDK 10.0.26100 이상)
- **드라이버 로드:** 테스트 서명 활성화 또는 `RansomGuard.sys` 정식 서명 카탈로그

> **드라이버 없이도 사용자 모드 에이전트만 단독 실행 가능** 합니다.
> 단, 커널 레벨 파일 I/O 신호는 못 받아요 (그 부분만 동작 안 함).

---

## 설치 (Install)

**관리자 권한 PowerShell** 에서 저장소 루트 위치에 실행:

```powershell
# 옵션 A — 한방 설치: Python 의존성 + 드라이버 빌드 + 드라이버 설치
.\scripts\install.ps1

# 옵션 B — 사용자 모드만 설치 (Python, venv, requirements)
.\scripts\bootstrap.ps1

# 옵션 C — 위 + 드라이버 빌드/설치까지
.\scripts\bootstrap.ps1 -BuildDriver -InstallDriver
```

`bootstrap.ps1` 이 하는 일:

1. Python 3.12 가 없으면 `winget` 으로 설치
2. 저장소 루트에 `.venv\` 생성
3. `requirements.txt` 설치
4. `pywin32_postinstall -install` 실행
5. (옵션) 드라이버 빌드 및 설치

드라이버 빌드 스크립트(`scripts/build_driver.ps1`)는 `vswhere` 로 찾은 `msbuild`
를 호출하고, 빌드 전에 NuGet 패키지(WDK/SDK)를 자동 복원합니다. **호스트
아키텍처를 자동 감지**해서 x64 호스트는 x64 로, ARM64 호스트는 ARM64 로 빌드하며,
산출물은 `minifilter\build\<arch>\Release\RansomGuard.sys` 와 `.inf`, `.cat` 입니다
(`-Platform x64|ARM64` 로 직접 지정도 가능).

WDK 나 VS Build Tools 가 없으면 스크립트가 **무인 설치하지 않고** 정확한
`winget` 명령을 출력해줘요 (수 GB 다운로드를 갑자기 시작하지 않으려고).

---

## 실행 방법 (Run)

### 방법 1: 서비스로 실행 (실제 테스트 추천)

```powershell
# RansomGuardAgent + RansomGuardWatchdog 서비스 설치,
# SCM 자동 재시작 설정, 서비스/데이터 폴더 DACL 락,
# 둘 다 시작.
.\scripts\install_services.ps1 -WatchDirs 'C:\Users'

# 제거
.\scripts\uninstall_services.ps1
```

Agent 는 LocalSystem 권한으로 `RtlSetProcessIsCritical` 가 설정된 상태로
실행되고, 커널 드라이버의 `ObCallback` 에 등록돼서 핸들 access 권한이
박탈됩니다. Watchdog 은 5초마다 Agent 를 폴링해서 크래시나 hang 발생 시
재시작해요. 데이터는 `C:\ProgramData\RansomGuard\` 에 저장.

### 방법 2: CLI 로 실행 (개발 / 일회용)

```powershell
.\.venv\Scripts\Activate.ps1

# 기본값: 미니필터 ON, responder 가 격리 + 종료까지 수행
python agent.py --watch C:\Users\you\Documents

# 관찰자 모드 (아무것도 안 죽임) — 튜닝할 때 유용
python agent.py --mode off --no-dashboard

# 격리만 하고 종료는 안 함
python agent.py --mode quarantine

# 개발 편의: 변조 방지 끄기 → taskkill 가능
python agent.py --no-tamper-protection
```

### CLI 플래그

| 플래그 | 효과 |
|---|---|
| `--watch <dir>` | 감시할 디렉토리 (여러 번 지정 가능). 기본: `./test_watch_dir` |
| `--mode {off,quarantine,kill}` | Responder 모드. 기본 `kill` |
| `--no-minifilter` | 커널 다리 비활성화 (사용자 모드만 사용) |
| `--no-dashboard` | Flask UI 시작 안 함 |
| `--port N` | 대시보드 포트 (기본 `5000`) |
| `--db PATH` | SQLite 경로 (기본 `detector.db`) |
| `--reports-dir PATH` | 마크다운 사건 보고서 저장 위치 (기본 `./reports`) |
| `--no-notify` | 프로세스 종료 시 데스크톱 알림 끄기 |
| `--no-tamper-protection` | `RtlSetProcessIsCritical` + DACL 강화 끄기 (개발 시 taskkill 가능하게) |
| `--watchdog-pid <PID>` | 동반 watchdog 의 PID. Agent 와 함께 커널 변조 방지 등록 |

---

## 테스트 / 검증 (Validation)

```powershell
# In-process 데모: 에이전트 띄우고 안전한 모의 이벤트를 자동 주입
python demo_inproc.py

# 독립 시뮬레이터: watch dir 안의 더미 파일을 랜덤 바이트로 덮어쓰고
# .encrypted 확장자로 rename — 실제 암호화는 절대 안 함.
# vss / bcd 시나리오는 ProcessCmdlineDetector.submit_external 로
# 가짜 cmdline 이벤트만 주입 (실제 vssadmin/bcdedit 실행 X).
# stealth 는 burst 임계를 회피하는 느린 페이스이지만
# magic/entropy/extension 신호는 여전히 발생.
python tests\simulator.py --scenario {populate|encrypt|canary|vss|bcd|full|stealth}
```

두 도구 모두 **진짜 `vssadmin` 이나 `bcdedit` 을 실행하지 않습니다.**
cmdline 룰은 `ProcessCmdlineDetector.submit_external` 을 통해 가짜 이벤트로만 검증됩니다.

---

## 격리 랩에서의 실검체 테스트 (Real-sample lab testing)

> ⚠ **위 시뮬레이터로 탐지 로직의 대부분이 검증됩니다.** 실제 랜섬웨어 검체는
> 권한상승·전파·안티VM 같은 부가 행위를 볼 때만 필요하고, **네트워크가 격리되고
> 스냅샷이 있는 전용 VM 에서만** 실행하세요. 실제 검체는 watch dir 밖 시스템
> 전체를 암호화해 VM 을 부팅 불능으로 만들 수 있습니다.

격리 VM 안에서 실검체를 터뜨려 탐지/대응 성적을 재는 절차입니다. 모든 명령은
**VM 게스트의 관리자 PowerShell** 에서 실행합니다. 검체는 직접 준비하세요(이
프로젝트는 검체를 배포하지 않습니다).

### 빠른 실행 — `scripts\lab.ps1`

아래 8단계 명령을 일일이 칠 필요 없이 오케스트레이터로 묶어 실행할 수 있습니다.
**watch 경로는 한 번만 등록**하면 이후 단계에서 재입력하지 않습니다. 안전
게이트는 그대로입니다 — **스냅샷 촬영과 검체 실행은 사람이 직접** 하고, `detonate`
는 Defender 비켜주기 + 압축 해제까지만 합니다(검체를 자동 실행하지 않음).

```powershell
.\scripts\lab.ps1 set -WatchDir C:\Users\you\Documents  # 0) 경로 한 번만 등록
.\scripts\lab.ps1 driver        # 2) (선택) testsigning 재부팅 후 드라이버 빌드+설치+확인
.\scripts\lab.ps1 run           # 3) 에이전트 실행 (필요시: lab.ps1 run --no-minifilter)
.\scripts\lab.ps1 preflight     # 4) GO/NO-GO 점검 + 디코이 배치 (-Count 기본 500)
#   --> 5) 여기서 VM 스냅샷을 직접 찍습니다 <--
.\scripts\lab.ps1 detonate -SampleZip C:\in\s.zip -Password infected -OutDir C:\sample
#   --> 6) 압축 해제까지만. 스냅샷 확인 후 검체를 직접 실행 <--
.\scripts\lab.ps1 postmortem    # 7) 성적 집계 -> postmortem.md
#   --> 8) 스냅샷 복원 <--
.\scripts\lab.ps1 help          # 전체 흐름 / 현재 watch 경로 확인
```

각 단계가 실제로 무엇을 하는지는 아래 상세 설명을 참고하세요.

**0) 준비** — 스냅샷 가능한 일회용 Windows 11 VM, `.\scripts\bootstrap.ps1` 로
사용자 모드 설치(커널 차단까지 볼 거면 WDK/VS Build Tools 도 — `설치` 섹션 참고).

**1) VM 격리** — 어댑터를 Host-only/Internal 로(NAT·브리지 금지), 공유 폴더·
클립보드·드래그앤드롭 모두 OFF. (4단계 pre-flight 가 다시 확인합니다.)

**2) 미니필터 로드** — 커널 신호/차단을 테스트할 때만. 생략 시
`agent.py --no-minifilter`.

```powershell
bcdedit /set testsigning on; shutdown /r /t 0   # 테스트 서명 ON → 재부팅
.\scripts\build_driver.ps1                       # 빌드 (호스트 arch 자동)
.\scripts\install_driver.ps1                     # 설치 + 시작
fltmc filters | Select-String RansomGuard        # 적재 확인
```

**3) 에이전트 실행** — 검체보다 먼저 띄웁니다(변조 방지 ON + `kill` 기본값).

```powershell
.\.venv\Scripts\Activate.ps1
python agent.py --watch C:\Users\you\Documents   # 진행은 콘솔 로그로 관찰
```

> ⚠ detonate 중 **테스트 VM 에서 브라우저를 띄우지 마세요.** Edge/Chrome 가
> 휴리스틱을 오염시켜 검체 대신 브라우저가 잡힙니다. 대시보드는 detonate 전에만
> 잠깐 보거나 7단계 postmortem 으로 봅니다. 변조 방지 ON 상태에서 검체가
> 에이전트를 죽이려 하면 의도적으로 BSOD 가 날 수 있어 스냅샷이 필수입니다.

**4) pre-flight GO/NO-GO** — 격리 재점검 + 디코이 배치 + 스냅샷 확인.

```powershell
.\scripts\lab_preflight.ps1 -WatchDir C:\Users\you\Documents -Count 500
```

점검: VM·네트워크 격리·공유 채널·testsigning·**Defender 실시간 보호**·드라이버/
에이전트 로드·디코이·스냅샷. BLOCKER 가 있으면 `NO-GO`(exit 1)로 막힙니다.

**5) 깨끗한 스냅샷** — 4단계 스냅샷 프롬프트에서, 에이전트 실행 + 디코이 채워진 +
검체 미실행 상태로 VM 스냅샷을 찍고 `I HAVE A SNAPSHOT` 입력 → `GO`.

**6) detonate** — `GO` 이후에만.

```powershell
# (a) Defender 비켜주기 — 안 끄면 압축 해제 순간 검체가 삭제됩니다
#     ("빈 폴더 + 비번창 안 뜸"의 원인). Windows 보안 UI 에서 변조 방지를
#     먼저 끈 뒤:
Set-MpPreference -DisableRealtimeMonitoring $true   # 또는 -ExclusionPath 'C:\sample'

# (a-1) 진짜 꺼졌는지 확인 — 변조 방지(IsTamperProtected)가 켜져 있으면 위
#       명령은 에러 없이 무시됩니다. RealTimeProtectionEnabled 가 False 여야 함.
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected, AntivirusEnabled
#   RealTimeProtectionEnabled=True 또는 IsTamperProtected=True 면 → 아직 안 꺼진
#   것. 보안 UI에서 변조 방지부터 끄고 (a) 다시 실행. (검체가 이미 삭제됐다면
#   "보안 기록 > 격리된 항목" 또는 MpCmdRun.exe -Restore -ListAll 로 복원 가능.)

# (b) 검체를 watch dir *밖*(예: C:\sample)에 압축 해제 → 실행
#     ⚠ 비밀번호가 걸린 zip 은 윈도우 탐색기로 풀지 마세요. 요즘 비번 압축은
#        대부분 AES 암호화라 탐색기가 복호화하지 못하고 → 비번창도 안 뜨고
#        "빈 폴더"가 됩니다(확장자가 .zip 이어도 동일). 7-Zip 으로 푸세요:
#        winget install -e --id 7zip.7zip   # 미설치 시
# 형식: & 'C:\Program Files\7-Zip\7z.exe' x '<받은_zip_경로>' -o'<압축_풀_폴더>' -p<비밀번호>
& 'C:\Program Files\7-Zip\7z.exe' x '<받은_zip_경로>' -o'<압축_풀_폴더>' -p<비밀번호>
#   -o / -p 와 값 사이에 공백 없음. "CRC failed"/"Data error" 가 나오면 압축
#   파일이 다운로드 중 잘린 것 → 재다운로드.
```

> ⚠ Defender 끄기는 **격리 VM 에서만**, 테스트 후 반드시 스냅샷 복원. 종료된
> PID 가 브라우저가 아니라 검체인지 콘솔 로그로 확인하세요.

**7) 집계** — 디스크 영속 데이터만 읽어 성적을 냅니다(BSOD 나도 동작). 스냅샷
복원 전에 실행.

```powershell
python postmortem.py --watch C:\Users\you\Documents --out postmortem.md
```

**8) 스냅샷 복원** — 5단계 지점으로 되돌립니다. **검체가 묻은 VM 은 재사용 금지.**

> **재테스트 체크리스트:** preflight 로 디코이 채우기 → 브라우저 등 종료 →
> Defender 비켜주기 → 검체 실행 → 잡힌 게 브라우저(msedge/chrome)가 아니라 진짜
> 검체인지 확인. responder 로그에 `observed only (no corroboration)` 로만 남고
> 종료 안 된 항목은 정상(오탐 후보를 흘려보낸 것)입니다.

---

## 제거 (Uninstall)

```powershell
.\scripts\uninstall_driver.ps1
Remove-Item -Recurse -Force .\.venv
```

---

## 안전 안내 (Safety)

- **Responder 는 프로세스를 진짜로 종료합니다.**
  자동화 랩에서는 기본값 `kill` 모드가 적합하지만, 일반 데스크톱에서는
  임계값 튜닝 동안 `--mode quarantine` 을 권장해요.
- `responder.py:NEVER_KILL` 의 하드 절대-안-죽이는 목록은 `lsass`, `csrss` 등
  시스템 핵심 프로세스를 보호합니다. **이 목록을 절대 완화하지 마세요.**
  (lsass 죽이면 BSOD)
- **시뮬레이터는 실제 사용자 데이터가 있는 머신에서 절대 돌리지 마세요.**
  더미 파일을 고엔트로피 노이즈로 덮어씁니다.

---

## 미구현 / 향후 과제 (Known gaps)

- **Authenticode 화이트리스트 없음.**
  Responder 가 이론적으로는 노이즈가 많아 보이는 서명된 정상 프로세스를
  종료할 수 있어요. 첫 배포 시 `--mode` 를 신중히 고르고 responder 로그를 모니터링하세요.
- **미니필터는 관찰만, 디스크에 컨텍스트 저장 X.**
  사후 포렌식용 디스크 기록은 없어요. SQLite 이벤트 스토어를 활용하세요.
- **Intermittent encryption (몇 시간에 걸쳐 천천히 쓰는 방식) 미대응.**
  120초 채점 윈도우로는 잡히지 않습니다.

---

## 추가 자료

- 영문 README: [`README.en.md`](./README.en.md)
- 상세 위키 (한글): [`docs/WIKI.ko.md`](./docs/WIKI.ko.md)
- 상세 위키 (영문): [`docs/WIKI.en.md`](./docs/WIKI.en.md)
- 산출물 문서: [`docs/deliverables/`](./docs/deliverables/)
