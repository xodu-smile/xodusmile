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

검체를 터뜨리기 전후로 두 보조 도구를 씁니다.

**detonate 전 — 준비 점검 (`scripts/lab_preflight.ps1`)**

격리 상태를 점검하고 GO / NO-GO 를 출력합니다. BLOCKER(물리 머신, 진짜 인터넷
도달, 스냅샷 미확인)가 하나라도 있으면 `exit 1` 로 막습니다.

```powershell
# 관리자 PowerShell, 격리 VM 안에서
.\scripts\lab_preflight.ps1 -WatchDir C:\Users\you\Documents -Count 500
```

점검 항목: VM 여부 · 네트워크 격리 · 호스트 공유 채널 · testsigning · 드라이버/
에이전트 로드 · 디코이 더미 파일 생성 · 스냅샷 확인(직접 타이핑).

**detonate 후 — 성적 집계 (`postmortem.py`)**

에이전트가 죽거나 BSOD 가 나도 동작하도록, 디스크에 영속된 데이터(`detector.db`,
`reports/`, watch dir)만 읽어 결과를 집계합니다.

```powershell
# 스냅샷 복원 전에 실행
python postmortem.py --watch C:\Users\you\Documents --out postmortem.md
```

출력: 탐지/대응 지연 타임라인 · 탐지기·심각도 분포 · quarantine/kill 집계 ·
디코이 손상 비율(= 탐지 전 피해량) · 첫 대응 이후 추가 손상 · 랜섬노트 후보.

**전체 흐름**

```powershell
python agent.py --watch C:\Users\you\Documents                 # 1) 에이전트 (변조 방지 ON)
.\scripts\lab_preflight.ps1 -WatchDir C:\Users\you\Documents   # 2) GO 확인 → VM 스냅샷
#                                                              # 3) 검체 detonate (격리 VM)
python postmortem.py --watch C:\Users\you\Documents --out postmortem.md  # 4) 집계
#                                                              # 5) 스냅샷 복원
```

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
