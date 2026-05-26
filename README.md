# RansomGuard EDR (Windows 11)

> 🌐 영문 버전: [README.en.md](./README.en.md)

Windows 11용 **랜섬웨어 전용 소형 EDR** 입니다.
커널 모드 **파일시스템 미니필터** 와 사용자 모드 **행동 기반 탐지기들** 을
조합하고, 점수가 임계치를 넘는 순간 의심 프로세스를 **격리(quarantine)** 하거나
**즉시 종료(kill)** 할 수 있는 **자동 대응(active responder)** 까지 갖췄어요.

> ⚠️ **이건 연구/학습용 프로토타입입니다.**
> 본인 소유의 머신, 가급적이면 격리된 VM에서만 돌리세요.
> 드라이버를 로드하려면 테스트 서명이 활성화돼 있거나 정식 서명된 카탈로그가 있어야 합니다.

---

## 🎯 한 줄 요약

> "**랜섬웨어가 본격적으로 파일을 잠그기 직전의 사전 행동들** 을
> 커널·사용자 모드 양쪽에서 감지해서, 점수가 임계치를 넘으면
> **그 프로세스를 자동으로 차단/종료** 하는 방어 도구."

---

## ✨ 주요 기능 (Features)

| 분류 | 설명 |
|---|---|
| 🧠 **커널 미니필터** | `minifilter/RansomGuard.sys` 드라이버가 모든 볼륨에서 `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` 을 가로채요. `(pid, path, op, bytes)` 형식 이벤트를 필터 통신 포트로 사용자 모드에 스트리밍하고, 격리된 PID 의 후속 쓰기/이름변경을 **커널 안에서 차단** 합니다. |
| 💥 **PID 단위 폭발 감지** | minifilter_bridge 가 PID 별로 쓰기 바이트와 rename 횟수를 누적해요. 짧은 시간 안에 폭증하면 어느 폴더든 상관없이 HIGH 신호 발생. |
| 🪤 **카나리 파일** | 사용자가 절대 안 건드릴 미끼 파일을 깔아두고 해시로 감시. 변경 시 **단발로 CRITICAL** 발사. |
| 🎤 **프로세스 명령어 룰** | VSS 섀도카피 삭제, BCD 변조, Defender 비활성화, 로그 삭제, BitLocker 해제, 흔한 PowerShell 난독화 패턴 등 22개 룰. |
| 👥 **프로세스 트리 휴리스틱** | LOLBin 부모-자식 체인(Office → PowerShell, 브라우저 → 스크립트 호스트), 한 부모가 짧은 시간 안에 자식을 다수 spawn 하는 fan-out, psutil 기반 디스크 쓰기 burst. |
| ⚡ **자동 대응 (Active Responder)** | 3가지 모드 — `off` / `quarantine` / `kill`. `kill` 모드에서 PID 가 명시된 HIGH/CRITICAL 신호가 발생하면 즉시 커널 격리 + `TerminateProcess`. **lsass, csrss 같은 시스템 핵심 프로세스는 절대 안 죽이는 하드코딩 목록** 으로 보호. |
| 🖥️ **Flask 대시보드** | `http://127.0.0.1:5000` — 실시간 점수, 최근 이벤트, 프로세스 목록, 자동 대응 로그, 수동 kill/release 버튼. |

---

## 🏗️ 동작 구조 (Architecture)

> 큰 그림: **커널이 모든 파일 작업을 가로채서** → 사용자 모드로 보내고 → 탐지기들이 점수 매기고 → 임계 넘으면 자동 대응.

```
                       +-----------------------------+
                       |     RansomGuard.sys         |  (커널 미니필터)
                       |  IRP 파일 작업 · Ps 콜백    |
                       |  Cm 콜백      · Ob 콜백     |
                       +--------------+--------------+
                                      | 필터 포트 (\RansomGuardPort)
                                      v
   +-----------------+      +---------------------+      +-------------------+
   |  사용자 모드    |      |  minifilter_bridge  |      |    responder      |
   |  탐지기:        |      |  (ctypes -> fltlib) |<---> |  - 격리           |
   |   canary        |----->+----------+----------+      |  - 종료           |
   |   mass_io       |                 |                 +---------+---------+
   |   process_*     |                 v                           |
   +--------+--------+      +---------------------+                |
            |               |  process_kernel     |                |
            |               |  registry_kernel    |                |
            |               +----------+----------+                |
            |                          |                           |
            +-----------+------------- v --------------------------+
                        v       +---------------------+
                 +------+-----+ |   ScoringEngine     |<--+
                 |   tamper   | |   (120초 윈도우)    |   |
                 +------------+ +----------+----------+   |
                                           |              |
                                           v              |
                                +---------------------+   |
                                |  EventStore (SQLite)|   |
                                +----------+----------+   |
                                           |              |
                              +------------+------------+ |
                              v                         v |
                +---------------------+    +---------------------+
                |   Flask 대시보드    |    |   incident_report   |
                +---------------------+    |  (마크다운 + 알림)  |
                            ^              +---------------------+
                            |
                            +--- watchdog_service (헬스체크 / 재시작)
```

### 🔑 핵심 아이디어: 점수 누적 방식

신호 하나로 결론 내지 않아요. **120초 슬라이딩 윈도우** 안의 모든 신호 점수를
합산해서 등급을 판정합니다.

| 점수 | 등급 | 의미 |
|---|---|---|
| 0~29 | INFO | 정상 |
| 30~59 | LOW | 약간 의심 |
| 60~99 | MEDIUM | 주의 |
| 100~149 | HIGH | 위험 |
| 150+ | CRITICAL | 즉시 대응 |

오래된 신호는 2분 뒤 자동으로 사라져서 "옛날 일 때문에 계속 경보 울리는" 일이 없어요.

---

## 📁 파일 구성 (Components)

| 파일 | 역할 |
|---|---|
| `minifilter/RansomGuard.c` | 커널 미니필터 드라이버 (C, 1,274 줄) |
| `minifilter/RansomGuard.h` | 커널↔사용자 공유 이벤트/명령 레이아웃 |
| `detectors/minifilter_bridge.py` | 사용자 모드 다리 (`ctypes` → `fltlib.dll`) |
| `detectors/canary.py` | 카나리 파일 SHA-256 트립와이어 |
| `detectors/mass_io.py` | watchdog 기반 대량 I/O + 엔트로피 + 매직바이트 |
| `detectors/process_cmdline.py` | WMI 기반 프로세스 생성 룰 (VSS/BCD/Defender 등) |
| `detectors/process_watcher.py` | psutil 폴링, LOLBin 체인, fan-out |
| `detectors/process_kernel.py` | 커널 콜백 기반 프로세스 생성 탐지 (WMI 미사용) |
| `detectors/registry_kernel.py` | 커널 콜백 기반 레지스트리 쓰기 탐지 |
| `scoring.py` | 가중치 + 시간 윈도우 신호 합산 |
| `responder.py` | 의심 PID 격리 + 종료 |
| `incident_report.py` | 마크다운 사건 보고서 + 데스크톱 알림 |
| `tamper.py` | Critical-process 플래그 + DACL 강화 |
| `event_store.py` | SQLite 영속화 |
| `dashboard/app.py` | Flask UI + `/api/*` |
| `service.py` | Windows 서비스 호스트 (`RansomGuardAgent`) |
| `watchdog_service.py` | Agent 가 hang 되면 재시작하는 사이드카 서비스 |

---

## 💻 실행 환경 (Requirements)

- **OS:** Windows 11 (22H2 이상), x64
- **사용자 모드:** Python 3.10+ x64
- **커널 빌드:** Visual Studio 2022 Build Tools (C++ 워크로드) + Windows Driver Kit (WDK 10.0.26100 이상)
- **드라이버 로드:** 테스트 서명 활성화 또는 `RansomGuard.sys` 정식 서명 카탈로그

> 💡 **드라이버 없이도 사용자 모드 에이전트만 단독 실행 가능** 합니다.
> 단, 커널 레벨 파일 I/O 신호는 못 받아요 (그 부분만 동작 안 함).

---

## 📥 설치 (Install)

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
를 호출해서 `minifilter\build\x64\Release\RansomGuard.sys` 와 `.inf`, `.cat` 을
생성합니다.

WDK 나 VS Build Tools 가 없으면 스크립트가 **무인 설치하지 않고** 정확한
`winget` 명령을 출력해줘요 (수 GB 다운로드를 갑자기 시작하지 않으려고).

---

## 🚀 실행 방법 (Run)

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

### 대시보드 API

| 메서드 | 경로 | 용도 |
|---|---|---|
| `GET` | `/api/status` | 현재 점수, 등급, 최근 신호, responder 상태 |
| `GET` | `/api/heartbeat` | `watchdog_service` 가 사용하는 헬스체크 (200 OK) |
| `GET` | `/api/events` | 최근 100개 영속화된 신호 |
| `GET` | `/api/processes` | watcher 의 실시간 프로세스 스냅샷 |
| `GET` | `/api/actions` | Responder 행동 로그 |
| `GET` | `/api/reports` | `--reports-dir` 아래 사건 보고서 목록 |
| `GET` | `/api/reports/<filename>` | 개별 사건 보고서 조회 |
| `POST` | `/api/kill` | 수동 종료 — `{ "pid": 1234, "reason": "..." }` |
| `POST` | `/api/release` | 격리된 PID 해제 — `{ "pid": 1234 }` |
| `POST` | `/api/reset` | 채점 윈도우 초기화 |

---

## ✅ 테스트 / 검증 (Validation)

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

> 🍎 **macOS / Linux 에서도 일부 작동:** 카나리, mass_io, 시뮬레이터의 cmdline 인젝션은
> Mac/Linux 에서도 동작합니다. 커널 드라이버·WMI·tamper 같은 Windows 전용 기능은
> graceful 하게 idle 상태로 들어가요.

---

## 🗑️ 제거 (Uninstall)

```powershell
.\scripts\uninstall_driver.ps1
Remove-Item -Recurse -Force .\.venv
```

---

## ⚠️ 안전 안내 (Safety)

- **Responder 는 프로세스를 진짜로 종료합니다.**
  자동화 랩에서는 기본값 `kill` 모드가 적합하지만, 일반 데스크톱에서는
  임계값 튜닝 동안 `--mode quarantine` 을 권장해요.
- `responder.py:NEVER_KILL` 의 하드 절대-안-죽이는 목록은 `lsass`, `csrss` 등
  시스템 핵심 프로세스를 보호합니다. **이 목록을 절대 완화하지 마세요.**
  (lsass 죽이면 BSOD)
- **시뮬레이터는 실제 사용자 데이터가 있는 머신에서 절대 돌리지 마세요.**
  더미 파일을 고엔트로피 노이즈로 덮어씁니다.

---

## 🚧 미구현 / 향후 과제 (Known gaps)

- **Authenticode 화이트리스트 없음.**
  Responder 가 이론적으로는 노이즈가 많아 보이는 서명된 정상 프로세스를
  종료할 수 있어요. 첫 배포 시 `--mode` 를 신중히 고르고 responder 로그를 모니터링하세요.
- **미니필터는 관찰만, 디스크에 컨텍스트 저장 X.**
  사후 포렌식용 디스크 기록은 없어요. SQLite 이벤트 스토어를 활용하세요.
- **Intermittent encryption (몇 시간에 걸쳐 천천히 쓰는 방식) 미대응.**
  120초 채점 윈도우로는 잡히지 않습니다.

---

## 📚 추가 자료

- 영문 README: [`README.en.md`](./README.en.md)
- 상세 위키 (한글): [`docs/WIKI.ko.md`](./docs/WIKI.ko.md)
- 상세 위키 (영문): [`docs/WIKI.en.md`](./docs/WIKI.en.md)
- 산출물 문서: [`docs/deliverables/`](./docs/deliverables/)
