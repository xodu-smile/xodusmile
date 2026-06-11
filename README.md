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

탐지는 **커널 드라이버 1개 + 사용자 모드 탐지기 8종**이 담당하고, 모든 신호는
하나의 점수 엔진(120초 슬라이딩 윈도우)에 합산됩니다. 임계를 넘으면 responder
가 격리/종료로 대응하고, 사건은 비전문가도 읽을 수 있는 한글 보고서로 자동
정리됩니다.

### 탐지 (Detection)

| 탐지기 | 구체 동작 |
|---|---|
| **커널 미니필터** (`minifilter/RansomGuard.sys`) | 모든 볼륨에서 `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` 을 가로채 `(pid, path, op, bytes)` 이벤트를 필터 통신 포트로 사용자 모드에 스트리밍. 파일 I/O 외에 **프로세스 생성/종료**(`PsSetCreateProcessNotifyRoutineEx`)와 **레지스트리 쓰기**(`CmRegisterCallbackEx`)도 같은 채널로 올립니다. 격리된 PID 의 후속 쓰기/이름변경은 pre-op 에서 **커널 안에서 차단**. |
| **PID 단위 폭발 감지** (`minifilter_bridge`) | 커널 이벤트를 PID 별로 누적 — **4초 안에 75MB+ 쓰기** 또는 **5초 안에 rename 20회+** 면 HIGH(`kernel_write_burst`/`kernel_rename_burst`). 경로가 아니라 **프로세스 기준**이라 감시 폴더 밖에서 진행되는 암호화도 잡습니다. |
| **커널 프로세스 감시** (`process_kernel`) | WMI 없이 커널 콜백으로 프로세스 생성 **순간**(첫 명령 실행 전)에 cmdline 룰 33개를 적용. 커맨드라인을 커널 메모리에서 받으므로 **PEB 변조로 숨길 수 없고**, WMI(50~500ms 지연, 부하 시 유실)가 놓치던 단명 프로세스도 포착. |
| **커널 레지스트리 감시** (`registry_kernel`) | 고가치 키 변조를 채점: Defender 서비스(`WinDefend`/`WdFilter`/`Sense`)·설정·정책 키, SafeBoot, Run/RunOnce 지속화, System 정책(UAC/SmartScreen), 그리고 **RansomGuard 자신의 서비스 키**(드라이버 언로드 시도 = 자기 보호). ctfmon 의 `internat.exe`, Defender 자체 텔레메트리 같은 알려진 정상 쓰기는 값 이름 단위로 제외해 오탐을 막습니다. |
| **프로세스 명령어 룰 (33개)** (`process_cmdline`) | WMI + 커널 이중 소스로 새 프로세스의 cmdline 을 정규식 검사. VSS 섀도카피 삭제·리사이즈, BCD 변조, Defender/SmartScreen 무력화, 이벤트 로그·USN 저널 삭제, 방화벽 차단, BitLocker 해제에 더해 — **내장/서명 도구를 암호화 엔진으로 악용**하는 living-off-the-land 룰: `cipher /e`(EFS), BitLocker 강제 암호화(`manage-bde -on`/`Enable-BitLocker`), LOLBin 프록시 실행(`certutil`/`bitsadmin`/`esentutl`/`wmic process call create`), BYOVD(`sc create type=kernel`), 이중 갈취 스테이징(`7z -p`/`rclone`), 난독화 PowerShell(인코딩 커맨드·인메모리 다운로더·정책 우회). |
| **협박문 탐지 (내용 기반)** (`ransom_note`) | 파일명 패턴 12종(`HOW_TO_DECRYPT*`, `_readme.txt` 등)**에 더해 파일 내용을 분석** — 암호화폐 지갑 주소(BTC/ETH/XMR)·`.onion` 주소는 *강* 지표, 협박 문구·복호화 안내·결제 용어·연락 채널·압박 문구는 *약* 지표. **강 지표 1개 이상 + 합계 3점 이상**이어야 "내용 확인"으로 인정 → **이름이 무작위인 협박문(`A7F3C.txt`)도 내용으로 탐지**. 내용 확인 단일 노트는 HIGH, 이름만 매칭은 MEDIUM 힌트. **CRITICAL 확산 판정**: 내용 확인 노트가 60초 안에 3개 디렉터리 이상, 또는 이름 매칭 노트 3개 디렉터리 + 실제 암호화 활동 동반. 64KB 초과 파일·심볼릭 링크는 제외. |
| **카나리 파일** (`canary`) | 정렬 시 맨 앞/뒤로 가는 미끼 파일 5종(`!!_DO_NOT_TOUCH_!!.docx` 등)을 감시 폴더마다 배치하고 SHA-256 으로 1.5초 폴링. 변조/삭제 시 **단발로 CRITICAL**. 트립 후 30초간 **교차 부스트**: mass_io 엔트로피 기준 7.5→6.8 완화 + 가중치 1.5배, 협박문 단일 노트도 CRITICAL 로 승격. |
| **대량 I/O 분석** (`mass_io`) | 변경된 파일의 머리 4KB 를 Shannon 엔트로피(≥7.5) + 매직바이트 10종(PE/PDF/Office/ZIP/JPEG …)으로 검사. 신호: **매직바이트 소실**(HIGH — 알려진 형식이 알 수 없는 바이트로), **고엔트로피 쓰기**(MEDIUM), **랜섬 확장자 rename**(HIGH — `.encrypted`/`.lockbit` 등), 암호화 특징 이벤트가 **10초에 15건+ 모이면 burst**(HIGH). |
| **프로세스 트리 휴리스틱** (`process_watcher`) | psutil 폴링 기반: LOLBin 부모-자식 체인(Office→PowerShell, 브라우저→스크립트 호스트), **5초 안에 자식 12개+ fan-out**, **2초 안에 50MB+ 디스크 쓰기 burst**, 그리고 **시스템 바이너리 위장 탐지** — `%TEMP%\svchost.exe` 처럼 핵심 시스템 이름을 달고 System32 밖에서 실행되는 사칭(T1036.005)을 즉시 채점. |

### 점수·신뢰 모델 (Scoring & trust)

| 기능 | 설명 |
|---|---|
| **윈도우 합산** | 단일 신호로 결론 내지 않고 **120초 윈도우** 안의 가중치를 합산해 INFO→CRITICAL 5등급 판정. 오래된 신호는 자연 감쇠. |
| **Actor 신뢰 2단계** (`actor_trust`) | 신호를 낸 프로세스의 **디스크 이미지 경로를 검증**해 신뢰를 판정(이름만으론 불가 — `C:\Temp\MsMpEng.exe` 는 탈락). FULL(Defender/서비싱/WMI — 모든 활동 면제) 과 REGISTRY_ONLY(svchost — 레지스트리만 면제, **대량 파일 변조는 여전히 채점**) 를 구분해, svchost 에 숨은 랜섬웨어를 놓치지 않으면서 부팅 직후 OS 하우스키핑이 CRITICAL 을 찍던 인플레를 제거. 경로 조회 실패 시 **불신(fail-closed)**. |
| **신뢰 게이트 사각지대 차단** | 카나리 변조·매직바이트 소실·랜섬 확장자 변경·협박문 확산·커널 차단 사건 같은 *지상 진실(ground-truth)* 암호화 증거는 **actor 가 신뢰여도 항상 채점** — 신뢰 프로세스가 이런 행위를 하면 그게 곧 인젝션(T1055)/위장(T1036)의 증거이기 때문. |
| **상관 게이트** | `file_delete` 같은 흔한 정상 행위는 단독으로 0점 — **같은 PID 가 실제 암호화 활동을 보일 때만** 가중. 휴리스틱 신호도 암호화 활동과의 상관으로만 의미를 가짐. |
| **위협 등급 자동 복구** | responder 가 PID 를 종료하면 그 PID 의 신호를 라이브 점수 윈도우에서 즉시 제거(`forget_pid`) — 모든 활성 위협이 제거되면 대시보드가 **수동 초기화 없이 스스로 "안전"으로 복귀**. 다른 PID(제2의 공격자)의 점수와 영구 감사 기록(SQLite/보고서)은 그대로. |

### 자동 대응 (Active Responder)

| 기능 | 설명 |
|---|---|
| **3가지 모드** | `off`(관찰만) / `quarantine`(커널이 파일 I/O 차단) / `kill`(차단 + `TerminateProcess`, 기본값). 대시보드에서 런타임 전환 가능. |
| **표적 대응 (no score-sweep)** | **PID 를 지목한 HIGH/CRITICAL 신호에만** 반응 — 합산 점수가 높다고 윈도우의 모든 PID 를 쓸어버리지 않습니다. CRITICAL 은 즉시 행동, **HIGH 휴리스틱은 corroboration 요구**(같은 윈도우의 실제 암호화 활동, 또는 제2의 탐지기가 같은 PID 지목). 미충족이면 `observed only` 로 기록만 — 운영자가 대시보드에서 판단. |
| **부모 에스컬레이션** | 파괴 행위는 보통 일회성 LOLBin(vssadmin/powershell/cmd 등 19종)으로 실행되므로, 그 도구만 죽이면 늦거나 거부됩니다 → **명령을 내린 부모(랜섬웨어 본체)까지 함께 종료**. |
| **Never-kill 보호 목록** | OS 핵심·브라우저·UI·개발 도구 등 **47개 프로세스는 하드코딩으로 절대 종료 금지**. 그중 핵심 시스템 바이너리 19종은 **경로 검증** — System32 밖에서 그 이름을 사칭하면 면제권 박탈. |
| **행동 시점 포렌식 캡처** | 종료 직전에 이미지 경로·소유 계정·부모 PID/이름·트리거 신호·당시 점수/등급을 캡처(죽고 나면 못 얻음). 이미지 SHA-256 은 **격리/종료가 끝난 뒤** 계산해 차단 지연 0. |

### 보고·포렌식 (Reporting & forensics)

| 기능 | 설명 |
|---|---|
| **SQLite 이벤트 스토어** | 모든 신호를 `detector.db` 에 영속화(타임스탬프·탐지기·가중치·당시 점수/등급). INFO 신호는 DB 에만 기록하고 콘솔은 생략(노이즈 차단). |
| **한글 인시던트 보고서** | 대응 액션마다 **비전문가용 한글 마크다운 보고서** 자동 생성 — 무슨 프로그램이 무슨 행동을 해서 무엇을 했는지 풀어 설명, 명령줄 해설, ATT&CK 기법, 피해 범위 집계 포함. 동일 상태는 60초 윈도우로 dedup. |
| **통합(campaign) 보고서** | 마지막 인시던트로부터 **120초 안에 이어지는 사건들을 하나의 공격으로 묶어** 통합 보고서 생성 — 다중 PID 공격이 보고서 수십 장으로 흩어지지 않음. 점수 윈도우가 비면 자동 확정. |
| **디스크 실측 피해 검증** | 보고서의 피해 집계를 신호 메타데이터로만 추정하지 않고 **실제 디스크에서 확인**(`verify_damage_on_disk`). 별도 도구 `scan_damage.py` 는 **디코이 없이도** 의심 확장자·매직바이트로 감시 트리의 피해를 사후 스캔. |
| **Postmortem 도구** | `postmortem.py` 가 디스크 영속 데이터(DB+보고서+디코이)만 읽어 타임라인·탐지→대응 지연·디코이 생존율을 집계 — **에이전트가 BSOD 로 죽었어도 동작**. |
| **데스크톱 알림** | 프로세스 종료 시 토스트 알림(30초당 최대 3개로 폭주 방지). |

### 운영·기업 기능 (Operations & enterprise)

| 기능 | 설명 |
|---|---|
| **운영자 허용 목록** | 정상 백업/동기화/압축 앱(Veeam, Acronis, 7-Zip 등)을 프로세스 이름 또는 경로 접두사로 등록해서 **오탐 방지**. 카나리/협박문 확산처럼 높은 신뢰도 신호는 여전히 탐지. 대시보드에서 편집 가능. |
| **MITRE ATT&CK 기법 태깅** | 모든 신호가 표준 ATT&CK 기법(T1486, T1490, T1055, T1218 등)으로 매핑. 보고서와 대시보드에 표기해서 SOC/IR 팀의 위협 인텔 연계 간편화. |
| **SIEM / Webhook 통합** | HIGH 이상 이벤트를 **CEF over syslog**(Splunk/QRadar/ArcSight/Sentinel) 와 **범용 JSON Webhook**(Slack/Teams/PagerDuty/SOAR)으로 비동기 전송. 외부 의존성 0, fail-open(통합 장애가 탐지를 멈추지 않음). |
| **대시보드 인증** | 토큰이 설정되면 상태 변경/관리자 엔드포인트(`/api/reset`, `/api/kill`, `/api/admin/*`)는 `X-API-Key` 또는 `Authorization: Bearer` 를 요구(상수시간 비교). watchdog 용 `/api/heartbeat` 는 항상 공개. `auth_required_for_reads` 로 읽기 API 까지 보호 가능. |
| **중앙 설정 파일** | `ransomguard.toml`/`.json` 로 정책(감시 경로·모드·통합·인증)을 일괄 배포(GPO/Intune/Ansible). 비밀(토큰/Webhook URL)은 환경변수 우선. |

### Flask 대시보드

`http://127.0.0.1:5000` — 한 화면에서 관제·대응·보고까지:

- **상태 히어로 배너**: 현재 위협 등급을 이모지+설명으로 즉시 표시, 차단/신호 카운터
- **실시간 점수 게이지 + 추이 스파크라인** (120초 윈도우와 동기)
- **이벤트 피드**: severity·탐지기 필터, 검색, 일시정지
- **인시던트 보고서 패널**: 보고서 목록 + **모달 뷰어(마크다운 렌더링) + PDF 저장**
- **대응 조치 감사 로그**: 트리거 신호·SHA-256/VT 링크·부모 프로세스·탐지→대응 지연
- **MITRE ATT&CK 기법 요약**, 프로세스 테이블(필터·위협 PID 하이라이트), 수동 kill/release
- **관리자 패널**: 시스템 상태 그리드(드라이버·감시 폴더·통합/인증 상태), 모드 전환, PID 별 위협 분석(ATT&CK 표시), 허용 목록 편집
- 다크(SOC)/라이트 테마 토글, 헤더 🔑 버튼으로 운영자 토큰(X-API-Key) 입력

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
또한 합산 전에 세 가지 게이트를 거칩니다 — **신뢰 actor 면제**(검증된 시스템
컴포넌트의 정상 활동은 0점), **상관 게이트**(`file_delete` 는 같은 PID 의 암호화
활동이 있을 때만 가중), **kill 후 자동 복구**(종료된 PID 의 신호는 윈도우에서
즉시 제거). 자세한 동작은 위 "점수·신뢰 모델" 표 참고.

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
| `--config <path>` | 정책 파일(`ransomguard.toml`/`.json`) 경로. 생략 시 작업 폴더에서 자동 탐색. **CLI 플래그 > 설정 파일 > 기본값** 순으로 우선. |
| `--watch <dir>` | 감시할 디렉토리 (여러 번 지정 가능). 기본: `./test_watch_dir` |
| `--mode {off,quarantine,kill}` | Responder 모드. 기본 `kill` |
| `--auth-token <token>` | 대시보드 API 토큰. **`RANSOMGUARD_AUTH_TOKEN` 환경변수나 설정 파일 사용 권장**(프로세스 목록 노출 방지). 설정 시 변경성/관리자 엔드포인트에 인증 요구. |
| `--allowlist <path>` | 운영자 허용 목록 JSON 파일 경로 (기본 `allowlist.json`). 신뢰하는 앱 등록으로 오탐 감소. |
| `--no-minifilter` | 커널 다리 비활성화 (사용자 모드만 사용) |
| `--no-dashboard` | Flask UI 시작 안 함 |
| `--port N` | 대시보드 포트 (기본 `5000`) |
| `--db PATH` | SQLite 경로 (기본 `detector.db`) |
| `--reports-dir PATH` | 마크다운 사건 보고서 저장 위치 (기본 `./reports`) |
| `--no-notify` | 프로세스 종료 시 데스크톱 알림 끄기 |
| `--no-tamper-protection` | `RtlSetProcessIsCritical` + DACL 강화 끄기 (개발 시 taskkill 가능하게) |
| `--watchdog-pid <PID>` | 동반 watchdog 의 PID. Agent 와 함께 커널 변조 방지 등록 |

> **환경변수(비밀 주입):** `RANSOMGUARD_AUTH_TOKEN`(대시보드 토큰),
> `RANSOMGUARD_WEBHOOK_URL`(Webhook 활성화+URL), `RANSOMGUARD_SYSLOG_HOST`(syslog
> 활성화+호스트). 환경변수는 항상 설정 파일을 덮어씁니다.

### 설정 파일 예시 (`ransomguard.toml`)

```toml
[general]
watch_dirs = ["C:\\Users"]
responder_mode = "kill"          # off | quarantine | kill
enable_minifilter = true

[dashboard]
host = "127.0.0.1"
port = 5000
auth_token = ""                  # 비우면 인증 비활성 — 운영에선 env 로 주입 권장
auth_required_for_reads = false  # true 면 읽기 API 도 토큰 요구

[syslog]                         # SIEM (CEF over syslog)
enabled = true
host = "siem.corp.local"
port = 514
protocol = "udp"                 # udp | tcp
min_severity = "HIGH"

[webhook]                        # Slack/Teams/PagerDuty/SOAR
enabled = true
url = "https://hooks.example.com/services/XXX"
min_severity = "CRITICAL"
```

> `.toml` 은 Python 3.11+(`tomllib`)에서 동작합니다. 3.10 이하면 같은 구조의
> `ransomguard.json` 을 쓰세요.

---

## 기업 배포 (Enterprise)

연구/학습용 단독 에이전트를 **실제 기업 환경 제품**으로 쓰기 위한 기능들입니다.

**이번 버전에 구현된 것:**

- **중앙 정책 파일** (`config.py`) — `ransomguard.toml`/`.json` 한 파일로 수백 대
  엔드포인트 정책을 일괄 배포. 비밀은 환경변수 우선(디스크에 토큰 미보존).
- **SIEM 통합** (`integrations.py`) — CEF over syslog. 모든 SOC 가 파싱하는 표준
  포맷으로 위협 이벤트를 중앙 SIEM 에 스트리밍.
- **알림/SOAR Webhook** — Slack/Teams/PagerDuty/SOAR 로 즉시 JSON 알림.
  비동기 워커 + fail-open 으로 탐지 핫패스를 절대 막지 않음.
- **대시보드 인증** — 무인증 관리자 API(보호 끄기/프로세스 종료/허용목록 편집)
  구멍을 토큰 인증으로 차단.
- **감사/포렌식** *(기존)* — SQLite 이벤트 스토어, 마크다운 사건 보고서,
  responder 액션 로그, ATT&CK 매핑.
- **고가용성/변조 방지** *(기존)* — watchdog 서비스 자동 재시작,
  `RtlSetProcessIsCritical`, DACL 강화, 커널 `ObCallback` 핸들 보호.

**완전한 기업 제품을 위해 추가로 필요한 것 (로드맵):**

- **중앙 관리 콘솔(fleet)** — 다수 에이전트의 상태/정책/경보를 한 화면에서
  관리하는 서버. 현재는 단말별 syslog/webhook 푸시까지 구현.
- **RBAC + SSO** — 대시보드 다중 사용자 역할(분석가/관리자), SAML/OIDC 연동.
  현재는 단일 토큰.
- **서명된 MSI 배포 + 자동 업데이트 채널** — winget/Intune 패키징, 단계적 롤아웃.
- **정책 원격 푸시 + 설정 드리프트 감지** — 중앙에서 정책 변경을 강제.
- **격리 파일 보관소 + 원클릭 복구** — VSS/백업 연계 롤백.
- **라이선싱/텔레메트리 옵트인**, **고객사별 멀티테넌시**.

---

## 테스트 / 검증 (Validation)

### 시뮬레이터와 데모

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

### 자동화 테스트

```powershell
# pytest 스위트 실행 (logic 레벨 단위 테스트)
pytest

# 또는 명시적으로
python -m pytest
```

저장소 루트에 `tests/` 폴더 하에 pytest 테스트 모음이 있습니다:
- `test_scoring.py` — 점수 엔진과 신호 가중치
- `test_attack_map.py` — MITRE ATT&CK 기법 매핑
- `test_allowlist.py` — 운영자 허용 목록 로직
- `test_mass_io.py` — 엔트로피/burst 탐지기
- `test_ransom_note.py` — 협박문 탐지기
- `test_responder.py` — 자동 대응(격리/종료)
- `test_incident_report.py` — 보고서 생성
- `test_dashboard_api.py` — Flask REST API

**주의**: Windows 의존 부분(psutil, WMI, Flask)은 비-Windows 에서 스킵되며,
순수 로직 부분은 모든 플랫폼에서 동작합니다. `pytest.ini` 와 `tests/conftest.py` 참고.

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
#   --> 6) 압축 해제하고 스냅샷 확인 후 검체를 직접 실행 <--
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

## 오탐 방지 (False Positives)

RansomGuard 는 여러 계층에서 오탐을 줄이도록 설계했습니다:

- **고엔트로피 데이터의 정상 포맷 제외**: `.zip`, `.rar`, `.7z`, `.jpg`, `.mp3`, `.mp4`, `.avi` 등
  **natively high-entropy 파일**은 정적 엔트로피 신호에서 제외됩니다. 정상적인 사진 편집,
  비디오 트랜스코딩, 아카이브 업데이트로 인한 오탐 감소. (이들이 실제로 암호화되면
  매직바이트 소실·확장자 변경 같은 *변화* 신호로 잡힙니다.)
- **노이즈 경로/확장자 제외**: 브라우저 캐시, 패키지 앱 캐시, `\Temp\`, `.tmp`/`.log`/`.etl`
  등 정상 프로그램이 끊임없이 쓰고 지우는 경로·확장자는 암호화 신호로 치지 않음.
- **협박문 판정 보수화**: 이름만 매칭된 단일 노트는 MEDIUM 힌트, 내용(암호화폐 주소·`.onion`
  등 강 지표 필수)으로 확인돼야 HIGH. CRITICAL 확산은 **60초 안에 3개 디렉터리 이상**
  + 내용 확인(또는 실제 암호화 활동 동반) 요구 → 정상 프로젝트의 `readme.txt` 두 개로
  최고 등급이 뜨던 v1 오탐 제거.
- **운영자 허용 목록**: 백업/압축/동기화 소프트웨어를 프로세스 **이름** 또는 **경로 접두사**로 명시 등록.
  경로 기반 등록은 이름 위장(`%TEMP%\veeamagent.exe` 같은 가짜) 방어.
  **단, canary 트립/협박문 확산 같은 고신뢰 단발 신호는 허용 목록으로도 면제 안 됨.**
- **신뢰 기반 점수 면제 (2단계)**: 검증된 이미지 경로의 시스템 프로세스(Defender, WMI,
  servicing)는 점수 가산 제외. svchost 는 레지스트리/하우스키핑만 면제되고 대량 파일
  변조는 여전히 채점 — 인젝션된 svchost 랜섬웨어 대비.
- **상관 게이트**: 단일 파일 삭제(`file_delete`) 같은 흔한 정상 행위는 같은 PID 의 실제
  암호화 활동이 동반될 때만 점수에 기여.
- **레지스트리 정상 값 필터**: ctfmon 의 `internat.exe` Run 키 갱신, Defender 자체
  텔레메트리 타임스탬프 등 라이브 런에서 관측된 정상 쓰기는 값 이름 단위로 제외.
- **Corroboration 없는 HIGH 는 기록만**: responder 는 단독 HIGH 휴리스틱에 행동하지 않고
  `observed only` 로 남깁니다 — 제2의 탐지기나 실제 암호화 활동이 확인될 때만 종료.

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

## MITRE ATT&CK 기법 매핑

모든 탐지 신호는 **표준 MITRE ATT&CK 기법**(T1486, T1490 등)으로 태깅됩니다.
대시보드 리포트와 관리자 패널에서 "T1486 Data Encrypted for Impact (임팩트)",
"T1490 Inhibit System Recovery (복구 무력화)" 같은 **표준 공격 기법명**을 확인할 수 있어요.
이를 통해 SOC/IR 팀이 내부 SIEM 룰, 위협 인텔, 외부 EDR 과 곧바로 연계 가능합니다.

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
- 캡스톤 결과 보고서: [`docs/CAPSTONE_REPORT.ko.md`](./docs/CAPSTONE_REPORT.ko.md)
- 설계 근거(신호 가중치·임계값): [`docs/DESIGN_RATIONALE.ko.md`](./docs/DESIGN_RATIONALE.ko.md)
- 산출물 문서: [`docs/deliverables/`](./docs/deliverables/)
