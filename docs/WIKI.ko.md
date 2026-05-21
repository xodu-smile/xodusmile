# RansomGuard EDR — 개발자 위키 (KO)

저장소의 모든 소스 파일에 대한 레퍼런스 — 무엇을 하는지, 어떤 공개
API를 노출하는지, 런타임에서 어디에 위치하는지를 정리한다. 영문
버전은 [`WIKI.en.md`](./WIKI.en.md) 참고.

---

## 1. 한눈에 보는 아키텍처

```
                  ┌─────────────────────────────────────────────┐
                  │                ScoringEngine                │
                  │  (슬라이딩 윈도우 가중치 합산)               │
                  └──┬───────────┬────────────────────────┬─────┘
                     │ submit()  │ subscribe(listener)    │
                     │           ▼                        ▼
   ┌─────────────────┴──┐  ┌─────────────┐   ┌──────────────────────┐
   │ Detectors          │  │ EventStore  │   │ ProcessResponder     │
   │  - canary          │  │ (SQLite)    │   │  - quarantine_pid    │
   │  - mass_io         │  └─────────────┘   │  - terminate         │
   │  - process_cmdline │                    └──────────┬───────────┘
   │  - process_watcher │                               │ on_action
   │  - minifilter      │◄──── 커널 이벤트 ───┐         ▼
   └────────────────────┘                     │   ┌────────────────┐
            ▲                                 │   │ IncidentReport │
            │                                 │   │  - .md 작성     │
            │                                 │   │  - 사용자 알림   │
   ┌────────┴────────┐                ┌───────┴───┐└────────────────┘
   │ Flask Dashboard │                │ RansomGuard│
   │  (브라우저 UI)  │                 │ minifilter │
   └─────────────────┘                │   (.sys)   │
                                      └────────────┘
```

시그널은 모두 `ScoringEngine` 으로 흘러 들어간다. 리스너는 셋이
달려 있다:

1. `Agent._on_signal` — 콘솔에 보기 좋게 출력하고 `EventStore` 에
   영구 저장.
2. `MassIODetector._on_engine_signal` — `canary` 트립을 감지하면
   이후 30초 동안 엔트로피/버스트 임계를 더 공격적으로 잡는다.
3. `ProcessResponder._dispatch` — PID 가 명시된 HIGH/CRITICAL 시그널이
   오면 커널 격리 후 프로세스를 종료한다. 또한 누적 점수가 CRITICAL
   임계를 넘으면 활성 윈도우 내 모든 PID 를 일제히 처리한다.

리스폰더는 모든 액션마다 `on_action(KillAction)` 을 호출한다.
`IncidentReporter` 가 이 훅을 사용해서 Markdown 인시던트 리포트를
작성하고 데스크톱 알림을 띄운다.

---

## 2. 저장소 구조

```
ransomware_detector/
├── agent.py                       # CLI 진입점 + 오케스트레이터
├── scoring.py                     # ScoringEngine, Signal, Severity
├── event_store.py                 # SQLite 영구 저장
├── responder.py                   # 격리 + 프로세스 종료
├── incident_report.py             # Markdown 리포트 + 알림
├── demo_inproc.py                 # 종단 데모(대시보드 없이)
├── __init__.py                    # 패키지 마커
├── detectors/
│   ├── __init__.py
│   ├── base.py                    # Detector ABC
│   ├── canary.py                  # Canary 파일
│   ├── mass_io.py                 # 파일 이벤트 버스트 + 엔트로피
│   ├── process_cmdline.py         # WMI + 정규식 룰셋
│   ├── process_watcher.py         # psutil 폴링, 부모-자식 체인
│   └── minifilter_bridge.py       # 유저모드 드라이버 클라이언트
├── dashboard/
│   └── app.py                     # Flask 앱(라우트 + JSON API)
├── tests/
│   └── simulator.py               # 안전한 행위 시뮬레이터
├── minifilter/
│   ├── RansomGuard.h              # 드라이버 ↔ 유저모드 계약
│   ├── RansomGuard.c              # 커널 minifilter
│   ├── RansomGuard.inf / .sln / .vcxproj
├── scripts/
│   ├── _common.ps1                # 공용 PS 헬퍼
│   ├── bootstrap.ps1              # Python + venv 설치
│   ├── build_driver.ps1           # MSBuild 래퍼
│   ├── install_driver.ps1         # .sys 적재 + 서비스 시작
│   ├── install.ps1                # bootstrap + 드라이버 일괄
│   └── uninstall_driver.ps1       # 드라이버 중지/제거
└── reports/                       # (런타임 생성) .md 인시던트
```

---

## 3. 최상위 Python

### 3.1 `agent.py`

CLI 진입점. 모든 구성요소를 연결하고 메인 루프를 돈다.

| API | 설명 |
|-----|------|
| `class Agent(watch_dirs, *, db_path, responder_mode, enable_minifilter, reports_dir, notify_user)` | 모든 디텍터, 스코어링 엔진, 이벤트 스토어, 리스폰더, 인시던트 리포터를 소유. |
| `Agent.start()` | Canary 배치 후 모든 디텍터 스레드 시작. |
| `Agent.stop()` | 디텍터 중지, canary 파일 정리. |
| `Agent.status()` | 점수+레벨+최근 시그널+리스폰더+인시던트 스냅샷 (`/api/status`에서 소비). |
| `Agent.processes(limit)` | `ProcessWatcher.snapshot` 패스스루. |
| `Agent._on_signal(sig, score, level)` | 출력 + 저장. |
| `parse_args()` / `main()` | CLI 옵션: `--watch`, `--db`, `--no-dashboard`, `--port`, `--mode`, `--no-minifilter`, `--reports-dir`, `--no-notify`. |

`python agent.py` 실행 흐름: `parse_args` → `Agent` 생성 →
`agent.start()` → 선택적으로 데몬 스레드에서 Flask 대시보드 기동 →
SIGINT/SIGTERM 핸들러 설치 → 종료 신호까지 idle → `agent.stop()`.

---

### 3.2 `scoring.py`

엔진의 뇌. 시간 윈도우 기반 가중치 합산과 이름 있는 임계값.

| API | 설명 |
|-----|------|
| `class Severity(str, Enum)` | `INFO < LOW < MEDIUM < HIGH < CRITICAL`. |
| `@dataclass Signal` | `detector, name, weight, severity, message, metadata, timestamp`. `metadata` 에 `pid`, `path` 등 추가. |
| `THRESHOLD_LOW=30, _MEDIUM=60, _HIGH=100, _CRITICAL=150` | 점수 경계. |
| `SIGNAL_WINDOW_SECONDS=120` | 슬라이딩 윈도우 길이. |
| `ScoringEngine.submit(signal)` | append → 만료 제거 → 모든 리스너에 `(signal, score, level)` 통지. |
| `ScoringEngine.subscribe(listener)` | 콜백 등록. 리스너 예외는 잡아두어 한 리스너의 실패가 엔진을 마비시키지 않게 한다. |
| `ScoringEngine.current_score()` / `current_level()` / `recent_signals(limit)` / `reset()` | 대시보드/리스폰더에서 사용. |

리스너 예외는 출력만 하고 전파하지 않는다 — 리스폰더가 PID 단위
작업에서 실패해도 엔진은 살아 있어야 하기 때문.

---

### 3.3 `event_store.py`

얇은 SQLite 래퍼. 스키마: `signals(id, timestamp, detector, name,
weight, severity, message, metadata, score_after, level_after)` +
`(timestamp DESC)` / `(severity)` 인덱스.

| API | 설명 |
|-----|------|
| `EventStore(db_path="detector.db")` | 파일/스키마 자동 생성. |
| `record(signal, score_after, level_after)` | 한 행 삽입. `metadata` 는 `json.dumps(default=str)` 로 직렬화 — 직렬화 불가 값은 예외 대신 문자열로. |
| `recent(limit=100)` | 최신순 N 개, metadata 는 dict 로 역직렬화. |
| `stats()` | `{total, by_detector, by_severity}`. |

호출당 새 connection + 전역 lock 으로 멀티스레드 쓰기에서 SQLite 가
안정적으로 동작하게 한다.

---

### 3.4 `responder.py`

능동 대응 컴포넌트. 스코어링 엔진을 구독하고, 누구를 격리/종료할지
판단·실행하고, `KillAction` 으로 기록한다.

| API | 설명 |
|-----|------|
| `class ResponderMode(str, Enum)` | `OFF, QUARANTINE, KILL`. |
| `NEVER_KILL = {…}` | 절대 죽이지 않는 목록 — OS 핵심 + `python.exe`/`py.exe`/`pythonw.exe`. |
| `@dataclass KillAction` | `timestamp, pid, process_name, cmdline, reason, mode, quarantined, terminated, error`. |
| `ProcessResponder(engine, *, mode, minifilter, critical_threshold, on_action)` | `on_action` 으로 `IncidentReporter` 가 연결된다. |
| `attach()` | 엔진 구독. 멱등. |
| `actions(limit=50)` | 대시보드용 이력. |
| `manual_kill(pid, reason)` / `manual_release(pid)` | 대시보드 버튼이 도달하는 곳. |
| `_dispatch(sig, score, level)` | (1) PID 가 있는 HIGH/CRITICAL 시그널 → `_respond_to_pid`; (2) 점수 ≥ CRITICAL → `_sweep_window`. |
| `_respond_to_pid(pid, reason)` | self-pid 거부 → never-kill 확인 → minifilter 격리 → `psutil.kill()` 후 ctypes `OpenProcess + TerminateProcess` 폴백. |
| `_record(action)` | append, 1000 으로 캡, 콘솔 출력, `on_action` 호출. |

Windows 종료 전략: 먼저 `psutil.kill()`, 그래도 안 끝나면 ctypes 로
`OpenProcess(PROCESS_TERMINATE) + TerminateProcess + CloseHandle` —
관리자 권한에서 psutil 캐시 이슈를 우회한다.

---

### 3.5 `incident_report.py`

`ProcessResponder.on_action` 훅. 실제 액션마다 Markdown 리포트 1개를
쓰고 데스크톱 알림을 띄운다.

| API | 설명 |
|-----|------|
| `@dataclass IncidentRecord` | 인덱스 엔트리 (`timestamp, pid, process_name, reason, terminated, quarantined, filename, path`). |
| `IncidentReporter(engine, *, reports_dir="reports", notify=True)` | 생성 시 리포트 디렉터리를 만든다. |
| `on_action(action)` | **No-op 은 스킵** (`terminated`/`quarantined` 모두 false). 마크다운 생성 → 파일 저장 → 이력 append → 알림 스레드 spawn. |
| `recent(limit=50)` | 최신순 `IncidentRecord` dict 리스트. |
| `read_report(filename)` | 경로 트래버설 방어 (`/`, `\`, `..`, reports_dir 탈출 거부). 파일 본문 또는 `None`. |
| `_build_markdown(action)` | 프로세스 헤더 → 응답 → 위협 컨텍스트 → 해당 PID 기여 시그널 → 최근 윈도우 → 원본 액션 JSON. |
| `_notify_user(action, path)` | 백그라운드 스레드; 플랫폼별 디스패치. |
| `_notify_linux` | `notify-send` subprocess. |
| `_notify_macos` | `osascript -e 'display notification …'`. |
| `_notify_windows` | `win10toast` → PowerShell `BurntToast` → `MessageBoxW` 폴백. |

파일명: `incident_<YYYYMMDD_HHMMSS>_pid<N>_<safe_name>.md`.

---

### 3.6 `demo_inproc.py`

단일 프로세스 종단 데모: `Agent` 부팅 → 더미 파일 배치 → 가짜
VSS/BCD 이벤트 주입 → canary touch → 암호화 시뮬레이션 → 통계 출력.
드라이버나 대시보드 없이 디텍터 동작을 검증할 때 쓴다.

---

### 3.7 `__init__.py`

빈 파일 — 저장소를 패키지로 인식시켜 `import scoring`,
`from detectors.base import …` 가 스크립트/모듈 양쪽에서 동작하게 한다.

---

## 4. Detectors

모든 디텍터는 `detectors.base.Detector` 를 상속하고, 데몬 스레드에서
동작하며, `self.emit(Signal(...))` 로 엔진에 시그널을 보낸다.

### 4.1 `detectors/base.py`

스레딩 스캐폴딩이 들어 있는 추상 베이스.

| API | 설명 |
|-----|------|
| `name: str = "base"` | 서브클래스가 override. |
| `__init__(engine)` | 엔진 보관 + 협력 취소용 `threading.Event`. |
| `start()` / `stop()` | 데몬 스레드 생성/조인(`stop` 은 3s 타임아웃). |
| `emit(signal)` | `engine.submit` 패스스루. |
| `_run_safe()` | `run()` 의 예외를 잡아 한 디텍터의 크래시가 다른 디텍터에 전파되지 않게. |
| `run()` *(abstract)* | 서브클래스 루프; `self._stop_event.is_set()` 을 주기적으로 확인. |

---

### 4.2 `detectors/canary.py`

각 감시 디렉터리에 "건드리지 마시오" 미끼 파일을 배치하고 1.5초마다
SHA-256 폴링. 삭제/내용 변경 시 CRITICAL 시그널 1개 (weight 80).

| 항목 | 설명 |
|------|------|
| `CANARY_FILENAMES` | 알파벳 정렬 시 맨 위/맨 아래로 가도록 설계. `!!_DO_NOT_TOUCH_!!.docx`, `0_important_notes.xlsx`, `00_archive_index.pdf`, `~$confidential_backup.docx`, `zzz_old_records.txt`. |
| `CANARY_WEIGHT = 80` | 한 번만 트립해도 HIGH 진입. |
| `CanaryDetector(engine, watch_dirs, poll_interval=1.5)` | 생성자. |
| `deploy()` | 없으면 작성, 베이스라인 해시 저장. |
| `cleanup()` | 종료 시 best-effort 삭제. |
| `run()` | 폴링; 불일치 시 `canary_modified` / `canary_deleted` emit 후 해시를 *갱신*해서 동일 변경이 연쇄 알람으로 폭주하지 않게. |

Canary 트립은 엔진 리스너를 통해 `MassIODetector` 에 크로스 시그널로
전달된다(4.3 참고) — 이후 30초간 mass_io 가 공격적으로 동작.

---

### 4.3 `detectors/mass_io.py`

유저모드 파일시스템 감시기 (`watchdog` 설치 시 그것을, 아니면 mtime
폴링 폴백). 시그널 3종 + fan-out 보너스:

| 시그널 | 가중치 | 심각도 | 발화 조건 |
|--------|--------|--------|-----------|
| `magic_bytes_lost` | 12 | HIGH | 이전엔 알려진 매직(PE/PDF/Office/JPEG 등)이었던 파일이 인식 불가로 변함. |
| `high_entropy_write` | 8 | MEDIUM | Shannon 엔트로피 ≥ 7.5 (canary boost 모드에선 ≥ 6.8), 매직 미인식, 타깃 확장자, 최초 관측 또는 Δ엔트로피 ≥ 2.5. |
| `suspicious_extension` | 5 × 3 | HIGH | `.encrypted/.locked/.wcry/…` 로 rename. |
| `modify_burst` | 25 + 20 × fanout | HIGH | 10s 안에 15개+ 파일 이벤트. 확장자 3종+ 또는 디렉터리 2개+ 일 때 +20씩. |

주요 상수: `BURST_WINDOW_SEC=10`, `BURST_THRESHOLD=15`,
`MAX_SAMPLE_BYTES=4096`, `MAX_TRACKED_FILES=20000` (대략적인 LRU
정리), `CANARY_BOOST_WINDOW=30s`, `CANARY_BOOST_MULTIPLIER=1.5`.

크로스 시그널: `_on_engine_signal` 은 `canary` 시그널을 받으면
`_canary_tripped_at = now()` 로 설정하고, 이후 30초간 `_boost(weight,
True)` 가 가중치를 1.5배 한다.

내부 `_Handler(FileSystemEventHandler)` 클래스는 watchdog 가 임포트될
때만 정의되며 `on_modified/on_created/on_moved` 를 디텍터로 위임한다.

---

### 4.4 `detectors/process_cmdline.py`

Win11 전용 WMI 프로세스 생성 구독자. 각 새 프로세스는 `RULES` —
정규식 기반 `Rule` 목록을 거친다:

- **VSS 삭제** — `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, PowerShell `Get-WmiObject … shadowcopy … Remove-…`.
- **BCD 조작** — `bcdedit … safeboot`, `recoveryenabled no`, `bootstatuspolicy ignoreallfailures`.
- **Defender / SmartScreen 무력화** — `Set-MpPreference -DisableRealtimeMonitoring`, `WinDefend/Sense/WdNisSvc/WdFilter` 서비스 stop, `Add-MpPreference -Exclusion*`, 레지스트리 편집, SmartScreen 비활성화.
- **Anti-forensics** — `wevtutil cl`, `Clear-EventLog`, `fsutil usn deletejournal`, `cipher /w`.
- **방어 인프라 종료** — `netsh advfirewall … state off`, `manage-bde -off`, `Disable-BitLocker`.
- **지속화** — `schtasks /create … /sc onlogon … /ru system`, Run/RunOnce 레지스트리 쓰기.
- **PowerShell 남용** — `-EncodedCommand <base64>`, 인메모리 다운로더, `-ExecutionPolicy bypass -WindowStyle hidden`.

| API | 설명 |
|-----|------|
| `@dataclass Rule` | `name, pattern, weight, severity, message`. |
| `RULES: List[Rule]` | 모듈 레벨 레지스트리 — 탐지 확장은 여기에 항목 추가. |
| `ProcessCmdlineDetector(engine)` | `wmi.WMI().Win32_Process.watch_for("creation")` 으로 구독. |
| `submit_external(process_name, cmdline, pid, ppid)` | 시뮬레이터 주입 진입점 (`simulate_vss_deletion` 이 사용). |
| `run()` | `pythoncom.CoInitialize` 후 `watcher(timeout_ms=1000)` 루프, `x_wmi_timed_out` 정상 처리. |
| `evaluate_cmdline(detector_name, process_name, cmdline, pid, ppid)` | 모듈 레벨 헬퍼 — `ProcessWatcher` 와 공유해서 WMI/psutil 양쪽 경로가 동일 룰을 적용. |

`wmi`/`pywin32` 미설치 환경에서는 경고만 출력하고 `_stop_event.wait()`
로 대기한다 — 나머지 에이전트는 정상 동작.

---

### 4.5 `detectors/process_watcher.py`

`psutil` 폴링 기반 감시기. WMI 가 놓치는 프로세스 보강, 부모-자식
LOLBin 체인 탐지, 단일 프로세스 I/O 버스트, 대시보드 프로세스 테이블
공급을 담당.

| API | 설명 |
|-----|------|
| `ProcSnapshot` dataclass | `pid, ppid, name, cmdline, user, started_at, cpu_percent, rss_bytes, write_bytes, last_seen`. |
| `SCRIPT_HOSTS` | LOLBin 스크립트 호스트 이름 (powershell, pwsh, cmd, wscript, cscript, mshta, regsvr32, rundll32, bitsadmin, certutil, msbuild, installutil). |
| `SUSPICIOUS_CHAINS` | `parent → set(child)` 매핑. Office, Adobe, 브라우저, explorer, OneDrive 등. |
| `ProcessWatcher.snapshot(limit=80)` | 최근 본 순으로 정렬된 dict 리스트 (`/api/processes` 용). |
| `run()` | 베이스라인 1패스(시그널 없음) → 1 Hz `_scan(initial=False)`. |
| `_on_new_process(snap)` | (1) `evaluate_cmdline` 룰 적용; (2) 부모-자식 체인 → `suspicious_parent_child` (weight 40, HIGH); (3) 동일 부모 fan-out → `child_fanout` (weight 30, MEDIUM), 5s 내 자식 12개+. |
| `_check_write_burst(...)` | `process_write_burst` (weight 20, MEDIUM) — 단일 프로세스가 2s 윈도우에 50MB+ 쓰기. |

자기 PID 는 건너뛰고, 사라진 PID 는 `_seen`/`_last_io` 에서 제거해
메모리 상한을 유지한다.

---

### 4.6 `detectors/minifilter_bridge.py`

`RansomGuard.sys` 커널 minifilter 의 유저모드 클라이언트.
`minifilter/RansomGuard.h` 의 바이너리 프로토콜을 그대로 사용.

| API | 설명 |
|-----|------|
| `class RG_EVENT(ctypes.Structure)` | 커널 `RG_EVENT` 패킷의 거울. |
| `RG_MESSAGE = FILTER_MESSAGE_HEADER + RG_EVENT` | `FilterGetMessage` 단일 버퍼 레이아웃. |
| `RG_COMMAND`, `RG_REPLY` | 격리/해제/ping 용 아웃바운드 컨트롤 패킷. |
| `_load_fltlib()` | `fltlib.dll` 로드 + `FilterConnectCommunicationPort/FilterGetMessage/FilterSendMessage` 바인딩. Windows 외/DLL 부재 시 `None`. |
| `MinifilterBridge.is_connected` | 포트 오픈 여부. |
| `quarantine_pid(pid)` / `release_pid(pid)` / `ping()` | `RG_COMMAND` 전송 후 `RG_REPLY.Status == 0` 확인. |
| `run()` | 지수 백오프 (1s → 30s) 재연결 루프. `_receive_loop` 에서 `FilterGetMessage` 블로킹, `Version == RG_PROTOCOL_VERSION` 검증 후 `_handle_event` 디스패치. |
| `_handle_event(evt)` | kind 별: `BLOCKED` → `kernel_blocked_op` (weight 60, HIGH); `WRITE` → `_account_write`; `SETINFO/RENAME` → `_account_rename`; `SETINFO/DELETE` → `file_delete` (LOW, weight 3); `CREATE` → 경로만 기록. |
| `_account_write(...)` | PID 별 슬라이딩 윈도우 (`PID_WRITE_BURST_BYTES=75 MB`, `WINDOW=4 s`). 트립 시 `kernel_write_burst` (weight 35, HIGH), 4s 디바운스. |
| `_account_rename(...)` | PID 별 슬라이딩 윈도우 (`PID_RENAME_BURST_COUNT=20`, `WINDOW=5 s`). `kernel_rename_burst` (weight 40, HIGH). |

드라이버 부재 시 브리지는 idle, 유저모드 디텍터만으로도 동작.

---

## 5. Dashboard — `dashboard/app.py`

`agent.py` 가 같은 프로세스에서 마운트하는 작은 Flask 앱.

| Route | Method | 용도 |
|-------|--------|------|
| `/` | GET | `templates/index.html` 렌더. |
| `/api/status` | GET | `agent.status()` JSON. |
| `/api/events` | GET | `EventStore` 최근 100개. |
| `/api/processes` | GET | `ProcessWatcher.snapshot(60)`. |
| `/api/actions` | GET | `ProcessResponder.actions(100)`. |
| `/api/reset` | POST | `engine.reset()`. |
| `/api/kill` | POST `{pid, reason?}` | `responder.manual_kill`. |
| `/api/release` | POST `{pid}` | `responder.manual_release`. |
| `/api/reports` | GET | `incident_reporter.recent(100)`. |
| `/api/reports/<filename>` | GET | Raw markdown 본문 (`text/markdown`), 미존재/트래버설 시 404. |

`create_app(agent)` 가 팩토리. 에이전트 스레드가
`use_reloader=False` 로 Flask 서버를 띄운다.

HTML 템플릿은 고정 위치 토스트 컨테이너를 두고 2.5s 마다
`/api/reports` 를 폴링; 새 항목은 토스트로 띄워 10s 후 자동 dismiss.

---

## 6. Tests — `tests/simulator.py`

안전한 행위 시뮬레이터. 실제 `vssadmin`/`bcdedit` 을 실행하지 않고
`ProcessCmdlineDetector.submit_external` 로 가짜 커맨드라인
이벤트만 주입한다.

| 함수 | 동작 |
|------|------|
| `populate_targets(directory, count=30)` | 현실적인 매직바이트를 가진 더미 `document_NNN.{docx,xlsx,pdf,jpg,txt}` 작성 — 엔트로피 디텍터 베이스라인 확보. |
| `simulate_encryption_pattern(directory, speed=0.05)` | 각 더미를 `os.urandom(size)` 로 덮어쓰고(고엔트로피) `<name>.encrypted` 로 rename. |
| `simulate_canary_touch(directory)` | 첫 canary 에 NUL 바이트 1개 append. |
| `simulate_vss_deletion(agent)` | cmdline 디텍터에 가짜 `vssadmin delete shadows /all /quiet` 주입. |
| `simulate_bcd_tamper(agent)` | 가짜 `bcdedit /set {default} recoveryenabled no` 주입. |
| `main()` | CLI: `--dir`, `--scenario {populate, encrypt, canary, vss, bcd, full, stealth}`, `--speed`. |

본인 격리 환경의 감시 디렉터리에서만 실행할 것. 타인 시스템 금지.

---

## 7. 커널 minifilter (C)

### 7.1 `minifilter/RansomGuard.h`

공유 계약. 드라이버와 `detectors/minifilter_bridge.py` 양쪽이 이
레이아웃을 포함 — 동기화 유지가 중요. 주요 정의:

- `RG_PORT_NAME = L"\\RansomGuardPort"`, altitude `385201`, 프로토콜 버전 `1`, 최대 경로 520 WCHAR.
- `RG_EVENT_KIND`: `RgEventCreate(1)`, `RgEventWrite(2)`, `RgEventSetInfo(3)`, `RgEventBlocked(4)`.
- `RG_SETINFO_KIND`: `Other/Rename/Delete`.
- `RG_EVENT` (`#pragma pack(4)`): `Version, Kind, SubKind, ProcessId, ThreadId, Status, WriteBytes (u64), TimestampNs (u64), PathLength, Path[520 WCHAR]`.
- `RG_COMMAND_KIND`: `RgCmdQuarantinePid(1)`, `RgCmdReleasePid(2)`, `RgCmdPing(3)`.
- `RG_COMMAND` / `RG_REPLY`: 컨트롤 플레인 구조체.

### 7.2 `minifilter/RansomGuard.c`

작은 minifilter — 로직은 커널 밖에 둔다.

**전역 상태** (`g_Rg`):
- `Filter`, `ServerPort`, `ClientPort` (리스너 1개만 허용).
- `ClientLock` (FAST_MUTEX) — 포트 보호.
- `QuarantineLock` (`EX_PUSH_LOCK`) — `QuarantinedPids[256]` 보호.
- `PerfFrequency` — 부팅 시 캐싱, ns 변환용.

**라이프사이클**:
- `DriverEntry` — `FltRegisterFilter` → 기본 SD 빌드 → `FltCreateCommunicationPort(RG_PORT_NAME, …, callbacks, max-connections=1)` → `FltStartFiltering`.
- `RgUnload` — 포트 close, unregister, push-lock 삭제.

**Operation 콜백** (`Callbacks[]` 가 `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` 등록):
- `RgPostCreate` — 유저모드 + 성공한 open 에 대해 `RgEventCreate` emit (드레인/커널 호출은 스킵).
- `RgPreWrite` — 요청 PID 가 격리 대상이면 `RgEventBlocked(Write)` emit 후 `STATUS_ACCESS_DENIED` 로 IRP 종료; 아니면 통과.
- `RgPostWrite` — 4096 바이트 이상 쓰기만 (서브 페이지는 throttle), `IoStatus.Information` 을 `WriteBytes` 로 실어 `RgEventWrite` emit.
- `RgPreSetInfo` — `Rename`/`Delete`/`Other` 분류. `Other` 스킵. 격리 PID 의 rename/delete 는 차단; 아니면 `sub` 를 `CompletionContext` 로 전달.
- `RgPostSetInfo` — 저장된 sub-kind 로 `RgEventSetInfo` emit.

**격리 비트맵** (`RgIsQuarantined`, `RgAddQuarantine`, `RgRemoveQuarantine`) — push-lock 아래 256 엔트리 선형 스캔. 용량 제한으로 커널 측은 단순/안전.

**포트 처리**:
- `RgPortConnect` — 두 번째 리스너 거부 (`STATUS_ALREADY_REGISTERED`).
- `RgPortDisconnect` — 포트 해제 + 격리 목록 클리어 (재연결 시 유저모드가 재구성).
- `RgPortMessage` — SEH 하에서 `ProbeForRead/Write`, `cmd.Kind` 디스패치.

**이벤트 emission** (`RgSendEvent`):
- non-paged pool 에서 `RG_EVENT` 할당 (tag `'GnsR'`).
- `ProcessId/ThreadId/Status/WriteBytes/TimestampNs` 채우고 `FltGetFileNameInformation`+`FltParseFileNameInformation` 으로 정규화 DOS 경로 복사.
- `FltSendMessage` **50 ms 타임아웃** — 유저모드가 막히면 IRP 를 멈추는 대신 이벤트를 버린다.

**Throttling 원칙**: 커널은 큐잉 안 함, 무제한 증가 안 함, 유저모드를
50 ms 이상 기다리지 않음. 무거운 상관 분석(엔트로피, fan-out,
커맨드라인 룰)은 전부 유저모드에서.

---

## 8. PowerShell 스크립트

### 8.1 `scripts/_common.ps1`

dot-source 헬퍼 모듈. `Set-StrictMode -Version Latest`,
`$ErrorActionPreference = 'Stop'`.

| 함수 | 용도 |
|------|------|
| `Test-Admin` / `Require-Admin` | 관리자 확인/요구. |
| `Write-Step`, `Write-Ok`, `Write-Warn2`, `Write-Err2` | 컬러 상태 출력 (cyan/green/yellow/red). |
| `Get-RepoRoot` | `$PSScriptRoot` 의 부모 해석. |
| `Test-Command(name)` | `Get-Command -ErrorAction SilentlyContinue` 래퍼. |
| `Invoke-CheckedExe -Exe ... -Args ...` | 실행 후 non-zero 종료 시 throw. |
| `Install-WithWinget -Id -DisplayName` | `winget install` + silent/auto-agree. |
| `Ensure-Python` | `py`/`python` 존재 시 반환, 없으면 winget 으로 Python 3.12 설치. |
| `Find-VsWhere` / `Find-MsBuild` | vswhere/MSBuild 위치 탐색. |
| `Test-WdkInstalled` | vswhere 로 WDK / Win11 SDK 컴포넌트 탐지. |

### 8.2 `scripts/bootstrap.ps1`

새 머신용 진입점. 파라미터: `-BuildDriver`, `-InstallDriver`,
`-SkipPython`. 단계:

1. `Ensure-Python` → 없으면 설치.
2. `.venv` 없으면 생성; `pip install --upgrade pip` 후 `pip install -r requirements.txt`.
3. `pywin32_postinstall -install` 실행 (실패 시 fail 대신 warn).
4. `-BuildDriver` / `-InstallDriver` 가 있으면 `build_driver.ps1` / `install_driver.ps1` 위임.

### 8.3 `scripts/install.ps1`

원라이너: `Require-Admin` 후
`bootstrap.ps1 -BuildDriver -InstallDriver`. 모든 단계를 한 번에
하고 싶을 때.

### 8.4 `scripts/build_driver.ps1`

`Find-MsBuild` → 없으면 winget 명령 안내 후 실패 →
`Test-WdkInstalled` (경고만) → `msbuild minifilter\RansomGuard.sln
/p:Configuration=Release /p:Platform=x64 /m /nologo`. 끝에
`RansomGuard.sys` / `.inf` 산출 여부 출력.

### 8.5 `scripts/install_driver.ps1`

관리자 전용. 빌드 산출물 확인 → `bcdedit … testsigning` 꺼져 있으면
경고 → `rundll32 setupapi.dll,InstallHinfSection DefaultInstall 132
RansomGuard.inf` → `sc.exe start RansomGuard` (`1056 =
ERROR_SERVICE_ALREADY_RUNNING` 은 허용) → `fltmc filters` 중
`RansomGuard` 행 출력.

### 8.6 `scripts/uninstall_driver.ps1`

관리자 전용. `sc.exe stop RansomGuard` → `rundll32
setupapi.dll,InstallHinfSection DefaultUninstall 132` (또는 폴백으로
`sc.exe delete RansomGuard`) →
`%windir%\System32\drivers\RansomGuard.sys` 삭제.

---

## 9. 시스템 확장

### 새 커맨드라인 룰 추가
`detectors/process_cmdline.py` 의 `RULES` 에 새 `Rule(...)` append.
WMI 구독자와 psutil 폴링 양쪽 모두 `evaluate_cmdline` 을 거치므로
자동 적용됨.

### 새 디텍터 추가
1. `detectors/your_detector.py` 작성. `Detector` 상속, `name` 지정, `run()` 구현.
2. `Agent.__init__` 에서 인스턴스화 후 `self.detectors` 에 추가.
3. `weight`/`severity` 는 기존 스케일과 일관성 있게 (CRITICAL ≈ 70+, HIGH ≈ 35–60, MEDIUM ≈ 10–30, LOW ≈ 1–9).

### 새 리스폰더 모드
`ResponderMode` 확장 → `_respond_to_pid` 에 분기 → `agent.parse_args`
의 `--mode` choices 업데이트.

### 새 대시보드 패널
1. `dashboard/app.py` 에 엔드포인트 추가.
2. `dashboard/templates/index.html` 에 `.panel` 블록 + 기존 `<script>` 안에 `tick()` 폴러 추가.

### 새 커널 이벤트
1. `RansomGuard.h` 의 `RG_EVENT_KIND` 에 kind 추가 (레이아웃이 바뀌면 `RG_PROTOCOL_VERSION` bump).
2. `detectors/minifilter_bridge.py` 에 대응 상수 추가.
3. `RansomGuard.c` 의 적절한 커널 콜백에서 `RgSendEvent` 로 emit.
4. `MinifilterBridge._handle_event` 에서 처리.

---

## 10. 운영 노트

- **Windows 에서 관리자 권한 실행** — 리스폰더가 타 프로세스 종료, 커널 브리지가 포트 연결을 하려면 필요.
- **Test signing** 가 켜져 있어야 미서명 드라이버가 로드됨 (`bcdedit /set testsigning on`).
- **`NEVER_KILL`** 은 오퍼레이터 실수 방어용 — 추가 중요 프로세스가 있으면 체크를 끄지 말고 목록에 추가.
- **Reports** 기본 위치는 `./reports/`. 회전/아카이브는 외부에서 — 리포터는 하지 않음.
- **크로스플랫폼** — 유저모드 에이전트는 Linux/macOS 에서도 동작 (WMI 없음, minifilter 없음). 시뮬레이터로 새 디텍터 개발할 때 유용.
