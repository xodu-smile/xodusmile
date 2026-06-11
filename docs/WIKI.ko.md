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
   │  - process_kernel  │◄──── 커널 이벤트 ───┐         ▼
   │  - registry_kernel │                     │   ┌────────────────┐
   │  - minifilter_bridge│                    │   │ IncidentReport │
   └────────────────────┘                     │   │  - .md 작성     │
            ▲                                 │   │  - 사용자 알림   │
            │                                 │   └────────────────┘
   ┌────────┴────────┐                ┌───────┴───┐
   │ Flask Dashboard │                │ RansomGuard│       ┌──────────┐
   │  (브라우저 UI)  │                 │ minifilter │       │  tamper  │
   └─────────────────┘                │   (.sys)   │       │ (변조방지)│
                                      └────────────┘       └──────────┘
                                            ▲
                                            │ heartbeat / 재기동
                                      ┌─────┴──────┐
                                      │ watchdog_  │
                                      │  service   │
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
├── tamper.py                      # 자가 변조 방지 (Critical 플래그 + DACL)
├── service.py                     # Windows 서비스 호스트 (RansomGuardAgent)
├── watchdog_service.py            # 사이드카 서비스, Agent heartbeat/재기동
├── demo_inproc.py                 # 종단 데모(대시보드 없이)
├── __init__.py                    # 패키지 마커
├── detectors/
│   ├── __init__.py
│   ├── base.py                    # Detector ABC
│   ├── canary.py                  # Canary 파일
│   ├── mass_io.py                 # 파일 이벤트 버스트 + 엔트로피
│   ├── process_cmdline.py         # WMI + 정규식 룰셋
│   ├── process_watcher.py         # psutil 폴링, 부모-자식 체인
│   ├── process_kernel.py          # 커널 콜백 기반 프로세스 생성 탐지 (WMI 미사용)
│   ├── registry_kernel.py         # 커널 콜백 기반 레지스트리 쓰기 탐지
│   └── minifilter_bridge.py       # 유저모드 드라이버 클라이언트
├── dashboard/
│   └── app.py                     # Flask 앱(라우트 + JSON API)
├── tests/
│   └── simulator.py               # 안전한 행위 시뮬레이터
├── minifilter/
│   ├── RansomGuard.h              # 드라이버 ↔ 유저모드 계약 (v2)
│   ├── RansomGuard.c              # 커널 minifilter
│   ├── RansomGuard.inf / .sln / .vcxproj
├── scripts/
│   ├── _common.ps1                # 공용 PS 헬퍼
│   ├── bootstrap.ps1              # Python + venv 설치
│   ├── build_driver.ps1           # MSBuild 래퍼
│   ├── install_driver.ps1         # .sys 적재 + 서비스 시작
│   ├── install_services.ps1       # Agent + Watchdog 서비스 등록 + DACL 락
│   ├── install.ps1                # bootstrap + 드라이버 일괄
│   ├── uninstall_driver.ps1       # 드라이버 중지/제거
│   └── uninstall_services.ps1     # Agent + Watchdog 서비스 제거
└── reports/                       # (런타임 생성) .md 인시던트
```

---

## 3. 최상위 Python

### 3.1 `agent.py`

CLI 진입점. 모든 구성요소를 연결하고 메인 루프를 돈다.

| API | 설명 |
|-----|------|
| `class Agent(watch_dirs, *, db_path, responder_mode, enable_minifilter, reports_dir, notify_user, enable_tamper_protection, watchdog_pid)` | 모든 디텍터(커널 콜백 기반 포함), 스코어링 엔진, 이벤트 스토어, 리스폰더, 인시던트 리포터, 변조 방지 훅을 소유. |
| `Agent.start()` | Canary 배치 후 모든 디텍터 스레드 시작. |
| `Agent.stop()` | 디텍터 중지, canary 파일 정리. |
| `Agent.status()` | 점수+레벨+최근 시그널+리스폰더+인시던트 스냅샷 (`/api/status`에서 소비). |
| `Agent.processes(limit)` | `ProcessWatcher.snapshot` 패스스루. |
| `Agent._on_signal(sig, score, level)` | 출력 + 저장. |
| `parse_args()` / `main()` | CLI 옵션: `--watch`, `--db`, `--no-dashboard`, `--port`, `--mode`, `--no-minifilter`, `--reports-dir`, `--no-notify`, `--no-tamper-protection`, `--watchdog-pid`. |

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
| `GROUND_TRUTH_ENCRYPTION` | **신뢰 게이트 사각지대 차단용 신호 집합** — `canary_modified`, `canary_deleted`, `magic_bytes_lost`, `suspicious_extension`, `ransom_note_spread`, `kernel_blocked_op`. 이 집합에 속한 신호는 행위자 신뢰(actor-trust) 게이트에 의해 **절대 면제되지 않는다** — 신뢰된 프로세스(svchost 등)에 인젝션(T1055)되거나 위장(T1036)된 랜섬웨어가 이 신호를 유발해도 항상 채점된다. |
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
<<<<<<< HEAD
| `@dataclass KillAction` | `timestamp, pid, process_name, cmdline, reason, mode, quarantined, terminated, error` + **행동 시점 포렌식 캡처** `exe_path, exe_sha256, username, ppid, parent_name, score_at_action, level_at_action, trigger_signal, detect_ts` (모두 기본값 보유 — 보고서가 라이브 엔진 대신 이 캡처를 1차 근거로 사용). |
| `ProcessResponder(engine, *, mode, minifilter, critical_threshold, on_action)` | `on_action` 으로 `IncidentReporter` 가 연결된다. |
=======
| `@dataclass KillAction` | `timestamp, pid, process_name, cmdline, reason, mode, quarantined, terminated, error`. |
| `ProcessResponder(engine, *, mode, minifilter, on_action, allowlist)` | `on_action` 으로 `IncidentReporter` 가, `allowlist` 로 운영자 허용목록(never-kill 보강)이 연결된다. |
>>>>>>> master
| `attach()` | 엔진 구독. 멱등. |
| `actions(limit=50)` | 대시보드용 이력. |
| `manual_kill(pid, reason)` / `manual_release(pid)` | 대시보드 버튼이 도달하는 곳. |
| `_dispatch(sig, score, level)` | PID 가 있는 HIGH/CRITICAL 시그널만 처리. `_is_confident()` 통과 시 `_respond_to_pid`, 아니면 `_record_observed`(무대응 기록). **점수 기반 전체 PID 스윕은 폐지** — 오탐을 대량 학살로 키우고 never-kill 목록에만 의존하던 구조였음. |
| `_is_confident(pid, sig)` | CRITICAL 단독은 고신뢰로 대응. HIGH 는 corroboration 필요 — 윈도우 내 실제 암호화 활동(`ScoringEngine.has_encryption_activity`) 또는 같은 PID 를 가리키는 서로 다른 탐지기 2개 이상. |
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
| `on_action(action)` | **No-op 은 스킵** (`terminated`/`quarantined` 모두 false). 마크다운 생성 → 파일 저장 → **JSON 사이드카 저장** → 이력 append → 알림 스레드 spawn. |
| `recent(limit=50)` | 최신순 `IncidentRecord` dict 리스트. |
| `read_report(filename)` | 경로 트래버설 방어 (`/`, `\`, `..`, reports_dir 탈출 거부). 파일 본문 또는 `None`. |
| `_incident_context(action)` | **행동 시점 캡처 우선** 컨텍스트: `KillAction.trigger_signal/score_at_action` 을 1차 근거로 쓰고, 트리거 신호는 점수 윈도우(120초)에서 퇴거됐어도 PID 신호 표에 재주입. 라이브 엔진 재조회로 인한 "차단했는데 점수 0/근거 없음" 자기모순 방지 (RustyStealer PDF 사례). md/JSON 양쪽이 같은 헬퍼를 사용. |
| `_build_markdown(action)` | 한눈에 보기 → 프로그램/조치 → 위협 수준(**차단 시점 점수 + 차단 근거** 명시) → MITRE → 피해 범위(**커널 burst 카운터를 최소 건수 바닥으로** — `_damage_floors`) → 포렌식 정보(이미지 경로/SHA-256/계정/부모/탐지→대응 지연) → 침해 지표(IOC) → PID 신호 표(**PID 열·날짜·◀ 표시**) → 다른 프로세스 신호(참고용 분리) → 원본 액션 JSON. |
| `_write_json_sidecar(action, md_path)` | `incident_*.json` (`schema: ransomguard.incident.v1`) — action+피해+MITRE+PID 신호. SIEM/SOAR 인제스트용. 실패해도 md 흐름은 막지 않음. |
| `_notify_user(action, path)` | 백그라운드 스레드; 플랫폼별 디스패치. |
| `_notify_linux` | `notify-send` subprocess. |
| `_notify_macos` | `osascript -e 'display notification …'`. |
| `_notify_windows` | `win10toast` → PowerShell `BurntToast` → `MessageBoxW` 폴백. |

파일명: `incident_<YYYYMMDD_HHMMSS>_pid<N>_<safe_name>.md`.

---

### 3.6 `tamper.py`

자가 변조 방지 헬퍼. Agent 시작 시 적용되는 best-effort 방어 3계층.
Windows 외에서는 모두 no-op.

| API | 설명 |
|-----|------|
| `is_windows()` | 플랫폼 가드. |
| `set_process_critical(enable=True)` | `ntdll!RtlSetProcessIsCritical` 호출. critical 프로세스를 죽이면 BSOD → "조용한 종료" 봉쇄. SeDebugPrivilege 필요 (LocalSystem 서비스에선 자동). |
| `harden_paths(paths)` | SQLite DB, reports 폴더 등에 SYSTEM/Administrators 만 접근하도록 DACL 설정. 일반 사용자 공격 차단. |

가장 강력한 보호는 별도로 커널 측 `ObCallback` (드라이버가
`MinifilterBridge.add_protected_pid` 로 등록) — 핸들 access mask 박탈로
SYSTEM 권한 공격도 차단.

---

### 3.7 `service.py`

`RansomGuardAgent` Windows 서비스 호스트. `pywin32` 의
`servicemanager` 를 사용해서 SCM 에 등록하고 LocalSystem 권한으로
Agent 를 실행한다.

| API | 설명 |
|-----|------|
| `SERVICE_NAME = "RansomGuardAgent"` | SCM 식별자. |
| `_load_params_from_registry()` | `HKLM\…\Services\RansomGuardAgent\Parameters` 에서 `WatchDirs`, `DbPath`, `ReportsDir`, `Mode` 읽기. 키 부재 시 기본값 폴백. |
| `RansomGuardService.SvcDoRun()` | Agent 구성 → `start()` → stop 이벤트 대기 → `stop()`. |
| `install` / `start` / `stop` / `remove` | 표준 pywin32 서비스 커맨드. |

`scripts/install_services.ps1` 이 이 모듈을 호출해서 SCM recovery
옵션 (auto-restart on failure) 까지 함께 설정한다.

---

### 3.8 `watchdog_service.py`

`RansomGuardWatchdog` 사이드카 서비스. Agent 서비스가 살아 있고
응답 가능한지 5초마다 검증, 죽었거나 hang 이면 SCM 으로 재기동.

| API | 설명 |
|-----|------|
| `WATCHDOG_INTERVAL_SECS = 5` | 폴링 주기. |
| `HEARTBEAT_MISS_THRESHOLD = 3` | 연속 미응답 임계 — 넘으면 강제 재기동. |
| `_check_agent_state()` | SCM 으로 Agent 서비스 현재 상태 조회. `RUNNING` / `START_PENDING` 아니면 start 요청. |
| `_check_heartbeat()` | `http://127.0.0.1:5000/api/heartbeat` GET. 3회 연속 실패면 stop → SCM 자동 재시작 트리거. |

상호 보호: Agent 가 부팅하면서 자신의 watchdog PID 를 커널
`ObCallback` 에 protect 등록 → Agent 와 Watchdog 둘 다 죽이려면 SCM
권한이나 BSOD 가 필요해진다.

---

### 3.9 `demo_inproc.py`

단일 프로세스 종단 데모: `Agent` 부팅 → 더미 파일 배치 → 가짜
VSS/BCD 이벤트 주입 → canary touch → 암호화 시뮬레이션 → 통계 출력.
드라이버나 대시보드 없이 디텍터 동작을 검증할 때 쓴다.

---

### 3.10 `__init__.py`

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

### 4.3b `detectors/ransom_note.py`

협박문(ransom note) 탐지기. 감시 폴더를 2초마다 폴링해서 암호화 후
랜섬웨어가 각 폴더에 떨어뜨리는 협박문 파일을 감지한다.

**내용 기반 분석 (content-aware)**: 파일명 패턴 매칭 외에 파일 내용을 직접
읽어 ① BTC/ETH/Monero 암호화폐 지갑 주소, ② `.onion` URL, ③ "your files have
been encrypted" 류 협박 문구, ④ 결제·연락처 용어를 탐지한다. 따라서 파일명이
`A7F3C.txt` 처럼 무작위여도 **내용으로 협박문임을 확인**한다.

| 항목 | 설명 |
|------|------|
| `NOTE_PATTERNS` | 정규식 목록 — `how.*to.*decrypt`, `recover.*files`, `your.*files.*encrypted`, `ransom.*note`, `_readme.txt`, 등 특이도 높은 패턴. |
| `CONTENT_PATTERNS` | 내용 검사 정규식 — 암호화폐 지갑 주소, `.onion` URL, 협박·결제 문구. |
| `SPREAD_DIR_THRESHOLD = 3` | 이 개 이상 *서로 다른* 디렉터리에서 노트가 나오면 spread (기존 2 → **3** 으로 상향). |
| `SPREAD_WINDOW_SEC = 60` | 이 시간 내에 모인 노트만 spread 로 집계. |
| `W_NOTE_SINGLE = 35` | 단일 내용 확인 협박문 가중치 (HIGH). |
| `W_NOTE_SPREAD = 90` | 다중 디렉터리 spread 가중치 (CRITICAL). |
| `RansomNoteDetector.run()` | 1차: baseline scan (기존 파일 무시); 이후 폴링에서 새 노트 감지 시 `_handle_note()`. |
| `_handle_note(path, now)` | 내용 확인 여부 판정 → 노트 경로를 `_recent_dirs` dict에 추가 → spread count 판정. **내용 확인된 노트가 ≥ 3 디렉터리에 spread 이면 `ransom_note_spread` (CRITICAL); 이름만 매칭되고 ≥ 3 dirs에 spread이면 실제 암호화 활동(canary/mass_io)이 동반될 때만 CRITICAL**. 단일 내용 확인 = HIGH; 이름만 = MEDIUM 힌트. |
| `_on_engine_signal(sig, score, level)` | canary 신호 구독 — canary 트립 시 30초 내 단일 노트도 CRITICAL로 강화. |

크로스 시그널: `canary` 트립이 감지되면 `_boost_active()` 가 True 반환해서
단일 노트도 `ransom_note_dropped` 대신 CRITICAL로 발화 (weight W_NOTE_SPREAD).

**오탐 억제 설계**: 이름만 매칭된 단발 노트는 MEDIUM 힌트로만 — 이름 패턴과
우연히 일치하는 정상 파일(README.txt 등)로 인한 오탐 억제. 내용 확인이 핵심 승격 조건.

---

### 4.4 `detectors/process_cmdline.py`

Win11 전용 WMI 프로세스 생성 구독자. 각 새 프로세스는 `RULES` —
정규식 기반 `Rule` 목록을 거친다 (총 **33개 룰**, 기존 22개에서 증가):

- **VSS 삭제/리사이즈** — `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, PowerShell `Get-WmiObject … shadowcopy … Remove-…`, **`vssadmin resize shadowstorage`**.
- **BCD 조작** — `bcdedit … safeboot`, `recoveryenabled no`, `bootstatuspolicy ignoreallfailures`.
- **Defender / SmartScreen 무력화** — `Set-MpPreference -DisableRealtimeMonitoring`, `WinDefend/Sense/WdNisSvc/WdFilter` 서비스 stop, `Add-MpPreference -Exclusion*`, 레지스트리 편집, SmartScreen 비활성화.
- **Anti-forensics** — `wevtutil cl`, `Clear-EventLog`, `fsutil usn deletejournal`, `cipher /w`.
- **방어 인프라 종료** — `netsh advfirewall … state off`, `manage-bde -off`, `Disable-BitLocker`.
- **지속화** — `schtasks /create … /sc onlogon … /ru system`, Run/RunOnce 레지스트리 쓰기.
- **PowerShell 남용** — `-EncodedCommand <base64>`, 인메모리 다운로더, `-ExecutionPolicy bypass -WindowStyle hidden`.
- **Living-off-the-land (신규 11개 룰)**:
  - `cipher_efs_encrypt` — `cipher /e` (내장 EFS 암호화 엔진 악용).
  - `bitlocker_abuse_enable` — `manage-bde -on` / `Enable-BitLocker` (BitLocker 강제 암호화).
  - `vssadmin_resize_shadowstorage` — 섀도 스토리지 축소로 복구 수단 약화.
  - `certutil_download` — `certutil -urlcache -split -f` (파일 다운로드 LOLBin).
  - `certutil_decode_payload` — `certutil -decode` (Base64 페이로드 복호화).
  - `bitsadmin_transfer` — `bitsadmin /transfer` (T1197 BITS 악용).
  - `esentutl_raw_copy` — `esentutl /y` (잠긴 파일 raw 복사).
  - `wmic_process_call_create` — `wmic process call create` (프로세스 생성 우회).
  - `kernel_service_create` — `sc create type=kernel` (BYOVD — 취약 커널 드라이버 로드).
  - `archive_password_staging` — `7z … -p` / `rar … -p` (이중 갈취 스테이징).
  - `rclone_exfil` — `rclone copy/sync` (클라우드 유출, T1567.002).

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
LOLBin 체인 탐지, 단일 프로세스 I/O 버스트, **시스템 바이너리 위장 탐지**,
대시보드 프로세스 테이블 공급을 담당.

| API | 설명 |
|-----|------|
| `ProcSnapshot` dataclass | `pid, ppid, name, cmdline, user, started_at, cpu_percent, rss_bytes, write_bytes, last_seen`. |
| `SCRIPT_HOSTS` | LOLBin 스크립트 호스트 이름 (powershell, pwsh, cmd, wscript, cscript, mshta, regsvr32, rundll32, bitsadmin, certutil, msbuild, installutil). |
| `CORE_SYSTEM_BINARIES` | 위장 탐지 대상 핵심 시스템 이름 목록 (svchost.exe, lsass.exe, csrss.exe 등). |
| `SYSTEM32_PATHS` | 정상 실행 경로 집합 (System32, SysWOW64). |
| `SUSPICIOUS_CHAINS` | `parent → set(child)` 매핑. Office, Adobe, 브라우저, explorer, OneDrive 등. |
| `ProcessWatcher.snapshot(limit=80)` | 최근 본 순으로 정렬된 dict 리스트 (`/api/processes` 용). |
| `run()` | 베이스라인 1패스(시그널 없음) → 1 Hz `_scan(initial=False)`. |
| `_on_new_process(snap)` | (1) `evaluate_cmdline` 룰 적용; (2) **`_check_masquerade`** — 시스템 바이너리 이름을 달고 System32/SysWOW64 밖에서 실행 시 `process_masquerade` (weight 60, HIGH, T1036.005) emit; (3) 부모-자식 체인 → `suspicious_parent_child` (weight 40, HIGH); (4) 동일 부모 fan-out → `child_fanout` (weight 30, MEDIUM), 5s 내 자식 12개+. |
| `_check_masquerade(snap)` | `%TEMP%\svchost.exe` 처럼 핵심 시스템 이름이 정상 경로 밖에서 실행될 때 `process_masquerade` 시그널 emit. |
| `_check_write_burst(...)` | `process_write_burst` (weight 20, MEDIUM) — 단일 프로세스가 2s 윈도우에 50MB+ 쓰기. |

자기 PID 는 건너뛰고, 사라진 PID 는 `_seen`/`_last_io` 에서 제거해
메모리 상한을 유지한다.

---

### 4.6 `detectors/minifilter_bridge.py`

`RansomGuard.sys` 커널 minifilter 의 유저모드 클라이언트.
`minifilter/RansomGuard.h` 의 바이너리 프로토콜을 그대로 사용.

| API | 설명 |
|-----|------|
| `class RG_EVENT(ctypes.Structure)` | 커널 `RG_EVENT` 패킷의 거울. v2: `ParentProcessId`, `DesiredAccess`, `Extra[1024]` 필드 추가. |
| `RG_MESSAGE = FILTER_MESSAGE_HEADER + RG_EVENT` | `FilterGetMessage` 단일 버퍼 레이아웃. |
| `RG_COMMAND`, `RG_REPLY` | 컨트롤 플레인 — 격리/해제/ping/PID 보호/언보호/격리 플러시. |
| `_load_fltlib()` | `fltlib.dll` 로드 + `FilterConnectCommunicationPort/FilterGetMessage/FilterSendMessage` 바인딩. Windows 외/DLL 부재 시 `None`. |
| `MinifilterBridge.is_connected` | 포트 오픈 여부. |
| `quarantine_pid(pid)` / `release_pid(pid)` / `ping()` | `RG_COMMAND` 전송 후 `RG_REPLY.Status == 0` 확인. |
| `add_protected_pid(pid)` / `remove_protected_pid(pid)` / `flush_quarantine()` | v2 추가: 자가 보호 등록 / 해제, 모든 격리 일괄 해제. |
| `subscribe_process(cb)` / `subscribe_registry(cb)` | `process_kernel`, `registry_kernel` 디텍터가 콜백 등록 시 사용. |
| `run()` | 지수 백오프 (1s → 30s) 재연결 루프. `_receive_loop` 에서 `FilterGetMessage` 블로킹, `Version == RG_PROTOCOL_VERSION (=2)` 검증 후 `_handle_event` 디스패치. |
| `_handle_event(evt)` | kind 별 분기 (8가지): `CREATE` → 경로 기록 / `WRITE` → `_account_write` / `SETINFO/RENAME` → `_account_rename` / `SETINFO/DELETE` → `file_delete` (LOW, weight 3) / `BLOCKED` → `kernel_blocked_op` (weight 60, HIGH) / `PROCESS_START`, `PROCESS_EXIT` → `subscribe_process` 콜백 / `REGISTRY` → `subscribe_registry` 콜백 / `TAMPER_BLOCKED` → `tamper_blocked` 시그널. |
| `_account_write(...)` | PID 별 슬라이딩 윈도우 (`PID_WRITE_BURST_BYTES=75 MB`, `WINDOW=4 s`). 트립 시 `kernel_write_burst` (weight 35, HIGH), 4s 디바운스. |
| `_account_rename(...)` | PID 별 슬라이딩 윈도우 (`PID_RENAME_BURST_COUNT=20`, `WINDOW=5 s`). `kernel_rename_burst` (weight 40, HIGH). |

드라이버 부재 시 브리지는 idle, 유저모드 디텍터만으로도 동작.

---

### 4.7 `allowlist.py`

운영자 신뢰 목록. 정상 백업/압축/동기화 소프트웨어를 **프로세스 이름** 또는
**이미지 경로 접두사**로 명시 등록해서 점수 가산 및 자동 종료를 면제한다.

| 항목 | 설명 |
|------|------|
| `AllowEntry(kind, value, note, added_at)` | 개별 항목. `kind` = `"name"` (프로세스 basename, 소문자) 또는 `"path"` (이미지 경로 접두사, 소문자 정규화). |
| `Allowlist(path="allowlist.json", autoload=True)` | 메인 클래스. 영속화는 JSON, 로드 시 `load()` (중복 제거), 편집 시 `add/remove()` 후 `save()`. |
| `add(value, kind="", note="")` | 항목 추가 (중복 무시), 영속화. |
| `remove(value, kind="")` | 항목 제거, 영속화. |
| `entries()` | 전체 항목 dict 리스트. |
| `pid_allowed(pid)` | PID 의 검증된 이미지(exe path) 또는 basename 이 허용 목록과 일치하는지. `psutil` 로 PID → 경로/이름 조회, fail-closed (경로 불가 시 False). PID 재사용 방어용 create_time 캐시. |
| `signal_exempt(sig)` | scoring trust classifier 용. 허용 PID 가 낸 신호는 점수에서 면제. **단, `_NEVER_EXEMPT_SIGNALS` 에 든 고신뢰 신호 (canary, ransom_note_spread, defender_self_disable)는 면제 안 함.** |
| `matches(name, exe_path)` | 이름/경로가 허용 항목과 일치하는지 (PID 조회 없이). |
| `combine_trust(*classifiers)` | 여러 trust 함수를 OR 로 합성. `actor_trust.signal_actor_trusted` + `allowlist.signal_exempt` 통합 시 사용. |

**설계 철학**: 경로 기반 항목이 이름 위장(`%TEMP%\veeamagent.exe` 같은 가짜)을 방어하지만,
이름 항목만으로는 못 방어하므로, 관리자가 실수로 악성코드를 허용하는 사태를 막도록
canary/협박문확산 같은 단발 고신뢰 신호는 허용 목록으로도 면제 불가.

---

### 4.8 `attack_map.py`

모든 탐지 신호를 **MITRE ATT&CK 기법 ID**에 매핑하는 순수 데이터 + 조회.

| 함수 | 용도 |
|------|------|
| `Technique(tid, name, tactic, tactic_ko, url)` | 기법 정의. 예: `T1486 Data Encrypted for Impact`. |
| `techniques_for(signal_name)` | 신호 이름 → 매핑된 기법 리스트. 없으면 빈 리스트. |
| `technique_dicts_for(signal_name)` | 직렬화 형태 (dict 리스트). 대시보드/보고서용. |
| `primary_technique(signal_name)` | 첫 번째 기법만 (뱃지 1개 표시용). |
| `annotate_signal_dict(sig_dict)` | Signal dict 에 `attack` 키(기법 목록) 추가. 표시 계층 전용. |
| `label_for(signal_name)` | 한 줄 요약: `"T1490 Inhibit System Recovery (+1)"` 형태. |

**매핑 예**:
- `high_entropy_write`, `canary_modified` → `T1486 Data Encrypted for Impact`
- `vssadmin_delete_shadows` → `T1490 Inhibit System Recovery`
- `defender_disable_realtime` → `T1562.001 Impair Defenses` + `T1489 Service Stop`
- `wevtutil_clear_log` → `T1070.001 Indicator Removal: Clear Windows Event Logs`
- `schtasks_persistence` → `T1053.005 Scheduled Task/Job`
- `powershell_downloader` → `T1059.001 PowerShell` + `T1105 Ingress Tool Transfer`
- `process_masquerade` → `T1036.005 Masquerading: Match Legitimate Name or Location`
- `trusted_process_encrypting` → `T1055 Process Injection`
- `certutil_download`, `certutil_decode_payload` → `T1218 System Binary Proxy Execution`
- `bitsadmin_transfer` → `T1197 BITS Jobs`
- `kernel_service_create` → `T1543.003 Create or Modify System Process: Windows Service`
- `wmic_process_call_create` → `T1047 Windows Management Instrumentation`
- `archive_password_staging` → `T1560.001 Archive Collected Data: Archive via Utility`
- `rclone_exfil` → `T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage`

대시보드 및 보고서가 이 매핑을 사용해서 SOC/IR 팀과 표준 기법명으로 소통.

---

### 4.9 `detectors/process_kernel.py`

`MinifilterBridge` 의 `PROCESS_START`/`PROCESS_EXIT` 이벤트
(`PsSetCreateProcessNotifyRoutineEx` 출처) 를 구독해서 WMI 없이 프로세스
생성을 감지하는 디텍터. `process_cmdline.py` 의 `RULES` 와 동일한
정규식을 `evaluate_cmdline` 으로 공유 적용.

| API | 설명 |
|-----|------|
| `ProcessKernelDetector(engine, bridge)` | 생성 시 `bridge.subscribe_process(self._on_process_event)` 로 등록. 자체 스레드 없음 (브리지 receive 스레드에서 콜백). |
| `_on_process_event(evt)` | `RG_EVENT.Extra` 의 커맨드라인을 꺼내 `evaluate_cmdline(...)` → 매칭되면 `Signal` emit. |
| `run()` | no-op — 콜백 기반이므로 stop 이벤트만 대기. |

**왜 WMI 대신**: (1) WMI 폴링은 50–500 ms 지연 + 부하 시 누락, (2) 커널
콜백은 동기적으로 새 프로세스 첫 명령 실행 전 발화, (3) 커맨드라인을
커널 메모리에서 가져오므로 PEB 위조로 못 숨김, (4) WMI 윈도우보다
빨리 죽는 단명 프로세스도 잡힘.

`process_cmdline` 과 동시 활성 시 같은 룰이 두 번 발화 가능 — 시그널
`name` + `weight` 기준이라 무해.

---

### 4.12 `detectors/registry_kernel.py`

`MinifilterBridge` 의 `REGISTRY` 이벤트 (`CmRegisterCallbackEx` 출처)
를 구독. 드라이버가 watch 리스트로 미리 필터해서 올려보내므로,
디텍터는 키 경로를 라벨로 매핑만.

| 패턴 (소문자 부분 매치) | 시그널 | weight | severity |
|--------------------------|--------|-------:|----------|
| `\system\currentcontrolset\services\ransomguard` | `ransomguard_service_tamper` | 80 | CRITICAL |
| `\windefend`, `\wdfilter`, `\sense` 등 | `defender_*_tamper` | 70 | CRITICAL |
| `\image file execution options` | `ifeo_hijack` | 60 | HIGH |
| `\currentversion\run(once)?` | `run_key_persistence` | 30 | MEDIUM |
| `\schedule\taskcache` | `schtasks_persistence` | 35 | MEDIUM |
| 매치 없음 | `registry_other` | 1 | LOW (텔레메트리) |

순서는 첫 매치가 이김. 매치 안 되는 이벤트도 LOW 시그널로 흘려서
텔레메트리를 잃지 않게 한다.

---

## 5. Dashboard — `dashboard/app.py`

`agent.py` 가 같은 프로세스에서 마운트하는 작은 Flask 앱.

| Route | Method | 용도 |
|-------|--------|------|
| `/` | GET | `templates/index.html` 렌더. |
| `/api/status` | GET | `agent.status()` JSON. |
| `/api/heartbeat` | GET | `watchdog_service` 가 호출하는 라이브니스 프로브 (200 OK). **항상 공개** — 토큰이 설정돼 있어도 인증 불필요. |
| `/api/events` | GET | `EventStore` 최근 100개. |
| `/api/processes` | GET | `ProcessWatcher.snapshot(60)`. |
| `/api/actions` | GET | `ProcessResponder.actions(100)`. |
| `/api/reset` | POST | `engine.reset()`. **토큰 설정 시 인증 필요.** |
| `/api/kill` | POST `{pid, reason?}` | `responder.manual_kill`. **토큰 설정 시 인증 필요.** |
| `/api/release` | POST `{pid}` | `responder.manual_release`. **토큰 설정 시 인증 필요.** |
| `/api/reports` | GET | `incident_reporter.recent(100)`. |
| `/api/reports/<filename>` | GET | Raw markdown 본문 (`text/markdown`), 미존재/트래버설 시 404. |
| `/api/admin/health` | GET | 시스템 상태 snapshot — responder mode, 드라이버 연결, uptime, 감시 폴더, 허용 목록 개수, **`auth_enabled`**, **통합(integrations) 통계**. **토큰 설정 시 인증 필요.** |
| `/api/admin/mode` | POST `{mode:"off\|quarantine\|kill"}` | Responder 모드 변경 (실시간). **토큰 설정 시 인증 필요.** |
| `/api/admin/threats` | GET | PID 별 위협 분석 (각 프로세스가 낸 신호 + ATT&CK 기법 + 점수 기여도). **토큰 설정 시 인증 필요.** |
| `/api/admin/allowlist` | GET | 허용 목록 전체 항목. **토큰 설정 시 인증 필요.** |
| `/api/admin/allowlist` | POST `{value, kind:"name\|path", note?}` | 허용 목록 항목 추가. **토큰 설정 시 인증 필요.** |
| `/api/admin/allowlist` | DELETE `{value, kind:"name\|path"}` | 허용 목록 항목 삭제. **토큰 설정 시 인증 필요.** |

**인증 (Dashboard Authentication)**: `auth_token` 이 설정되면 위 표에서 "인증 필요"
로 표시된 모든 엔드포인트(변경성 + 모든 `/api/admin/*`)에 다음 중 하나가 있어야 한다:
- 헤더: `X-API-Key: <token>`
- 헤더: `Authorization: Bearer <token>`

읽기 전용 엔드포인트(`/api/status`, `/api/events` 등)는 기본적으로 공개.
`auth_required_for_reads = true` 설정 시 읽기 API 도 토큰 요구.
`/api/heartbeat` 는 watchdog 용이므로 **항상 공개**.

**관리자 패널** — Flask UI 내 새 collapsible 섹션 "관리자 패널 (Administrator)":
- **시스템 상태** — responder mode (off/quarantine/kill), minifilter 연결 상태, uptime, 감시 폴더 목록, 허용 목록 항목 수, 인증/통합 상태.
- **모드 전환** — POST `/api/admin/mode` 로 on-the-fly mode 변경 (재시작 불필요).
- **PID 별 위협 분석** — 어느 프로세스가 점수를 올렸는지, 각 신호의 ATT&CK 기법, 기여도 합산.
- **허용 목록 편집** — UI 폼으로 항목 추가/제거 (또는 `allowlist.json` 수동 편집 + reload).

`create_app(agent)` 가 팩토리. 에이전트 스레드가
`use_reloader=False` 로 Flask 서버를 띄운다.

HTML 템플릿은 고정 위치 토스트 컨테이너를 두고 2.5s 마다
`/api/reports` 를 폴링; 새 항목은 토스트로 띄워 10s 후 자동 dismiss.

---

## 5b. 기업 모듈

### `config.py`

중앙 정책 파일 로더. `ransomguard.toml` (Python 3.11+ `tomllib`) 또는
`ransomguard.json` 을 자동 탐지하거나 `--config <path>` 로 명시 지정한다.

우선순위: **CLI 플래그 > 설정 파일 > 내장 기본값**.

| 섹션 | 주요 키 |
|------|---------|
| `[general]` | `watch_dirs`, `responder_mode`, `enable_minifilter` |
| `[dashboard]` | `host`, `port`, `auth_token`, `auth_required_for_reads` |
| `[syslog]` | `enabled`, `host`, `port`, `protocol` (udp/tcp), `min_severity` |
| `[webhook]` | `enabled`, `url`, `min_severity` |

비밀 환경변수 (파일 값을 항상 덮어씀):
- `RANSOMGUARD_AUTH_TOKEN` — 대시보드 API 토큰.
- `RANSOMGUARD_WEBHOOK_URL` — Webhook 활성화 + URL.
- `RANSOMGUARD_SYSLOG_HOST` — syslog 활성화 + 호스트.

### `integrations.py`

SIEM/알림 통합 비동기 워커. 탐지 핫패스를 절대 막지 않는 **fail-open** 설계.

| 통합 | 프로토콜 | 설명 |
|------|---------|------|
| **SIEM** | CEF over syslog (UDP/TCP) | Splunk/QRadar/ArcSight/Sentinel 에서 파싱하는 표준 포맷으로 이벤트 스트리밍. `min_severity` 이상만 전송 (기본 HIGH). |
| **Webhook** | HTTPS JSON POST | Slack/Teams/PagerDuty/SOAR 로 즉시 JSON 알림. `min_severity` 이상만 (기본 CRITICAL). |

외부 의존성 없음(표준 라이브러리만). 통합 장애는 로그만 남기고 에이전트는 계속 동작.

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

- `RG_PORT_NAME = L"\\RansomGuardPort"`, altitude `385201`, **프로토콜 버전 `2`**, 최대 경로 520 WCHAR, 보조 버퍼 `Extra[1024]`.
- `RG_EVENT_KIND` (8가지): `RgEventCreate(1)`, `RgEventWrite(2)`, `RgEventSetInfo(3)`, `RgEventBlocked(4)`, **`RgEventProcessStart(5)`**, **`RgEventProcessExit(6)`**, **`RgEventRegistry(7)`**, **`RgEventTamperBlocked(8)`**.
- `RG_SETINFO_KIND`: `Other/Rename/Delete`.
- `RG_REGISTRY_KIND`: `Other/SetValue/DeleteValue/CreateKey/DeleteKey/RenameKey`.
- `RG_TAMPER_KIND`: `Process(1)/Thread(2)`.
- `RG_EVENT` (`#pragma pack(4)`, v2): `Version, Kind, SubKind, ProcessId, **ParentProcessId**, ThreadId, Status, **DesiredAccess**, WriteBytes (u64), TimestampNs (u64), PathLength, **ExtraLength**, Path[520 WCHAR], **Extra[1024 WCHAR]** (커맨드라인 또는 레지스트리 값 이름).
- `RG_COMMAND_KIND` (6가지): `RgCmdQuarantinePid(1)`, `RgCmdReleasePid(2)`, `RgCmdPing(3)`, **`RgCmdProtectPid(4)`**, **`RgCmdUnprotectPid(5)`**, **`RgCmdFlushQuarantine(6)`**.
- `RG_COMMAND` / `RG_REPLY`: 컨트롤 플레인 구조체.

v1 → v2 변경 요약: 프로세스 생성/종료 이벤트 + 레지스트리 이벤트 +
self-protection 이벤트 추가, `ParentProcessId`/`Extra` 필드 추가,
`ProtectPid`/`UnprotectPid`/`FlushQuarantine` 명령 추가, "sticky
quarantine" 모델 (유저모드 단절 시 격리 목록 유지).

### 7.2 `minifilter/RansomGuard.c`

작은 minifilter — 로직은 커널 밖에 둔다.

**전역 상태** (`g_Rg`):
- `Filter`, `ServerPort`, `ClientPort` (리스너 1개만 허용).
- `ClientLock` (FAST_MUTEX) — 포트 보호.
- `QuarantineLock` (`EX_PUSH_LOCK`) — `QuarantinedPids[256]` 보호.
- **`ProtectLock` (`EX_PUSH_LOCK`)** — `ProtectedPids[16]` 보호 (v2).
- **`CmCallbackCookie`** — `CmRegisterCallbackEx` 등록 토큰 (v2, 레지스트리 콜백).
- **`ObCallbackHandle`** — `ObRegisterCallbacks` 등록 핸들 (v2, 핸들 access 박탈).
- `PerfFrequency` — 부팅 시 캐싱, ns 변환용.

**라이프사이클**:
- `DriverEntry` — `FltRegisterFilter` → 기본 SD 빌드 → `FltCreateCommunicationPort(RG_PORT_NAME, …, callbacks, max-connections=1)` → `FltStartFiltering` → **`PsSetCreateProcessNotifyRoutineEx`** → **`CmRegisterCallbackEx`** → **`ObRegisterCallbacks`**.
- `RgUnload` — 포트 close, 모든 콜백 해제, unregister, push-lock 삭제.

**Operation 콜백** (`Callbacks[]` 가 `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` 등록):
- `RgPostCreate` — 유저모드 + 성공한 open 에 대해 `RgEventCreate` emit (드레인/커널 호출은 스킵).
- `RgPreWrite` — 요청 PID 가 격리 대상이면 `RgEventBlocked(Write)` emit 후 `STATUS_ACCESS_DENIED` 로 IRP 종료; 아니면 통과.
- `RgPostWrite` — 4096 바이트 이상 쓰기만 (서브 페이지는 throttle), `IoStatus.Information` 을 `WriteBytes` 로 실어 `RgEventWrite` emit.
- `RgPreSetInfo` — `Rename`/`Delete`/`Other` 분류. `Other` 스킵. 격리 PID 의 rename/delete 는 차단; 아니면 `sub` 를 `CompletionContext` 로 전달.
- `RgPostSetInfo` — 저장된 sub-kind 로 `RgEventSetInfo` emit.

**v2 추가 콜백**:
- **`RgCreateProcessNotify`** (`PsSetCreateProcessNotifyRoutineEx`) — 프로세스 생성/종료를 커널에서 동기 감지. 생성 시 `RG_EVENT.Extra` 에 커맨드라인을 채워 `RgEventProcessStart` emit. 종료 시 `RgEventProcessExit` + 격리 목록에서 자동 제거.
- **`RgCmRegistryCallback`** (`CmRegisterCallbackEx`) — Defender / Run / RansomGuard 자신 등 high-value 키 변경을 watch 리스트 기반으로 사전 필터 → `RgEventRegistry` emit.
- **`RgObPreOperation`** (`ObRegisterCallbacks`, `ObjectType=PsProcessType/PsThreadType`) — 보호 PID 에 대한 핸들 open 시 위험 권한 (`PROCESS_TERMINATE`, `PROCESS_VM_*`, `THREAD_TERMINATE` 등) 을 access mask 에서 박탈. 자기 자신 호출은 통과. 차단 시 `RgEventTamperBlocked` emit.

**격리 비트맵** (`RgIsQuarantined`, `RgAddQuarantine`, `RgRemoveQuarantine`) — push-lock 아래 256 엔트리 선형 스캔. 용량 제한으로 커널 측은 단순/안전.

**보호 비트맵 (v2)** (`RgIsProtected`, `RgAddProtected`, `RgRemoveProtected`) — `ProtectedPids[16]` 별도 push-lock 아래. `ObCallback` 가 핸들 open 시 빠르게 조회. v2 에서 추가된 "sticky" 모델: 유저모드 단절 시 격리 목록은 보존, 명시적 `FlushQuarantine` 명령에만 비움 (anti-tamper default).

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
RansomGuard.inf` → `fltmc load RansomGuard` → `fltmc filters` 에
`RansomGuard` 가 보이면 성공으로 간주(이미 로드돼 load 가 nonzero 여도
목록에 있으면 OK).

### 8.6 `scripts/uninstall_driver.ps1`

관리자 전용. `fltmc unload RansomGuard` → `rundll32
setupapi.dll,InstallHinfSection DefaultUninstall 132` (또는 폴백으로
`sc.exe delete RansomGuard`) →
`%windir%\System32\drivers\RansomGuard.sys` 삭제.

### 8.7 `scripts/install_services.ps1`

관리자 전용. 파라미터: `-WatchDirs`, `-Mode`, `-DashboardPort`,
`-NoHeartbeat`. 단계:

1. `service.py install` 로 `RansomGuardAgent` 등록 + `watchdog_service.py install` 로 `RansomGuardWatchdog` 등록.
2. 각 서비스의 SCM recovery option 설정 — 1차/2차/3차 실패 모두 즉시 자동 재시작.
3. `HKLM\…\Services\RansomGuardAgent\Parameters` 에 `WatchDirs`, `Mode`, `DashboardPort` 등 쓰기.
4. `C:\ProgramData\RansomGuard\` 데이터 디렉토리 생성 + SYSTEM/Administrators 만 접근하도록 DACL 락.
5. 두 서비스 `sc.exe start`.

### 8.8 `scripts/uninstall_services.ps1`

관리자 전용. 두 서비스를 순서대로 stop → `service.py remove` /
`watchdog_service.py remove` 로 SCM 등록 해제. `C:\ProgramData\
RansomGuard\` 는 보존 (수동 정리, 사고 보고서 보호 목적).

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
