# Ransomware Detection Agent (Windows 11)

랜섬웨어 탐지·차단 프로토타입. 사용자 모드 휴리스틱 + **EDR-grade 커널
minifilter** 조합. 드라이버가 로드되어 있을 때는 시판 EDR 의 파일·프로세스
센서를 동등하게 대체하는 것을 목표로 한다 (process tree, image load,
entropy guard, susp-ext rename guard, kernel scoring, auto-terminate).

```
   ┌─────────────────────────────────────────────────┐
   │  agent.py (ScoringEngine + EventStore + Flask)  │
   └───┬─────────────┬───────────────┬───────────────┘
       │             │               │
   detectors/    detectors/      detectors/
   canary        mass_io         minifilter ────┐
   process_*                                    │  \RmDetectorPort (FltMgr)
                                                ▼
                                  ┌─────────────────────────────────────┐
                                  │ kmod/RmDetectorFlt (.sys)           │
                                  │  Pre/Post: Create / Write /         │
                                  │   SetInfo / Cleanup                 │
                                  │  PsSetCreateProcessNotifyRoutineEx  │
                                  │  PsSetLoadImageNotifyRoutine        │
                                  │  Entropy sampler + per-PID scoring  │
                                  │  Susp-ext rename guard              │
                                  │  ZwTerminateProcess (auto-kill)     │
                                  └─────────────────────────────────────┘
```

## EDR-grade 기능 (드라이버 로드 시)

| 영역 | 동작 | 비고 |
|---|---|---|
| Process tree | `PsSetCreateProcessNotifyRoutineEx` — PID, parent PID, image path, command line 업콜 | Sysmon EID 1/5 동등 |
| Image load | `PsSetLoadImageNotifyRoutine` — 로드된 DLL/EXE 경로 업콜 | Sysmon EID 7 동등 |
| Entropy guard | `IRP_MJ_WRITE` 직전 256 바이트 샘플 → distinct-byte 휴리스틱 (entropy x100) | floating-point 미사용, IRQL ≤ APC 안전 |
| Suspicious-ext rename | watch 경로 내 `.locked / .crypt / ...` 로의 rename 차단 | 기본 30개 패밀리, runtime 추가 가능 |
| Canary block | canary 파일에 대한 write/rename/delete 무조건 거부 | `STATUS_ACCESS_DENIED` |
| PID write block | user-mode 가 위험 PID 를 알려오면 모든 write 거부 | watchdog 폴백용 |
| **In-kernel scoring** | per-PID 누적 점수 (entropy hit + new ext + susp-ext rename + canary block + write burst) | user-mode roundtrip 없이 차단 가능 |
| **Auto-terminate** | per-PID 점수가 threshold 돌파 → `ZwTerminateProcess` (delayed work item) | policy bit 으로 비활성 가능 |

## 컴포넌트

| 모듈 | 역할 |
|---|---|
| `detectors/canary.py` | Canary 파일 무결성 (SHA256) |
| `detectors/mass_io.py` | 대량 I/O + 엔트로피 + 매직바이트 (watchdog) |
| `detectors/minifilter.py` | 커널 minifilter 브리지 — kernel event → Signal 변환, 커널 명령 push |
| `detectors/process_cmdline.py` | WMI 기반 VSS/BCD cmdline 룰 |
| `detectors/process_watcher.py` | psutil 폴링, LOLBin chain, I/O burst |
| `kmod/RmDetectorFlt/` | C minifilter 드라이버 (WDK) + INF + 빌드/설치 스크립트 |
| `scoring.py` | 가중치 합산 (120s 윈도우) |
| `event_store.py` | SQLite 영속화 |
| `dashboard/app.py` | Flask UI + `/api/processes` |

설계 원칙: 시그널 → ScoringEngine → Severity. 커널 시그널은 ground-truth PID
보장 덕분에 가중치가 더 크다. 사용자 모드 점수와 **별개로** 커널이 자체
점수를 누적해서 임계치 돌파 시 즉시 process termination 까지 끝낸다.

기본 가중치: canary block = 95, kernel score critical = 90, auto-terminated
= 100, blocked susp-ext rename = 80, blocked PID write = 70, entropy spike
= 18, watched delete/rename = 12.

## 동작 모드

| 모드 | 조건 | 차이 |
|---|---|---|
| **EDR-grade** (권장) | `RmDetectorFlt.sys` 로드 | 프로세스 트리 + 이미지 로드 + 엔트로피 가드 + susp-ext rename 가드 + canary 보호 + PID 차단 + **커널 자체 score 누적 + ZwTerminateProcess**. PID/path ground-truth. |
| **User-mode only** | 드라이버 미로드 | watchdog 폴링으로 파일 변경 탐지. 차단 없음. PID 부정확 가능. |

`agent.py` 가 자동으로 `\RmDetectorPort` 연결을 시도해 모드를 결정한다.

## 요구사항

- Windows 11 (22H2+), Python 3.10+ x64
- 관리자 PowerShell
- `winmgmt` 서비스 동작 (WMI `Win32_Process` 접근)
- **EDR 모드 추가 요구**: Visual Studio 2022 + Windows Driver Kit (WDK)

## 설치 — Python (user-mode)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\.venv\Scripts\pywin32_postinstall.py -install
```

## 설치 — Minifilter 드라이버 (EDR 모드)

상세는 [`kmod/README.md`](kmod/README.md) 참고. **모든 단계는 관리자 PowerShell
에서 실행한다** (인증서 LocalMachine 스토어 등록 + bcdedit + fltmc).

```powershell
cd kmod

# 1) 빌드 + 자체 서명 + 카탈로그 생성 + install\ 에 산출물 배치
#    산출물: kmod\install\{RmDetectorFlt.sys, .inf, .cat, .pdb}
.\build.ps1                        # Debug|x64 기본
# .\build.ps1 -Configuration Release  # 필요 시
# .\build.ps1 -SkipBuild              # 재서명만

# 2) 첫 실행: testsigning 자동 활성화 → 재부팅 안내
.\install.ps1

# 3) 재부팅 후 다시 실행: 서비스 등록 + 드라이버 로드
.\install.ps1

# 확인
fltmc instances -f RmDetectorFlt
Get-AuthenticodeSignature .\install\RmDetectorFlt.sys

# 제거
.\uninstall.ps1
```

빌드는 `CN=RmDetectorFltTestCert` 자체 서명 인증서를 자동 생성하고
`LocalMachine\Root` 와 `LocalMachine\TrustedPublisher` 에 자동 등록한다.
테스트 환경 외에 배포하지 말 것 (WHCP 정식 서명 아님).

## 실행

```powershell
# Agent + Dashboard (http://127.0.0.1:5000)
python agent.py --watch C:\path\to\watch_dir

# 콘솔 데모
python demo_inproc.py

# 시뮬레이터 (실제 암호화/명령 실행 없음, 가짜 이벤트만)
python tests\simulator.py --scenario {canary|encrypt|full}
```

기동 시 모드를 안내한다:

```
[agent] RmDetectorFlt ACTIVE — EDR mode (process tree + image load + entropy
        guard + susp-ext rename guard + auto-terminate)
```
또는
```
[agent] RmDetectorFlt inactive (driver not loaded) — user-mode watchers
        only (no in-kernel kill)
```

## 동작 확인

드라이버 로드 후, 다음 시나리오들을 테스트:

```powershell
# 1) Canary 직접 건드리기
echo "wipe" > C:\path\to\watch_dir\0_important_notes.xlsx
#   → Access is denied. agent 콘솔에 canary_blocked CRITICAL.

# 2) 의심 확장자로 rename
ren C:\path\to\watch_dir\test.docx test.docx.locked
#   → Access is denied. agent 콘솔에 blocked_susp_ext CRITICAL.

# 3) 고엔트로피 대량 쓰기 (암호화 시뮬레이션)
python tests\simulator.py --scenario encrypt
#   → entropy_spike 가 누적되다가 kernel_score_critical → auto_terminated.
```

agent 콘솔의 예:

```
▓▓▓▓▓ [minifilter/canary_blocked] Driver blocked canary write/rename/delete: ...
      (weight=95, total_score=95, level=CRITICAL)
▓▓▓▓▓ [minifilter/kernel_score_critical] In-kernel per-PID score crossed
      threshold (pid=12345, kscore=105) (weight=90, total_score=185,
      level=CRITICAL)
▓▓▓▓▓ [minifilter/auto_terminated] Driver auto-terminated pid=12345
      (kernel score=105, entropy hits=14) (weight=100, total_score=285,
      level=CRITICAL)
```

격리된 VM/테스트 환경에서만 사용할 것. **자체 서명 + auto-terminate** 조합은
실 사용자 환경에서 위험하다.

## 튜닝

`MinifilterDetector` 가 노출하는 in-kernel knob:

```python
detector.set_thresholds(
    score_critical=100,         # 커널 per-PID 점수 임계치 → auto-terminate
    entropy_threshold_x100=750, # 7.50/8.00 이상이면 high-entropy hit
    distinct_ext_alert=6,       # 한 PID 가 만진 distinct 확장자 수 알림
    write_burst_bytes=50*1024*1024,
)
detector.set_suspicious_extensions([".locked", ".crypt", ...])
detector.terminate_pid(1234)    # 즉시 ZwTerminateProcess
```

## 미구현 (후속 과제)

ETW 직접 구독, Authenticode 화이트리스트, intermittent encryption stream
context, 메모리 시그니처 스캔, PPL cmdline 접근, **WHCP 정식 서명**, 레지스
트리 / 네트워크 filter (현재 파일·프로세스 센서만), 백업 (pre-write
shadow copy) — 모두 본격 EDR 와의 갭.
