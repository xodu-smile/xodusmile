# Ransomware Detection Agent (Prototype)

보고서 *"랜섬웨어 탐지 솔루션 설계 보고서"*의 P0/P1 항목 중
사용자 모드에서 구현 가능한 것들을 골라 만든 학습용 프로토타입.

> 교육 / 연구 목적 전용. 실제 EDR 대체로 사용하지 말 것.

## 보고서 매핑

| 보고서 항목 | 구현 위치 | 비고 |
|---|---|---|
| 2.2 Canary 파일 모니터링 (P0) | `detectors/canary.py` | 폴링 + SHA256 |
| 2.3 VSS 삭제 탐지 (P0) | `detectors/process_cmdline.py` | WMI 기반 |
| 2.4 단일 프로세스 대량 I/O (P0) | `detectors/mass_io.py` | watchdog + 엔트로피 + 매직바이트 |
| 2.9 BCD 조작 (P1) | `detectors/process_cmdline.py` | 같은 룰 엔진 |
| 5.2 다중 시그널 가중치 합산 | `scoring.py` | 시간 윈도우 + threshold |

## 아키텍처

```
┌───────────────────────────────────────────────────┐
│  Agent                                            │
│   ├─ CanaryDetector       ─┐                      │
│   ├─ MassIODetector       ─┼─> ScoringEngine ──┐  │
│   └─ ProcessCmdlineDetector ┘                  │  │
│                                                 ▼  │
│                                          EventStore │
│                                          (SQLite)   │
└────────────────────────────────────────┬───────────┘
                                         │
                                         ▼
                           Flask Dashboard (:5000)
```

핵심 설계 결정:
- **시그널 ≠ 알람**. 모든 탐지기는 가중치 있는 시그널만 발생.
  ScoringEngine이 시간 윈도우(120초) 내 누적 점수로 위협 수준을 판정.
- **Canary는 강한 단일 시그널**(weight=80) — Critical 즉시 도달.
- **VSS/BCD는 pre-encryption** 시그널이라 weight 60~70.
- **엔트로피/매직바이트는 약한 시그널**(weight 8~12) — 다른 시그널과 결합 필요.
  보고서 5.2의 "단일 시그널 탐지는 위험" 통찰을 그대로 반영.

## 설치

```bash
pip install -r requirements.txt
```

Linux/macOS에서는 watchdog과 Flask만 설치되고, WMI/pywin32는 건너뜀.
이 경우 `ProcessCmdlineDetector`는 passive 모드로 동작 (시뮬레이터에서
`submit_external()`로 이벤트 주입 가능).

## 실행

### 1) Agent + Dashboard
```bash
python agent.py --watch ./test_watch_dir
```
브라우저에서 http://127.0.0.1:5000 접속.

### 2) In-process 데모 (대시보드 없이 콘솔로 검증)
```bash
python demo_inproc.py
```
모든 시나리오를 순차 실행하면서 점수 변화를 콘솔로 확인.

### 3) 외부 시뮬레이터로 자극
별도 터미널에서:
```bash
python tests/simulator.py --scenario canary
python tests/simulator.py --scenario encrypt
python tests/simulator.py --scenario full
```

## 안전성 노트

`tests/simulator.py`는 **실제 암호화를 수행하지 않는다**:
- 더미 파일에만 동작 (사용자 데이터 건드리지 않음)
- 무작위 바이트로 덮어쓰기 (대칭키 암호 없음)
- VSS 삭제는 **에이전트에 가짜 이벤트 주입**으로만 시뮬레이션
  → 실제 `vssadmin delete shadows` 명령은 실행되지 않음
- BCD 조작도 동일하게 가짜 이벤트만

격리된 VM이나 자기 소유 테스트 환경에서만 실행할 것.

## 한계 (보고서 대비)

이 프로토타입에서 **빠진 것**:
- ❌ Minifilter 드라이버 (보고서 2.1) — 실시간 차단 불가, 사후 탐지만
- ❌ ETW 직접 구독 — WMI 폴링 기반이라 지연 ~1초
- ❌ 고급 화이트리스트 (보고서 3.3) — Microsoft 서명 검증 없음
- ❌ Intermittent encryption 블록 단위 분산 (보고서 2.11)
- ❌ 메모리 시그니처 스캔 (보고서 2.10)

학습용으로 위 한계를 한두 개씩 보강하면 좋은 후속 과제가 됨.

## 확장 아이디어

1. 화이트리스트 모듈 (`whitelist.py`) — Authenticode 서명 검증
2. ML 기반 행위 분류 (sklearn IsolationForest 같은 것)
3. 블록 단위 엔트로피 분산 → intermittent encryption 대응
4. Sigma rule 임포트 → 룰 엔진 확장
