# Spec: 인시던트 보고서 — 보안 전문가 관점 개선 (run 2026-06-11)

입력: `~/Downloads/RustyStealer.pdf` (2026-06-10 11:47:52, pid 10652, reason
`minifilter/kernel_rename_burst`, 격리+종료 성공) — 이 프로젝트(RansomGuard)가
실제로 생성한 보고서.

## 관찰된 결함 (PDF 증거)

| # | 결함 | 전문가 관점 영향 |
|---|------|------------------|
| F1 | 자동 차단 직후인데 위험 점수 0 / 위협 수준 INFO. 차단을 유발한 kernel_rename_burst 신호가 "이 프로세스 신호" 표·"최근 신호" 표 어디에도 없음. 피해 규모 전부 0개 | 보고서가 자기모순 — "대량 이름 변경으로 차단했다"면서 근거 신호·점수·피해가 모두 0. IR/법무 제출 불가 수준의 신뢰도 훼손 |
| F2 | 피해 범위가 신호 metadata 경로만 집계. 커널 burst 신호는 count+last_path 1건만 가짐 → "12건 burst"인데 "이름변경 0~1개"로 표기 | 피해 규모 과소보고. 헤드라인과 본문이 모순 |
| F3 | "최근 탐지 신호" 표가 무관한 PID(2344/3264/2896, OS 하우스키핑 삭제)를 라벨 없이 나열. PID 열 자체가 없음 | 분석가가 무관 이벤트를 침해 지표로 오인. 신호↔프로세스 귀속 불가 |
| F4 | 포렌식 필수 필드 부재: 실행파일 경로·SHA-256 해시·부모 프로세스(PPID/이름)·사용자 계정·탐지→대응 지연시간 | 해시 없이는 VT/인텔 조회 불가, 부모 없이는 감염 경로 추적 불가 |
| F5 | "(150 이상이면 자동 차단)" 문구 — 실제 차단은 점수와 무관한 단일 HIGH 신호 즉시 차단이었음 | 탐지 로직 오해 유발. 점수 0 + 차단됨의 모순을 키움 |
| F6 | IOC 섹션·기계가독(JSON) 산출물 없음 (원본 JSON은 KillAction 일부만) | SIEM/SOAR 인제스트, 플레이북 자동화 불가 |
| F7 | 신호 표 시각이 HH:MM:SS만 (날짜 없음) | 타임라인 재구성/상관분석 시 모호 |

## 근본 원인 (코드 확인)

- `IncidentReporter._build_markdown` 이 보고서 생성 시점에 **라이브 엔진을
  재조회** (`current_score()`, `recent_signals(limit=200)`). 신호는 120초
  윈도우에서 자동 퇴거되므로, 탐지~대응 사이에 시간이 흐른 경로(재시도,
  지연된 escalation, dedup 재보고)에서는 근거가 사라진 채 보고서가 생성됨.
  PDF가 그 실증. 인프로세스 재현(즉시 경로)은 정상 출력 — 즉 타이밍 의존.
- 커널 burst 신호 metadata 는 `count`/`last_path` 뿐 → 경로 집계 구조적 한계.
- (회귀 발견) 1ee4263 이 `engine.forget_pid()` 호출을 실수로 제거 →
  44ca918 의 "처치 후 위협 수준 자동 회복" 기능이 사일런트하게 죽어 있음.

## 요구사항

R1. **행동 시점 컨텍스트 캡처**: responder 가 차단 시점의 score/level/트리거
    신호를 KillAction 에 담아 전달. 보고서는 라이브 엔진이 아니라 이 캡처를
    1차 근거로 사용 (엔진 조회는 보조, 트리거 신호는 퇴거됐어도 항상 표시).
R2. **포렌식 필드**: exe 경로, SHA-256(청크 해시, 크기 상한, best-effort),
    사용자 계정, PPID+부모 이름, 탐지→대응 지연(ms). psutil 실패 시 공란.
R3. **피해 집계 정합화**: burst count 를 최소 건수 바닥으로 사용 —
    "이름변경 최소 12건 (경로 확인 1건)" 식으로 모순 제거.
R4. **신호 표 개선**: PID 열 추가, 인시던트 PID 행 표시(◀), "최근 탐지 신호"
    를 "다른 프로세스 신호 (참고용 — 본 사건과 무관할 수 있음)"로 명시 분리,
    시각에 날짜 포함.
R5. **점수 문구 수정**: 차단 시점 점수 표기 + 차단 근거(단일 고위험 신호 즉시
    차단 vs 누적 점수 150 임계 초과)를 명시.
R6. **IOC 섹션 + JSON 사이드카**: 보고서에 IOC 블록(해시/경로/확장자/기법 ID),
    `.md` 옆에 동일 베이스명 `.json` (action+damage+signals+attack) 저장.
R7. **forget_pid 회귀 복원**: 종료 성공 시 `_record()` *이후* 호출 (보고서가
    근거를 캡처한 뒤). R1 캡처 덕에 이후 캠페인 확정과도 충돌 없음.
R8. 기존 비전공자용 한국어 톤 유지 — 전문가 내용은 "자세한 정보" 이하 배치.
    기존 테스트 호환(새 KillAction 필드는 기본값 보유).

## 구현 계획

1. `responder.py`
   - `KillAction` 확장(기본값 있는 신규 필드): `exe_path`, `exe_sha256`,
     `username`, `ppid`, `parent_name`, `score_at_action`, `level_at_action`,
     `trigger_signal`(dict), `detect_ts`.
   - `_lookup` → 프로세스 상세(이름/cmdline/exe/username/ppid/부모이름) 수집.
   - `_hash_exe(path)`: 청크 SHA-256, 64MB 상한, 실패 시 "".
   - `_dispatch`/`_sweep_window` 가 trigger Signal·score·level 을
     `_respond_to_pid(..., trigger=, score=, level=)` 로 전달.
   - `_respond_to_pid` 끝에서 `result.terminated`면 `engine.forget_pid(pid)`
     (R7, `_record()` 이후).
2. `incident_report.py`
   - `_build_markdown`: action 캡처 우선 사용. 트리거 신호를 pid_signals 에
     항상 포함(엔진에 없어도). 위협 수준 섹션 재작성(R5). 포렌식 섹션(R2),
     IOC 섹션(R6) 추가. `_signal_table` 에 PID 열+날짜+인시던트 표시(R4).
     `_damage_headline`/`_damage_lines` 에 burst 바닥값 반영(R3).
   - `_write_file` 옆에 JSON 사이드카 생성(R6).
3. `tests/` — 회귀 테스트: 엔진이 빈 상태에서도(=PDF 시나리오) 보고서에
   트리거 신호·점수·피해가 남는지; KillAction 신규 필드 기본값; burst 바닥값
   집계; forget_pid 복원; JSON 사이드카 스키마.

## 비범위

- 디텍터 신호 metadata 확장(커널 드라이버 변경 필요).
- 대시보드 UI 변경.
