# 설계 근거 문서 — 모든 신호·가중치·임계값은 왜 그 값인가

> 이 문서는 RansomGuard EDR의 **모든 탐지 신호(weight/severity), 임계값, 게이트
> 정책의 수치적 근거**를 소스 코드와 1:1 로 대응시켜 설명한다.
> 보고서(`CAPSTONE_REPORT.ko.md`) 5-2 절의 상세 부록이며, 각 수치는 코드의
> 상수 정의와 동일하다(검증: `pytest tests/` 430 케이스).

---

## 1. 점수 체계의 뼈대 — 왜 "시간 윈도우 가중 합산"인가

### 1-1. 단일 신호 판정의 문제

행위 신호는 하나하나가 *확률적*이다. 고엔트로피 쓰기는 압축 파일 저장에서도
나오고, 대량 파일 변경은 백업에서도 나온다. 단일 신호로 차단하면 오탐이
업무를 끊고, 단일 신호를 무시하면 미탐이 피해를 키운다. 그래서:

- **여러 독립 신호를 합산**한다 — 정상 작업은 신호 1~2개를 내지만,
  랜섬웨어는 *반드시* 여러 신호를 동시에 낸다(암호화 + 확장자 변경 +
  협박문 + VSS 삭제는 한 묶음의 행위다).
- **시간 윈도우(120초) 안에서만** 합산한다 — "어제의 압축 작업 + 오늘의
  레지스트리 변경"이 합쳐져 거짓 경보가 되는 것을 막고, 위협이 끝나면
  점수가 자연 감쇠한다.

### 1-2. 왜 120초인가 (`scoring.SIGNAL_WINDOW_SECONDS = 120`)

- **하한 근거:** 실측에서 현대 랜섬웨어의 암호화 burst 는 수 초~수십 초
  단위로 진행된다. 윈도우가 너무 짧으면(예: 10초) *저속 은닉형*(파일당
  수 초 간격으로 암호화)의 신호들이 서로 만나지 못해 합산이 무력화된다.
  120초면 파일당 5~8초 간격의 저속 공격도 윈도우 안에 15개+ 신호가 겹친다.
- **상한 근거:** 윈도우가 너무 길면(예: 1시간) 정상 작업의 산발 신호가
  계속 누적돼 베이스라인 점수가 상승하고, 종료된 위협의 잔류 경보가
  오래 남는다. 120초는 "사람이 대시보드에서 상황을 인지·대응하는 시간
  단위"와도 일치한다.

### 1-3. 등급 임계값 30/60/100/150 의 보정(calibration) 논리

| 점수 | 등급 | 보정 기준(어떤 조합이 이 등급에 와야 하는가) |
|---:|---|---|
| 30 | LOW | 약한 휴리스틱 1개(지속화 30, 의심 PS 30~40)만으로는 "관심" 수준에 머문다 |
| 60 | MEDIUM | 사보타주 명령 1개(BCD 50~60) 또는 약한 신호 2~3개 조합 — "주의" |
| 100 | HIGH | **지상 진실 1개(카나리 80) + 보조 신호 1개** 또는 사보타주 2개 — 여기부터 "공격 진행 중"으로 간주 |
| 150 | CRITICAL | 협박문 확산(90)+카나리(80), 또는 VSS 삭제(70)+BCD(55)+α 등 **서로 다른 단계의 행위가 동시 관측**될 때만 도달 |

즉 임계값이 먼저 있고 가중치를 끼워 맞춘 것이 아니라, **"어떤 증거 조합이
어느 등급에 도달해야 하는가"라는 시나리오 집합을 먼저 정의**하고, 그
연립조건을 만족하도록 가중치·임계값을 함께 결정했다. 대표 보정 시나리오:

- 카나리 1회(80)만으로는 HIGH(100) 미달 — 미끼 파일을 사용자가 실수로
  여는 경우가 *드물지만 존재*하므로, 단독으로는 MEDIUM 까지만.
- 카나리(80) + 암호화 정황 아무거나 1개(매직 소실 12, burst 25 등) ≥ 100
  → HIGH. 미끼 변조 + 실제 암호화 흔적이면 사실상 확정이다.
- 정상 압축 작업: 고엔트로피 쓰기(8)가 여러 번 나도 매직 소실·확장자
  변경·burst 가 없으면 8×n 이 LOW(30)를 넘기 어렵고, 넘더라도 MEDIUM
  미달 — 압축 파일은 애초에 `NATIVE_HIGH_ENTROPY_EXTS` 로 신호 자체가
  제외된다(§4-2).

### 1-4. weight 와 severity 의 2채널 설계

모든 신호는 **weight(점수 기여)** 와 **severity(단발 심각도)** 를 따로 가진다.
이유: 두 값은 서로 다른 질문에 답한다.

- `weight` → "이 신호가 **종합 상황 인식**(대시보드 등급)에 얼마나
  기여하는가" — 누적·합산되는 양.
- `severity` → "이 신호 **하나만으로** 대응(차단/종료)을 검토할 가치가
  있는가" — responder 의 트리거. HIGH/CRITICAL + PID 명시 신호만
  responder 가 검토하며, CRITICAL 은 단독으로, HIGH 는 보강 증거
  (corroboration)가 있을 때만 실행한다(§6).

예: `vssadmin delete shadows` 는 weight 70(단독으로는 CRITICAL 점수 미달)
이지만 severity 는 CRITICAL — *점수와 무관하게* 그 즉시 해당 PID 와 부모
프로세스를 차단할 가치가 있는 행위이기 때문이다. 반대로 `modify_burst` 는
weight 25 로 점수에는 크게 기여하지만 severity HIGH 라서 단독으로는
종료로 이어지지 않는다(보강 증거 필요).

---

## 2. 가중치 티어 — 5단계 위계와 그 근거

전 신호의 가중치는 다음 5개 티어로 위계화돼 있다. 티어를 가르는 질문은
단 하나: **"정상 소프트웨어가 이 행위를 할 확률이 얼마나 되는가"**.

| 티어 | weight | 의미 | 대표 신호 |
|---|---:|---|---|
| T1 텔레메트리 | 1~5 | 정상에서도 흔함. 기록·상관용, 점수 기여 미미 | `process_create` 1, `file_delete` 3, `registry_watched` 5 |
| T2 약한 암호화 정황 | 8~25 | 정상에서도 가끔 발생(압축, 대량 저장). *조합*돼야 의미 | `high_entropy_write` 8, `magic_bytes_lost` 12, `modify_burst` 25 |
| T3 의심 행위 패턴 | 30~45 | 정상 용도가 분명히 존재하지만 공격 전조로 흔용 | 지속화 30~35, LOLBin 스테이징 35~45, 협박문(내용확인) 45 |
| T4 사보타주/회피 | 50~70 | 정상 운영에서 *드물고*, 랜섬웨어 킬체인의 정형 단계 | Defender 무력화 55, 로그 삭제 55, VSS 삭제 70, 위장 60 |
| T5 지상 진실 | 80~90 | 정상 프로세스가 *절대* 하지 않는 행위. 단독으로 거의 확정 | `canary_modified` 80, `ransom_note_spread` 90, 자기 서비스 변조 80 |

티어 경계의 수치 논리:

- **T5 ≥ 80:** 지상 진실 1개 + T2 아무거나 1개로 HIGH(100)에 도달해야
  한다 → 최소 80 (80+25=105, 80+12=92+카나리는 보통 복수 트립).
  단, 단독으로 HIGH(100)를 넘지 않게 90 이하 — 100% 확신이 아닌 한
  단일 관측만으로 점수 채널이 "공격 진행 중"을 선언하지 않는다는 원칙.
  (응답은 severity CRITICAL 채널이 corroboration 규칙으로 따로 처리.)
- **T4 50~70:** 사보타주 2개(예: VSS 70 + BCD 55 = 125)면 HIGH 를 확실히
  넘되, 1개로는 MEDIUM 에 머물러야 한다(50~70 < 100). 운영자가 진짜로
  `vssadmin delete shadows` 를 칠 수도 있기 때문(드물지만 0이 아님).
- **T3 30~45:** 1개로 LOW(30) 진입은 허용하되 MEDIUM(60)은 불허.
  지속화 + 다운로더 + 난독화 PS 처럼 3개쯤 모이면(30+35+40=105) HIGH —
  "전조 행위만 3종이 한 윈도우에" 는 실제로 이상하다.
- **T2 8~25:** 가장 오탐이 잦은 구간이라 의도적으로 낮다. 암호화가
  진짜 진행되면 이 신호들은 *수십 번* 발생해 어차피 점수가 치솟는다 —
  단가를 낮춰도 탐지력 손실이 없고, 단발 오탐의 피해만 줄어든다.

---

## 3. 카나리 탐지기 (`detectors/canary.py`)

| 항목 | 값 | 근거 |
|---|---|---|
| `CANARY_WEIGHT` | **80** | T5. 미끼 파일은 사용자·OS 가 건드릴 *업무상 이유가 없는* 파일이므로 변조=거의 확정. 단 사용자가 호기심에 열어 저장하는 사고가 가능하므로 단독 100+ 는 부여하지 않음(§2). severity 는 CRITICAL — 실제 암호화가 시작되면 카나리는 보통 *여러 개가 연쇄* 트립해 80×n 으로 즉시 CRITICAL 점수에 도달한다. |
| 파일명 5종 | `!!_DO_NOT_TOUCH_!!.docx`, `0_important_notes.xlsx`, `00_archive_index.pdf`, `~$confidential_backup.docx`, `zzz_old_records.txt` | 랜섬웨어 다수가 디렉터리를 **정렬 순서로 순회**한다 → `!`, `0`, `~`(앞), `zzz`(뒤)로 정렬 양 끝을 모두 커버해 *암호화 초기에* 트립되도록 함. 확장자는 랜섬웨어 타깃 상위(docx/xlsx/pdf/txt)로 위장. |
| 폴링 주기 | 1.5초 | SHA-256 해시 폴링. 1.5초는 "수 초 내 대응" 요구와 폴링 부하(파일 5개×디렉터리 수)의 절충. watchdog 이벤트가 아닌 폴링인 이유: 카나리는 *무결성*(내용 해시)이 기준이라 이벤트 누락에도 안전한 주기 검증이 맞다. |
| 트립 후 처리 | 해시 갱신/추적 중단 | 같은 파일로 알람이 폭주하지 않게 1회 알림 후 상태 갱신. |

**교차 신호 부스트(canary boost):** 카나리 트립 시 30초간 mass_io 의
엔트로피 기준을 7.5→6.8 로 낮추고 가중치를 ×1.5 한다. 베이즈적으로,
카나리 트립 후에는 "랜섬웨어가 활동 중"일 사전확률이 급등하므로 같은
증거에 더 큰 확신을 부여하는 것이 옳다. 30초는 부스트가 만든 추가 오탐
위험이 *카나리 오탐 1회당 30초*로 한정되도록 하는 안전 상한이다.
(`CANARY_BOOST_WINDOW=30.0`, `CANARY_BOOST_MULTIPLIER=1.5`,
`ENTROPY_THRESHOLD_BOOST=6.8`)

---

## 4. 대량 I/O 탐지기 (`detectors/mass_io.py`)

### 4-1. 신호와 가중치

| 신호 | weight | severity | 발화 조건 | 왜 이 가중치인가 |
|---|---:|---|---|---|
| `high_entropy_write` | 8 | MEDIUM | 샘플 4KB 엔트로피 ≥ 7.5(부스트 시 6.8) AND 매직바이트 미인식 AND 타깃 확장자 AND 비(非)압축·미디어 형식 | T2 최하단. 압축 파일 저장·암호화 컨테이너 등 정상 고엔트로피 쓰기가 존재 → 단발 기여를 최소화. 진짜 암호화면 파일 수십 개에서 연발돼 8×n 으로 충분히 누적된다. |
| `magic_bytes_lost` | 12 | HIGH | 직전에 알려진 형식(PE/PDF/ZIP/JPEG…)이던 파일의 헤더가 인식 불가로 *변함* | T2 중단. 엔트로피와 달리 **변화 기반**(상태 전이) 증거라 더 특이적 → 8보다 높게. 그러나 정상 재저장(포맷 변환)도 가능 → T4 미만. |
| `modify_burst` | 25 | HIGH | 10초 내 "암호화 특징 이벤트" 15개 이상 | T2 최상단. burst 카운터에는 *암호화 특징*(고엔트로피/매직소실/의심확장자)만 누적하므로 일반 대량 저장은 카운트 자체가 안 됨 → 특이도가 높아 25. |
| `suspicious_extension` | 15 (=5×3) | HIGH | `.encrypted`, `.locked`, `.wcry` 등 알려진 랜섬 확장자로 rename | 기본 단가 5 에 ×3 — 랜섬 확장자 rename 은 정상 용도가 사실상 없으나, 목록이 정적(신종 확장자 미수록)이라 T5 로 올리지는 않음. |

### 4-2. 임계값 근거

- **엔트로피 7.5 (`ENTROPY_THRESHOLD`)** — 섀넌 엔트로피 최대 8.0.
  실측 분포: 일반 텍스트/Office 문서 3~6, 실행파일 5~6.5, **압축/암호문
  7.5~8.0**. 7.5는 "정상 문서는 절대 안 넘고, 암호문은 거의 항상 넘는"
  경계값이다. AES 암호문의 4KB 샘플 엔트로피는 7.95+ 에 몰리므로 7.5는
  여유 있는 하한이며, 거짓 음성을 줄이는 쪽으로 설정했다. 거짓 양성
  (압축물)은 임계값이 아니라 **형식 제외 목록**으로 푼다(아래).
- **`NATIVE_HIGH_ENTROPY_EXTS` 제외 목록** — zip/jpg/mp4 등은 *원래부터*
  7.5+ 다. 이들을 엔트로피로 보는 것은 정보가 0 인 검사이므로 신호에서
  제외하고, 이들이 실제 암호화되면 *변화* 신호(매직 소실, 확장자 변경,
  burst)로 잡는다. 라이브 테스트에서 미디어 재저장이 오탐의 주범이었던
  실측 결과를 반영한 목록이다.
- **burst 15개/10초 (`BURST_THRESHOLD`/`BURST_WINDOW_SEC`)** — 사람의
  문서 작업은 분당 수 개 수준(10초에 1~3개)이고, 자동 저장·빌드도
  *암호화 특징* 이벤트는 내지 않는다. 반면 랜섬웨어는 초당 수~수십
  파일을 변조한다. 15/10초(=1.5개/초 지속)는 사람·정상 앱 상한과
  랜섬웨어 하한 사이의 분리대역에 있다. 발화 후 카운터를 비워 같은
  burst 로 점수가 무한 가산되는 폭주를 막는다.
- **샘플 4KB (`MAX_SAMPLE_BYTES`)** — 엔트로피는 표본 4KB 로도 ±0.1
  내 수렴한다(256 심볼 분포에 충분한 표본). 전체 파일을 읽으면 GB급
  파일에서 탐지기가 I/O 병목이 된다 — 정확도 손실 없이 비용을 상수화.
- **`NOISE_PATH_FRAGMENTS` / `NOISE_EXTENSIONS`** — 브라우저 캐시,
  패키지 앱 캐시, `.tmp/.log/.etl` 등은 정상 시스템이 *끊임없이*
  고엔트로피로 쓰는 경로다. 실검체 detonation 중 이 경로들이 이벤트
  스트림을 지배하며 점수를 CRITICAL 에 고정시킨 실측 사후분석에서
  도출된 목록이다(커밋 이력 참조). 사용자 문서가 이 경로에 있을 수
  없으므로 제외해도 미탐 위험이 없다.

---

## 5. 협박문 탐지기 (`detectors/ransom_note.py`)

### 5-1. 왜 "내용 기반"으로 재설계했나

v1 은 파일명 정규식만 봤다 → ① 무작위 이름 노트(`A7F3C.txt`)를 통째로
놓치고, ② `readme.txt` 2개만으로 CRITICAL 을 띄우는 오탐이 있었다.
v2 는 **내용 지표**로 판정한다: 이름이 무엇이든 내용이 협박문이면 잡고,
이름만 매칭된 것은 약하게 본다.

### 5-2. 내용 점수표 — 왜 강/약 2단계인가

| 지표 | 점수 | 분류 | 근거 |
|---|---:|---|---|
| 암호화폐 지갑 주소(BTC bech32/legacy, ETH, Monero 정규식) | +2 | **강** | 정상 텍스트 파일에 지갑 주소가 등장할 확률은 사실상 0(암호화폐 관련 메모 정도). 협박문에는 거의 100% 존재 — 결제 수단이 협박의 목적이므로. |
| `.onion` 주소 | +2 | **강** | Tor 히든서비스 주소가 일반 문서에 나올 일이 없음. 협박문 연락 채널의 정형. |
| "your files have been encrypted" 류 문구 | +1 | 약 | 협박문에 흔하지만 보안 문서·IT 가이드("files are encrypted at rest")에도 나옴. |
| 복호화 유도 문구(decryption key/tool…) | +1 | 약 | 동상. |
| 결제 용어(bitcoin/ransom/payment…) | +1 | 약 | 뉴스 스크랩·보고서에도 등장 가능. |
| 연락 채널(이메일/Tox/Telegram/protonmail) | +1 | 약 | 이메일 주소는 평범한 문서에 흔함. |
| 협박 문구(deadline/permanently lost/price will double…) | +1 | 약 | 동상. |

**확정(confirmed) 조건: 강 지표 ≥ 1개 AND 합계 ≥ 3 (`CONTENT_CONFIRM_SCORE`)**

- "강 지표 필수" — 약 지표만 여러 개로 confirmed 되는 경로를 의도적으로
  차단했다. IR 보고서나 보안 교육 문서는 약 지표를 4~5개 담을 수 있지만
  지갑 주소·onion 은 담지 않는다. 이 한 줄이 보안 문서 오탐을 구조적으로
  제거한다.
- "합계 ≥ 3" — 강 지표 1개(+2)만으로도 부족하고 약 지표 1개 이상이
  동반돼야 한다. 우연히 지갑 주소만 적힌 메모(코인 투자 메모)를
  걸러내는 2차 방어선.

### 5-3. 신호 가중치·확산 임계

| 신호 | weight | severity | 조건 | 근거 |
|---|---:|---|---|---|
| `ransom_note_dropped`(이름만) | 15 | MEDIUM | 이름 패턴 매칭, 내용 미확인 | 단독으론 위협 아님(LOW 진입에도 미달 15<30). 같은 윈도우의 다른 신호와 합산될 때만 의미 — "힌트" 포지션. |
| `ransom_note_dropped`(내용 확인) | 45 | HIGH | content confirmed | T3 상단. 내용 확인된 협박문 1개는 강한 증거지만, 확산 전이므로 암호화 신호와의 조합(45+25+12 등)으로 HIGH 에 도달하게 설계. |
| `ransom_note_dropped`(카나리 부스트 중) | 90 | CRITICAL | 카나리 트립 후 30초 내 | 카나리+협박문 동시면 사실상 확정 → T5 대우. |
| `ransom_note_spread` | **90** | CRITICAL | (a) 내용 확인 노트가 **3개+ 디렉터리** 또는 (b) 이름 매칭 노트 3개+ 디렉터리 AND 윈도우 내 실제 암호화 활동 | T5. "여러 폴더에 협박문 살포"는 랜섬웨어 외의 행위자가 없다. 90인 이유: 단독으로 MEDIUM 후반 — 점수 채널에서도 단발 최고 단가. 실제로는 카나리·암호화 신호와 함께 와 즉시 CRITICAL 점수가 된다. |
| `SPREAD_DIR_THRESHOLD` | 3 | — | v1 의 2 → 3 상향 | 정상 프로젝트 2개 폴더에 같은 `README.txt` 가 있는 경우는 흔하지만 3개 폴더 + 60초 내 *신규 생성*은 드묾. 오탐 실측 후 상향. |
| `SPREAD_WINDOW_SEC` | 60초 | — | 확산 집계 시간창 | 랜섬웨어의 노트 살포는 암호화와 동시 진행(분당 수십 폴더). 60초는 살포 속도를 충분히 담으면서, 시간상 무관한 노트 2개가 우연히 합산되는 것을 막는다. |
| `MAX_NOTE_BYTES` | 64KB | — | 이보다 큰 파일은 후보 제외 | 협박문은 짧다(보통 1~4KB). 64KB 상한은 대용량 파일을 읽는 비용과 TOCTOU 메모리 폭주를 차단. |

추가 안전장치: 이름-매칭 확산의 corroboration 판정에서 **노트 자신의
신호는 제외**(노트가 노트를 보강하는 순환 차단), 신뢰 actor 의 신호도
제외. 시작 시 이미 존재하던 노트는 baseline 으로만 기록(과거 사건으로
새 알람을 내지 않음). 심볼릭 링크 거부(워치 트리 밖 파일 읽기 차단).

---

## 6. 명령어 룰셋 — 33룰의 가중치 근거 (`detectors/process_cmdline.py`)

룰은 6개 군으로 나뉘며, 군 안에서의 가중치 차등은 "정상 사용 빈도"와
"공격 결정성"의 곱으로 정했다.

### 6-1. VSS/백업 파괴 (T1490) — 군 내 최고 가중치

| 룰 | weight | severity | 근거 |
|---|---:|---|---|
| `vssadmin_delete_shadows` | **70** | CRITICAL | 랜섬웨어 킬체인의 가장 정형화된 단계("암호화 전 복구 차단"). 정상 운영에서 전체 섀도 삭제는 극히 드묾(디스크 정리 시에도 보통 GUI/정책 경유). 70 = T4 최상단: 단독 MEDIUM, 사보타주 1개만 더 동반해도 HIGH. severity CRITICAL → corroboration 없이 즉시 대응 + **부모 프로세스 동시 종료**(vssadmin 은 일회성이라 죽여봐야 늦음 — 그것을 띄운 본체를 죽인다, §9-3). |
| `wmic_shadowcopy_delete` | 70 | CRITICAL | 같은 행위의 WMI 경로. 동일 가중치. |
| `powershell_remove_shadowcopy` | 70 | CRITICAL | 같은 행위의 PowerShell/CIM 경로. 도구가 달라도 행위 단가는 동일해야 우회 유인이 없다. |
| `wbadmin_delete_catalog` | 60 | HIGH | 백업 *카탈로그* 삭제 — 복구 방해지만 섀도 삭제보다 파급이 한 단계 낮고, 백업 재구성 시 정상 사용이 가능 → 70-10. |
| `vssadmin_resize_shadowstorage` | 55 | HIGH | 섀도 저장소 축소로 기존 섀도를 *간접* 증발시키는 우회 기법. 직접 삭제보다 한 단계 낮게 — 스토리지 관리 목적의 정상 resize 가 존재. |

### 6-2. BCD/부팅 변조 (T1490)

| 룰 | weight | 근거 |
|---|---:|---|
| `bcdedit_safeboot` | 60 | 안전모드 강제 부팅은 "AV 가 안 뜨는 환경에서 암호화"하는 고전 수법(예: Snatch). 정상 용도는 트러블슈팅뿐 → T4 중상단. |
| `bcdedit_recovery_disabled` | 55 | 복구 환경 비활성화. 배포 이미지 커스터마이징이라는 정상 용도가 소수 존재 → 60-5. |
| `bcdedit_ignore_failures` | 50 | 부팅 실패 무시 정책 — 위 둘보다 단독 파급이 작아 군 최하단. |

### 6-3. Defender/방어 무력화 (T1562.001)

| 룰 | weight | 근거 |
|---|---:|---|
| `defender_disable_realtime` | 55 | 실시간 보호 해제·서비스 중지. 관리자/테스트 환경에서의 정상 사용이 실재하므로 CRITICAL 이 아닌 HIGH/55. 단 레지스트리 콜백 쪽(`registry_kernel`)에서 *서비스 키 변조*로 잡히면 70(§8) — 커널 관측이 더 확정적이기 때문. |
| `defender_disable_via_registry` | 55 | 같은 행위의 reg.exe 경로. |
| `defender_add_exclusion` | 45 | 예외 등록은 무력화의 *준비* 단계고, 개발자가 빌드 디렉터리를 제외하는 정상 사용이 흔함 → 55-10. |
| `smartscreen_disable` | 35 | SmartScreen/PUA 는 보조 방어층 — 핵심 방어 해제보다 한 티어 낮음(MEDIUM). |
| `netsh_firewall_off` | 45 | 방화벽 전체 해제. 랜섬웨어 측면 이동 준비 단계지만 트러블슈팅 정상 사용도 흔함. |
| `bitlocker_disable` | 50 | 보호 해제 후 재암호화(공격자 키로) 준비 단계. |

### 6-4. 흔적 삭제(anti-forensics, T1070)

| 룰 | weight | 근거 |
|---|---:|---|
| `wevtutil_clear_log` / `powershell_clear_eventlog` | 55 | 이벤트 로그 클리어 — 정상 운영에서 거의 없음(디스크 절약 목적도 보존 정책으로 함). 침해 후 정리의 정형. |
| `fsutil_usn_delete` | 60 | USN 저널 삭제는 로그 클리어보다 더 드물고 더 의도적(파일 활동 추적 자체를 지움) → +5. |
| `cipher_wipe_free_space` | 55 | 빈 공간 영구 소거 — 삭제 원본의 복구를 차단. 퇴역 장비 처리라는 정상 용도가 소수 존재. |

### 6-5. LotL 암호화·LOLBin·유출 — "정상 도구의 무기화"

| 룰 | weight | severity | 근거 |
|---|---:|---|---|
| `cipher_efs_encrypt` | 45 | HIGH | OS 내장 EFS 로 파일 암호화 — 자체 암호화 코드 없는 랜섬웨어의 수법. 단 EFS 는 *정상 기업 기능*이므로 T3 상단에서 멈추고 조합으로 승격. |
| `bitlocker_abuse_enable` | 60 | HIGH | BitLocker 강제 활성화(공격자 키) — 디스크 전체를 인질화하는 강력한 수법이라 cipher 보다 높음. 그러나 IT 부서의 정상 배포 작업이기도 해서 **의도적으로 CRITICAL 이 아닌 HIGH**(코드 주석에 명시) — corroboration 채널로 검증 후 대응. |
| `certutil_download` | 45 | HIGH | certutil 의 URL 다운로드는 MS 문서화된 LOLBin 남용 1순위. 정상 인증서 관리에서 `-urlcache -f http` 조합은 거의 없음. |
| `certutil_decode_payload` | 35 | MEDIUM | base64 디코드는 스테이징 단계 — 다운로드보다 결정성 낮음. |
| `bitsadmin_transfer` | 35 | MEDIUM | BITS 전송 — 레거시 스크립트의 정상 사용 잔존. |
| `esentutl_raw_copy` | 35 | MEDIUM | 잠긴 파일 raw 복사(NTDS 탈취 등) — DB 유지보수 정상 사용 존재. |
| `wmic_process_call_create` | 40 | HIGH | WMI 프록시 실행 — 원격 관리 정상 사용이 있으나 랜섬웨어 측면 전파의 정형. |
| `kernel_service_create` | 55 | HIGH | `sc create type= kernel` — BYOVD(취약 드라이버 반입으로 커널에서 EDR 무력화) 전조. 드라이버 설치는 설치 프로그램의 정상 행위이기도 해 T4 중단. |
| `archive_password_staging` | 30 | MEDIUM | `7z a -p…` 암호 압축 — 이중 갈취 유출 준비의 정형이지만 *백업·개인 용도 정상 사용이 매우 흔함* → T3 최하단. |
| `rclone_exfil` | 35 | MEDIUM | rclone 대량 이동 — 클라우드 백업 정상 사용 존재. |

### 6-6. 지속화·실행 패턴

| 룰 | weight | 근거 |
|---|---:|---|
| `schtasks_persistence` | 35 | SYSTEM 권한 + 자동 트리거 조합만 매칭(일반 작업 등록은 제외) — 그래도 배포 도구의 정상 사용이 있어 T3. |
| `run_key_persistence` | 30 | Run 키 등록은 설치 프로그램의 일상 — T3 최하단. |
| `powershell_obfuscated_exec` | 40 | 40자+ base64 `-enc` — 정상 자동화도 enc 를 쓰지만(원격관리), 길이 조건으로 특이도를 높임. |
| `powershell_downloader` | 35 | IWR/WebClient 인메모리 다운로드 — DevOps 스크립트 정상 사용 흔함. |
| `powershell_bypass_policy` | 30 | `-ep bypass -w hidden` *조합* — 단독 bypass 는 너무 흔해서 hidden 동반 시만. |

**룰셋 전반의 원칙:** 같은 행위는 도구(cmd/wmic/PowerShell)가 달라도
같은 가중치 — 공격자가 "더 싼 경로"로 우회할 유인을 없앤다. 그리고
모든 룰은 `process_cmdline`(WMI), `process_watcher`(psutil),
`process_kernel`(커널 콜백) 3개 소스가 **동일 룰셋을 공유**
(`evaluate_cmdline`) — 탐지 일관성과 소스 다중화(한 소스가 놓쳐도 다른
소스가 잡음)를 동시에 얻는다.

---

## 7. 프로세스 행위 탐지기 (`detectors/process_watcher.py`)

| 신호 | weight | severity | 조건 | 근거 |
|---|---:|---|---|---|
| `process_masquerade` | **60** | HIGH | 핵심 시스템 바이너리 이름(svchost 등 19종)인데 이미지가 System32/SysWOW64 밖 | T4. 위장은 never-kill 면역·신뢰를 *가로채려는* 적극적 기만(T1036.005)이라 정상 용도가 0에 가깝다. 그래도 CRITICAL 이 아닌 이유: 포터블 도구를 시스템 이름으로 복사하는 무지성 사례가 이론상 존재 + 경로를 못 읽으면 판정 자체를 안 하는 fail-safe(증거 없는 추측 금지)와 짝을 이뤄, corroboration 채널로 확정. |
| `suspicious_parent_child` | 40 | HIGH | Office/PDF/브라우저/explorer → 스크립트 호스트 체인 | T3 상단. "워드가 PowerShell 을 띄움"은 매크로 공격의 정형이지만, 플러그인·자동화가 일으키는 정상 사례가 실재 → 단독 종료 불가 포지션. |
| `child_fanout` | 40 | HIGH | 같은 부모가 5초 내 자식 12개+ | T3 상단. 랜섬웨어가 파일 단위로 작업 프로세스를 살포하는 패턴. 빌드 시스템·브라우저도 fan-out 하므로 40에서 멈춤. 신호에 **부모 PID 를 `pid` 로 실어** responder 가 본체를 직접 겨냥하게 함. |
| `process_write_burst` | 20 | MEDIUM | 단일 프로세스가 2초 내 50MB+ 쓰기(psutil io_counters) | T2. 커널 관측(35)보다 낮은 이유: psutil 의 write_bytes 는 모든 쓰기(정상 설치·다운로드 포함)를 합산하고 경로를 모른다 — 증거 품질이 낮으면 단가도 낮다. |

임계 근거: `FANOUT_THRESHOLD=12/5s` — 브라우저 시작 시 렌더러 동시
생성이 보통 5~10개라 그 위로 설정. `WRITE_BURST_BYTES=50MB/2s` — SSD
순차쓰기로도 사용자 작업이 2초에 50MB 를 넘기는 일은 대용량 복사/설치
정도이고, 이는 MEDIUM(점수 기여 20)이 감당할 수준의 오탐.

---

## 8. 커널 신호 (`minifilter_bridge.py`, `registry_kernel.py`, `process_kernel.py`)

### 8-1. 왜 커널 관측은 가중치가 더 높은가

같은 "대량 쓰기"라도 커널 미니필터 관측(`kernel_write_burst` 35)이
사용자 모드 psutil 관측(`process_write_burst` 20)보다 높다. 이유는
**증거의 품질**: 커널 이벤트는 ① 우회 불가(모든 I/O 가 필터를 통과),
② 경로 단위 노이즈 필터링이 가능, ③ PID 귀속이 정확(IRP 발행자)하기
때문이다. 가중치는 "행위의 위험도 × 증거의 신뢰도"다.

### 8-2. 파일 이벤트

| 신호 | weight | severity | 조건 | 근거 |
|---|---:|---|---|---|
| `kernel_write_burst` | 35 | HIGH | PID 당 4초 내 75MB+ 쓰기 | 75MB/4초 ≈ 19MB/s 지속 — 문서 작업·일반 앱 영역 밖, 대량 암호화·대량 복사 영역 안. 백업·설치가 오탐원이므로 T3 수준에서 corroboration 으로 확정. 발화 후 카운터 리셋 + 윈도우당 1회 디바운스로 폭주 방지. |
| `kernel_rename_burst` | 40 | HIGH | PID 당 5초 내 rename 20회+ | 대량 rename 은 대량 쓰기보다 정상 사례가 적다(파일 정리 도구 정도) → +5. 랜섬 확장자 부여 단계의 직접 관측. |
| `kernel_blocked_op` | 60 | HIGH | **격리된 PID** 의 쓰기/rename 을 커널이 차단 | T4. 이미 격리 판정을 받은 프로세스가 *계속 시도*하는 것 — 공격이 활성 상태라는 지상 진실(`GROUND_TRUTH_ENCRYPTION` 포함). 차단 자체는 커널이 했으므로 점수는 "후속 대응(종료) 촉진" 역할. |
| `file_delete` | 3 | LOW | 단일 파일 삭제 | T1. 단일 삭제는 가장 흔한 정상 행위(temp 청소). **상관 게이트**(§9-1): 같은 PID 가 암호화 신호를 낼 때만 점수 인정 — read→encrypt→원본삭제 패턴의 일부일 때만 의미. |
| `tamper_attempt` | 50 | HIGH | 보호 PID 핸들에 TERMINATE/VM_WRITE 요구(ObCallback 이 권한 박탈) | 보안 에이전트를 죽이려는 시도 — 작업관리자에서 사용자가 실수로 누르는 사례가 있어 T4 중단에서 corroboration 대기. |

`NOISY_PATHS` 16종: 실검체 detonation 사후분석에서 이벤트 스트림을
지배한 경로들(Unistore .dat 수천 rename, PSScriptPolicyTest, Edge
캐시…)을 제외 — *순수 오탐으로 점수가 CRITICAL 에 고정*되던 실측
문제의 직접 해결책.

### 8-3. 레지스트리 이벤트 (커널 `CmRegisterCallbackEx`)

| 신호 | weight | severity | 근거 |
|---|---:|---|---|
| `ransomguard_service_tamper` | **80** | CRITICAL | 자기 서비스 키 변조 = EDR 무력화 시도. 우리 서비스 키를 만질 정상 주체는 우리 설치자뿐 → T5. |
| `defender_service_tamper` / `defender_filter_tamper` | 70 | CRITICAL | WinDefend/WdFilter **서비스 키** 변조 — cmdline 룰(55)보다 높은 이유: 커널에서 본 서비스 키 직접 변조는 GUI/정책 경유 정상 변경이 아니라는 강한 증거. |
| `mdatp_sense_tamper` | 60 | HIGH | MDE Sense 서비스 — 미설치 환경이 많아 한 단계 낮음. |
| `defender_policy_tamper` | 60 | HIGH | 정책 키는 GPO 가 정상적으로 쓰므로 서비스 키(70)보다 낮음. |
| `defender_settings_tamper` | 55 | HIGH | 설정 키 — Defender 자신도 쓰는 키라 최하단 + 자기 텔레메트리 값 3종은 값 이름 단위로 무시(`_BENIGN_VALUES`). |
| `safeboot_tamper` | 55 | HIGH | SafeBoot 키 — bcdedit safeboot(60)와 같은 의도의 레지스트리 경로. |
| `system_policy_tamper` | 40 | MEDIUM | UAC/SmartScreen 정책 — 관리 도구 정상 사용 흔함. |
| `run_key_persistence` / `runonce_persistence` | 35 | MEDIUM | cmdline 룰(30)과 정합 + ctfmon 의 `internat.exe` 값은 무시(실측 스팸). |
| `registry_watched` | 5 | LOW | 워치 목록에 걸렸지만 분류 안 된 쓰기 — 텔레메트리 보존용. |

### 8-4. 커널 프로세스 이벤트

`process_kernel` 은 같은 cmdline 룰셋을 **커널 콜백 소스**로 다시 돌린다.
WMI 대비 ① 지연 50~500ms → 동기(첫 명령 실행 전), ② PEB 위조 무효
(커널 메모리에서 취득), ③ 단명 프로세스 누락 제거. `process_create`(1,
INFO)는 점수용이 아니라 보고서·대시보드 상관용 텔레메트리다.

---

## 9. 오탐 억제 게이트 — 왜 3중인가, 왜 각자 다른 층에 있나

세 게이트는 서로 다른 오탐원을 막는다. 하나로 합치면 사각지대가 생긴다.

### 9-1. 상관 게이트 (`CORRELATION_GATED_NAMES` = {`file_delete`})
- **막는 오탐:** OS 하우스키핑의 단발 삭제가 쌓여 유휴 머신을 CRITICAL
  로 밀던 인플레(실측).
- **방식:** 같은 PID 가 윈도우 내 *암호화 신호*를 냈을 때만 weight 인정.
- **미탐 안전성:** 랜섬웨어의 삭제는 정의상 암호화와 동반되므로 잃는
  것이 없다.

### 9-2. 행위자 신뢰 게이트 (`actor_trust.py`)
- **막는 오탐:** Defender 스캔/서비싱/WMI 재빌드 등 *정상 OS 작업*이
  부팅마다 점수를 부풀리던 문제.
- **방식:** PID 의 **디스크상 검증된 이미지 경로**(쓰기 보호 디렉터리
  + 이름 화이트리스트)로 신뢰 판정, 신뢰 actor 의 신호는 점수 제외.
- **2단 신뢰 등급이 핵심:** `TRUST_FULL`(Defender/서비싱 — 대량 파일
  churn 이 본업)과 `TRUST_REGISTRY_ONLY`(svchost — 레지스트리·하우스키핑만
  면제, **대량 파일 변조는 면제 불가**)를 분리. svchost 는 서비스
  하이재킹·인젝션의 최대 표적이라, "진짜 System32\svchost.exe" 라도
  파일 대량 변조는 채점한다.
- **fail-closed:** 경로 조회 실패(종료됨/권한) → 비신뢰 → 정상 채점.
  비용은 약간의 점수 노이즈, 이득은 미탐 0.
- **면제 불가 신호:** `GROUND_TRUTH_ENCRYPTION`(카나리, 매직 소실, 랜섬
  확장자, 협박문 확산, 커널 차단)은 신뢰 actor 여도 **항상 채점** —
  정상 시스템 컴포넌트는 이 행위를 절대 하지 않으므로, "신뢰 프로세스가
  이걸 했다"는 것 자체가 인젝션(T1055)/위장(T1036)의 증거다. 이 한 줄이
  "신뢰 게이트를 노리는 인젝션형 랜섬웨어"라는 사각지대를 막는다.

### 9-3. 운영자 허용목록 (`allowlist.py`)
- **막는 오탐:** 하드코딩할 수 없는 서드파티(백업/동기화/빌드) — 현장마다
  다르므로 운영자 런타임 등록.
- **방식:** 이름 항목 또는 **경로 접두사** 항목(권장 — `%TEMP%\veeamagent.exe`
  위장을 구조적으로 차단). 판정은 검증된 on-disk 경로로만, fail-closed.
  경로 접두사 비교는 **디렉터리 경계 단위**(`C:\Trusted` 가
  `C:\TrustedEvil\` 에 매칭되지 않음).
- **면제 불가 신호:** `_NEVER_EXEMPT_SIGNALS`(카나리, 협박문 확산,
  Defender 자기 비활성화) — 관리자가 백업 앱을 허용했더라도, 그 이름을
  위장한 악성코드의 카나리 침해까지 면제되면 안 되기 때문.

---

## 10. 대응 정책 — corroboration 기반 정밀 종료 (`responder.py`)

### 10-1. 왜 "점수 기반 일괄 종료"를 폐지했나

초기 설계는 종합 점수가 CRITICAL 을 넘으면 윈도우 내 모든 기여 PID 를
일괄 종료(sweep)했다. 실측 결과: 정상 Win11 휴리스틱(explorer→rundll32
체인, 브라우저 fan-out, 캐시 churn)이 PID 명시 HIGH 를 내고, 무관한
정상 burst 가 점수만 넘기면 **방관자 PID 전원이 never-kill 목록 하나에
목숨을 거는** 구조였다. 오탐 1건이 "경고 1건"이 아니라 "정상 프로세스
대량 학살"로 증폭된다 — 대응의 비대칭 위험. (커밋 `ab743d1`)

### 10-2. 현재 정책

| 신호 | 대응 |
|---|---|
| CRITICAL + PID | **즉시** 격리+종료 — CRITICAL 은 지상 진실(카나리·확산) 또는 사보타주 정형(VSS 삭제)에만 부여되므로 단독 신뢰 가능 |
| HIGH + PID + **보강 증거** | 격리+종료. 보강 증거 = ① 윈도우 내 실제 암호화/파괴 신호(트리거 자신 제외 — 자기 보강 순환 차단) 또는 ② 같은 PID 를 지목한 **서로 다른 탐지기 2개+** |
| HIGH + PID, 보강 없음 | **"observed only" 기록만** — 대시보드에 노출, 운영자 판단 대기. 죽이지 않는다 |
| 점수만 CRITICAL | 아무도 죽이지 않는다(sweep 없음) |

"서로 다른 탐지기 2개" 조건의 근거: 탐지기들은 관측 채널이 독립적
(파일 내용/커널 I/O/프로세스 메타/레지스트리)이라 오탐의 상관도가 낮다.
독립 채널 2개가 같은 PID 를 지목할 확률은 단일 채널 오탐 확률의 곱
수준으로 떨어진다.

### 10-3. 종료 안전장치

- **NEVER_KILL** (~40종): OS 핵심(죽이면 BSOD), 브라우저/탐색기(캐시
  churn 오탐 빈발 실측), 개발 도구, **자기 자신(python)**. 
- **PATH_VERIFIED** (19종): never-kill 중 "System32 에서만 실행되는"
  이름들은 경로 검증 — `%TEMP%\svchost.exe` 사칭은 면역 박탈. 경로를
  못 읽으면(PPL) 보호 유지: *적극적 증거 없이는 면역을 벗기지 않는다*.
- **부모 승격(`ESCALATE_CHILD_NAMES`):** vssadmin 등 일회성 도구는
  차단 시점에 이미 종료됐거나 never-kill 이다. 죽일 대상은 그 도구를
  띄운 **부모(랜섬웨어 본체)** — LOLBin 신호에 한해 부모를 함께 종료.
- **`forget_pid`:** 종료 성공 시 그 PID 의 신호를 라이브 윈도우에서
  즉시 제거 → 위협 제거 후 대시보드가 수동 초기화 없이 "안전"으로 자동
  복귀(잔류 경보 제거). 실패 시엔 유지(위협이 끝나지 않았으므로).
- **모드 3단계** `off/quarantine/kill`: 탐지 검증 단계(off) → 포렌식
  보존이 필요한 분석 환경(quarantine: 커널이 후속 파일 변조만 차단,
  프로세스는 생존) → 운영(kill).

---

## 11. 임계값·상수 일람 (정의 위치 포함)

| 상수 | 값 | 위치 |
|---|---|---|
| 등급 임계 LOW/MED/HIGH/CRIT | 30/60/100/150 | `scoring.py` |
| 신호 윈도우 | 120 s | `scoring.py` |
| 엔트로피 임계 / 부스트 | 7.5 / 6.8 | `detectors/mass_io.py` |
| 엔트로피 샘플 | 4096 B | `detectors/mass_io.py` |
| 사용자모드 burst | 15개 / 10 s | `detectors/mass_io.py` |
| 카나리 부스트 | 30 s, ×1.5 | `detectors/mass_io.py` |
| 카나리 폴링 | 1.5 s | `detectors/canary.py` |
| 협박문 내용 확정 | 강≥1 AND 합≥3 | `detectors/ransom_note.py` |
| 협박문 확산 | 3 디렉터리 / 60 s | `detectors/ransom_note.py` |
| 협박문 크기 상한 | 64 KB | `detectors/ransom_note.py` |
| 커널 write burst | 75 MB / 4 s | `detectors/minifilter_bridge.py` |
| 커널 rename burst | 20회 / 5 s | `detectors/minifilter_bridge.py` |
| psutil write burst | 50 MB / 2 s | `detectors/process_watcher.py` |
| fan-out | 12 자식 / 5 s | `detectors/process_watcher.py` |
| corroboration | CRITICAL 단독 / HIGH+증거 | `responder.py` |

---

## 12. 이 수치들은 어떻게 검증되는가

1. **단위 테스트(430 케이스):** 임계값·게이트·승격 규칙이 회귀로
   고정된다 — 예: "카나리 80 단독은 HIGH 미달", "이름만 노트는 MEDIUM",
   "uncorroborated HIGH 는 observed only", "신뢰 actor 의 burst 는 다른
   PID 의 휴리스틱을 보강하지 못함".
2. **시뮬레이터(`tests/simulator.py`, `demo_inproc.py`):** populate→
   encrypt/stealth/canary/vss/bcd 시나리오로 임계값 통과·미달 경계를
   재현.
3. **격리 VM 실검체(`scripts/lab.ps1` + `postmortem.py`):** 탐지 지연·
   피해 파일 수·차단 여부를 디스크 증거(detector.db, reports/)로 집계.
   NOISY_PATHS·_BENIGN_VALUES 등은 이 실측 사후분석에서 역도출된
   목록이다.
