# Spec — RansomGuard 대시보드: 시스템 보안 전문가(SOC 분석가) 지원 강화 (run 2026-06-11)

## 1. Persona & 문제 정의

현재 대시보드(`dashboard/templates/index.html`)는 **비전공자**를 위해 설계됨
(신호등 이모지, 용어 한글 순화, 세부정보 숨김). 그러나 실제 운영자는
**시스템 보안 전문가(SOC 분석가/인시던트 대응자)** 이며, 이들에게 필요한 것:

1. **트리아지 속도**: 점수 추이, 어떤 프로세스가 점수를 올리는지, 어떤 신호가
   언제 발생했는지 — 한 화면에서 필터링·검색 가능해야 함.
2. **표준 분류 체계(taxonomy)**: 원본 detector ID, 영문 severity(CRITICAL 등),
   MITRE ATT&CK technique 빈도 요약 — 순화된 한글 별명만으로는 보고서·인텔과
   대조 불가.
3. **대응 감사 추적(audit trail)**: 무엇이 언제 kill/quarantine/release
   되었고, 트리거 신호·exe SHA-256·부모 프로세스는 무엇이었는지.
   → 백엔드 `/api/actions` 가 이 데이터를 모두 제공하지만 **UI 미사용**.
4. **인증 운영 가능성**: `agent.auth_token` 설정 시 admin API 는 `X-API-Key`
   요구 — 현재 UI는 토큰을 보낼 수단이 없어 **admin 패널이 깨짐** (기능 버그).
5. **저조도 환경(SOC) 가독성**: 다크 테마가 사실상 표준.

## 2. 범위 (Functional Requirements)

### FR1 — 운영자 토큰 (auth) [버그 수정 겸 신기능]
- 헤더에 🔑 토큰 버튼: 입력값을 `sessionStorage` 에 저장, 모든 fetch 에
  `X-API-Key` 헤더로 첨부 (빈 값이면 미첨부).
- 401 수신 시 헤더 버튼에 "인증 필요" 경고 상태 표시.

### FR2 — 위험도 추이 타임라인
- `/api/status` 폴링(1.5s) 값을 클라이언트 링버퍼(최근 ~10분)에 누적,
  `<canvas>` 스파크라인으로 렌더 (외부 라이브러리 금지 — 오프라인 동작 유지).
- 임계값(60/100/150) 가이드라인 표시. 페이지 새로고침 시 초기화됨을 힌트로 명시.

### FR3 — 이벤트 피드 전문가화
- 필터: severity 다중 토글(영문 칩: CRITICAL/HIGH/MEDIUM/LOW/INFO),
  detector 드롭다운, 자유 텍스트 검색(메시지+메타데이터).
- 일시정지(⏸) 토글: 분석 중 리스트가 새 이벤트로 밀리지 않게.
- 각 이벤트에 원본 detector ID + 신호 name(mono) 병기, 영문 severity 표기.
- 시각: HH:MM:SS 유지 + title 속성에 전체 일시.

### FR4 — 대응 조치 로그 (Response Actions) 패널 [신규, /api/actions]
- 시간 역순 목록: action(kill/quarantine/release), 프로세스명/PID, 사유,
  exe 경로·SHA-256(복사 버튼), 부모(PPID/이름), 차단 시점 점수/레벨, 성공 여부.
- SHA-256 은 VirusTotal 조회 링크 제공.

### FR5 — MITRE ATT&CK 요약 패널
- 현재 윈도우 이벤트의 technique 빈도 집계(클라이언트), technique 칩
  (ID+이름+빈도) 표시, attack.mitre.org 링크.

### FR6 — 프로세스 테이블 강화
- 컬럼 헤더 클릭 정렬(PID/이름/CPU/메모리), 토글 시 오름/내림 전환.
- 위협 분석(threat_breakdown)에 잡힌 PID 행 하이라이트 + 점수 배지
  (admin 패널 열림+인증 시 데이터 확보).

### FR7 — 다크(SOC) 테마
- 다크/라이트 토글(🌙/☀), `localStorage` 저장. 기존 라이트 팔레트 유지(토글).
- CSS 변수만 교체하는 방식 — 컴포넌트 구조 변경 없음.

### FR8 — 연결 상태 표시
- 폴링 실패 시 헤더 status-pill 을 "연결 끊김" 상태로 전환(조용한 무시 대신),
  복구 시 원복.

## 3. 비범위 (Out of scope)
- 백엔드 신규 엔드포인트(기존 API 만 사용; `dashboard/app.py` 변경 없음 목표).
- 서버측 점수 히스토리 영속화, WebSocket 전환, 다국어(영문) UI.
- 기존 비전공자용 한글 안내 문구 제거 — 전문가 정보를 *추가*하되 병기 유지.

## 4. 제약
- 단일 파일 `index.html` 유지(현 구조), 외부 CDN/라이브러리 금지(오프라인).
- 모든 동적 문자열은 기존 `escape()`/`mdEsc()` 경로로 이스케이프 (XSS 방지).
- 폴링 주기 기존 유지(상태 1.5s/프로세스 2s/기록 2.5s/admin 3s).

## 5. 수용 기준
- pytest 전체 통과, Flask test client 로 `GET /` 200 + 주요 신규 DOM id 존재.
- 토큰 설정 시 admin fetch 에 `X-API-Key` 부착 (코드 경로 검증).
- 새 패널들이 데이터 없음/오류 상태에서 빈 상태 문구를 보여줌.
