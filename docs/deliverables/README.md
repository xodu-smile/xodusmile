# 산출물 인덱스 — RansomGuard EDR

> 본 디렉터리에는 RansomGuard EDR 프로젝트의 6 가지 문서 산출물이
> 마크다운과 PNG 다이어그램으로 함께 정리되어 있다.
> 작성일: 2026-05-21 (1~4), 2026-06-05 (5~6 추가)

## 산출물 목록

| # | 산출물 | 마크다운 | 다이어그램 (PNG) |
|---|--------|----------|------------------|
| 1 | **기능명세서** (대/중/소) | [`01_기능명세서.md`](01_기능명세서.md) | [`images/01_features.png`](images/01_features.png) |
| 2 | **AS-IS 분석서** | [`02_AS-IS.md`](02_AS-IS.md) | [`images/02_asis.png`](images/02_asis.png) |
| 3 | **WBS (작업 분해 구조)** | [`03_WBS.md`](03_WBS.md) | [`images/03_wbs.png`](images/03_wbs.png) |
| 4 | **프로세스 정리도** (Swim-lane) | [`04_프로세스정리도.md`](04_프로세스정리도.md) | [`images/04_process.png`](images/04_process.png) |
| 5 | **정보 구조 (IA)** | [`05_IA.md`](05_IA.md) | [`images/05_ia.png`](images/05_ia.png) |
| 6 | **프로젝트 아키텍처** | [`06_아키텍처.md`](06_아키텍처.md) | [`images/06_architecture.png`](images/06_architecture.png) |
| 7 | **Core 모듈 아키텍처** (발표용) | [`06_아키텍처.md`](06_아키텍처.md) (07 절 참조) | [`images/07_core_architecture.png`](images/07_core_architecture.png) |

## 다이어그램 재생성

```bash
cd docs/deliverables
python3 _gen.py    # matplotlib + Noto Sans CJK 사용
```

`_gen.py` 안의 함수 7개 (`gen_features`, `gen_asis`, `gen_wbs`,
`gen_process`, `gen_ia`, `gen_architecture`, `gen_core_architecture`) 가
각각의 PNG 를 `images/` 에 출력한다. `01_features`·`06_architecture`·
`07_core_architecture` 는 **Core 1~4 / Support** 그룹핑을 공통 색상으로 시각화한다.

## 분류 체계

- **대분류 6** : F1 커널 I/O / F2 사용자모드 탐지 / F3 스코어링·저장 / F4 능동 대응 / F5 모니터링 / F6 설치·운영
- **중분류 18** · **소분류 54** — 자세한 내용은 [`01_기능명세서.md`](01_기능명세서.md) 참조
