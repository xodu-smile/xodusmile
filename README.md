# Ransomware Detection Agent (Windows 11 Prototype)

학습용 사용자 모드 랜섬웨어 탐지 프로토타입. **EDR 대체 아님.**

## 구성

| 모듈 | 역할 |
|---|---|
| `detectors/canary.py` | Canary 파일 무결성 (SHA256) |
| `detectors/mass_io.py` | 대량 I/O + 엔트로피 + 매직바이트 |
| `detectors/process_cmdline.py` | WMI 기반 VSS/BCD cmdline 룰 |
| `detectors/process_watcher.py` | psutil 폴링, LOLBin chain, I/O burst |
| `scoring.py` | 가중치 합산 (120s 윈도우) |
| `event_store.py` | SQLite 영속화 |
| `dashboard/app.py` | Flask UI + `/api/processes` |

설계: 시그널 → ScoringEngine → Severity. Canary=80, VSS/BCD=60~70, 엔트로피=8~12 (단일 시그널 회피).

## 요구사항

- Windows 11 (22H2+), Python 3.10+ x64
- 관리자 PowerShell (WMI `Win32_Process` 접근용)
- `winmgmt` 서비스 동작

## 설치

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\.venv\Scripts\pywin32_postinstall.py -install
```

## 실행

```powershell
# Agent + Dashboard (http://127.0.0.1:5000)
python agent.py --watch C:\path\to\watch_dir

# 콘솔 데모
python demo_inproc.py

# 시뮬레이터 (실제 암호화/명령 실행 없음, 가짜 이벤트만)
python tests\simulator.py --scenario {canary|encrypt|full}
```

격리된 VM/테스트 환경에서만 사용할 것.

## 미구현 (후속 과제)

Minifilter 드라이버, ETW 직접 구독, Authenticode 화이트리스트, intermittent encryption 대응, 메모리 시그니처 스캔, PPL cmdline 접근.
