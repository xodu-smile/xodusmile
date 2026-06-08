# RansomGuard EDR — 관리자 가이드 (Administrator Guide)

> English version below (한국어 버전은 위쪽 참고)

---

## 한국어 (Korean)

### 소개

이 가이드는 RansomGuard EDR 을 **운영 및 관리**하는 시스템 관리자를 위한 실무 문서입니다.
대시보드 읽는 법, 응답 모드 선택, 허용 목록 관리, 오탐 처리 절차를 다룹니다.

---

## 1. 대시보드 관리자 패널 읽기

### 시스템 상태 (System Health)

관리자 패널의 첫 섹션에서 다음을 확인합니다:

- **Responder Mode** — 현재 모드 (off / quarantine / kill). 
- **Minifilter connected** — 커널 드라이버 연결 상태. ✓ 면 정상, ✗ 면 드라이버 로드 실패 (사용자 모드만 동작).
- **Uptime** — 에이전트 시작 이후 경과 시간.
- **Watch directories** — 감시 중인 폴더 목록.
- **Allowlist entries** — 허용 목록 항목 수.

### PID 별 위협 분석 (Per-PID Threat Breakdown)

테이블에 현재 활성 프로세스들이 나열되며, 각 행은:

| 열 | 의미 |
|----|------|
| **PID** | 프로세스 ID. |
| **Process name** | 실행파일명 (예: `ransomware.exe`). |
| **Attack technique** | MITRE ATT&CK 기법 (예: `T1486 Data Encrypted for Impact`). 여러 개면 첫 번째 + 개수로 표시 (예: `T1490 (+2)`). |
| **Score contribution** | 이 프로세스가 총점에 얼마나 기여했는지 (예: `45/150` 점). |
| **Recent signals** | 최근 30초 내 발화한 신호 이름들 (예: `high_entropy_write, modify_burst`). |

**해석 팁**:
- "T1486" 가 보이면 → 데이터 암호화 의심.
- "T1490" 가 보이면 → VSS/BCD 복구 수단 파괴 의심.
- "T1562" 가 보이면 → 방어 무력화(Defender 비활성화 등).
- Score contribution 이 `100+` 면 → 즉각 조사 필요.

---

## 2. Responder 모드 선택

### 언제 어떤 모드?

| 모드 | 동작 | 추천 상황 |
|------|------|---------|
| **off** | 신호를 감지만 하고 행동 안 함. | 초기 설정 / 임계값 튜닝. |
| **quarantine** | HIGH/CRITICAL 신호 시 프로세스를 kernel에서 격리(쓰기/이름변경 차단)하지만 **종료하지 않음**. | 운영 환경 (오탐 리스크 낮출 때). |
| **kill** | HIGH/CRITICAL 신호 시 프로세스 즉시 종료. | 자동화 랩 / 고신뢰 시스템. |

### 모드 전환 (실시간)

관리자 패널에서 **"Change Mode"** 드롭다운을 클릭해 선택 후 **"Apply"** 누르면,
다시 시작하지 않고도 즉시 모드가 바뀝니다. 예:

```
Current: off
↓ 클릭 ↓
Select: kill
[Apply]
→ 모드 변경됨 (재시작 불필요)
```

---

## 3. 허용 목록 관리 (Allowlist Management)

### 3.1 UI 로 항목 추가/제거

대시보드 "관리자 패널" → "Allowlist" 섹션에서:

1. **항목 추가**: 
   - 입력: `Value` (프로세스명 또는 경로), `Kind` (name 또는 path), `Note` (선택, 예: "사내 백업 에이전트")
   - 예: Value=`veeamagent.exe`, Kind=`name`, Note=`Veeam backup agent`
   - **[Add]** 클릭 → `allowlist.json` 자동 저장.

2. **항목 삭제**:
   - 기존 항목 옆의 **[Delete]** 클릭 → 즉시 삭제 및 저장.

### 3.2 JSON 파일 수동 편집

저장소 루트의 `allowlist.json` 을 직접 편집할 수도 있습니다:

```json
{
  "entries": [
    {
      "kind": "name",
      "value": "veeamagent.exe",
      "note": "Veeam backup 에이전트",
      "added_at": 1718000000.0
    },
    {
      "kind": "path",
      "value": "C:\\Program Files\\Acronis\\",
      "note": "Acronis True Image",
      "added_at": 1718000010.0
    }
  ]
}
```

**주의**:
- `kind` 는 `"name"` (소문자 basename) 또는 `"path"` (경로 접두사) 만 가능.
- `value` 는 모두 소문자로 정규화됩니다 (Windows 경로는 자동 정규화).
- 파일 저장 후, 대시보드를 새로고침하거나 에이전트를 재시작하면 반영됩니다.

### 3.3 CLI 로 관리 (REST API)

에이전트가 실행 중이고 대시보드가 열려 있다면:

```powershell
# 항목 추가 (name 기반)
curl -X POST http://127.0.0.1:5000/api/admin/allowlist `
  -H "Content-Type: application/json" `
  -d '{"value":"7z.exe","kind":"name","note":"7-Zip compression"}'

# 항목 조회
curl http://127.0.0.1:5000/api/admin/allowlist

# 항목 삭제
curl -X DELETE http://127.0.0.1:5000/api/admin/allowlist `
  -H "Content-Type: application/json" `
  -d '{"value":"7z.exe","kind":"name"}'
```

---

## 4. 허용 목록 설계 - 이름 vs 경로

### Name 기반 (프로세스 이름)

**형식**: 프로세스 실행파일명 (basename, 소문자)  
**예**: `veeamagent.exe`, `7z.exe`, `rclone.exe`

**장점**:
- 간단, 직관적.
- 설정 간단.

**단점**:
- **위장 공격 가능** — 악성코드가 같은 이름으로 위장하면 탐지 우회.
  예: `%TEMP%\veeamagent.exe` (가짜) 도 통과.

### Path 기반 (이미지 경로 접두사)

**형식**: 이미지 경로의 접두사 (소문자, 경로 정규화)  
**예**: `C:\Program Files\Veeam\`, `C:\Program Files\7-Zip\`

**장점**:
- **위장 방어** — 경로 접두사가 정확히 맞아야만 허용.
  `C:\Program Files\Veeam\` 은 `%TEMP%\veeamagent.exe` 를 통과 X.
- 더 안전.

**단점**:
- 경로를 정확히 알아야 함.

### 추천 전략

- **정상 소프트웨어** → **경로 기반** 사용 (더 안전).
  - `C:\Program Files\Veeam\` (Veeam)
  - `C:\Program Files (x86)\Acronis\` (Acronis)
  - `C:\Program Files\7-Zip\` (7-Zip)
- **필요시에만** name 기반 사용 (경로를 못 알 때).
- **High-confidence 신호는 항상 탐지** — 허용 목록이 canary 트립이나 협박문 확산을 면제하지 않습니다.

---

## 5. ATT&CK 기법 태깅 이해

대시보드와 보고서의 각 신호/프로세스 옆에 **MITRE ATT&CK 기법 ID** 가 표시됩니다.

### 자주 보는 기법들

| 기법 | ID | 의미 | 대응 |
|------|-----|------|------|
| Data Encrypted for Impact | T1486 | 파일 암호화 | 즉각 response (HIGH+). |
| Inhibit System Recovery | T1490 | VSS/BCD 파괴 | 거의 확실한 랜섬웨어. |
| Impair Defenses | T1562.001 | Defender 비활성화 | 방어 무력화 시도. |
| Indicator Removal | T1070.001 | 로그 삭제 (wevtutil) | 은폐 시도. |
| Scheduled Task/Job | T1053.005 | schtasks 지속화 | 재감염 대비. |
| Service Stop | T1489 | 서비스 종료 | 추가 피해 방지. |

**팁**: 
- `T1486` + `T1490` 함께 보이면 → **고급 랜섬웨어** 거의 확실.
- `T1562` 만 보이고 암호화 없으면 → **오탐 가능성** 검토.

---

## 6. 오탐 처리 워크플로우 (False-positive Triage)

### 시나리오 1: 정상 백업/압축 앱이 자꾸 탐지됨

**증상**: `veeamagent.exe` 또는 `7z.exe` 가 계속 HIGH/CRITICAL 신호 발생.

**해결**:

1. **프로세스 확인**: 대시보드 "프로세스" 탭에서 pid / 경로 확인.
2. **경로 기반 허용 목록 추가**:
   ```json
   {
     "kind": "path",
     "value": "C:\\Program Files\\Veeam\\",
     "note": "Veeam backup service"
   }
   ```
   또는 UI: `Value=C:\Program Files\Veeam\`, `Kind=path` → **[Add]**.
3. **재테스트**: 같은 작업을 다시 실행 → 신호 안 나오면 성공.

### 시나리오 2: 정상 파일 암호화 도구가 탐지됨

**증상**: VeraCrypt 또는 7-Zip 이 높은 엔트로피 쓰기로 HIGH 신호 발생.

**해결**:

1. **신호 확인**: 대시보드에서 signal name 확인 (`high_entropy_write` 등).
2. **합법 여부 재검토**:
   - ✓ 정상 도구 → 허용 목록 추가.
   - ✗ 의심 프로세스 → quarantine 모드 유지.
3. **경로 기반 허용**:
   ```json
   {
     "kind": "path",
     "value": "C:\\Program Files\\7-Zip\\",
     "note": "7-Zip compression tool"
   }
   ```

### 시나리오 3: 신호 발화했지만 진짜 공격인지 확실 없음

**증상**: `modify_burst` 신호는 발화했으나 프로세스 이름이 낯선 경우.

**권장 대응**:

1. **모드를 `quarantine` 으로 전환** (kill 아니면 격리).
2. **몇 분간 모니터링** — 추가 신호가 오는가?
   - ✓ canary 트립 또는 협박문 확산 → **확실한 공격**, kill 실행.
   - ✗ 신호 없음 → **거짓양성**, 허용 목록 추가.
3. **필요시 과거 보고서 검토**: `/api/reports` 에서 사건 분석.

### 시나리오 4: 많은 시스템에서 같은 오탐 발생

**예**: 표준 배포 에이전트 (`mycompany_agent.exe`) 가 모든 PC에서 탐지.

**해결**:

1. **프로세스 경로 확인**: C:\Program Files\MyCompany\Agent\ 같은 표준 경로.
2. **조직 내 허용 목록 배포**:
   - `allowlist.json` 을 모든 PC에 배포.
   - 또는 중앙 정책으로 CI/CD 자동화.
3. **예시**:
   ```json
   {
     "kind": "path",
     "value": "C:\\Program Files\\MyCompany\\Agent\\",
     "note": "Company standard deployment agent v1.2"
   }
   ```

---

## 7. 시스템 상태 모니터링

### 주요 모니터링 지표

| 지표 | 목표 | 대응 |
|------|------|------|
| Minifilter connected | ✓ (항상) | ✗면 드라이버 로드 실패 — 재부팅 또는 재로드. |
| Score (실시간) | 0-29 (INFO) | 60+ 지속 → 임계값 튜닝 필요. |
| Allowlist entries | 적정 (5-50 권장) | 너무 많으면 (100+) 보안 정책 재검토. |
| Responder mode | quarantine (운영) / kill (랩) | off 로 두면 행동 안 함 (위험). |

### 대시보드 상태 확인 API

```powershell
# 시스템 건강도
curl http://127.0.0.1:5000/api/admin/health | ConvertFrom-Json | Format-Table

# 출력 예:
# responder_mode : quarantine
# minifilter_connected : True
# uptime_seconds : 3600
# watch_dirs : @("C:\Users\you\Documents", "C:\Users\you\Desktop")
# allowlist_count : 5
```

---

## 8. 드라이버 / 서비스 관리

### 드라이버 상태 확인

```powershell
# 드라이버 로드 확인
fltmc filters | Select-String RansomGuard

# 출력 예:
# Filter Name           : RansomGuard
# Instances             : 3
# Frame                 : 0

# 로드 실패 시
fltmc load RansomGuard   # 재로드

# 또는 재부팅 후 재시도
```

### 서비스 상태 (서비스로 실행 시)

```powershell
# 상태 확인
Get-Service -Name RansomGuardAgent, RansomGuardWatchdog

# 재시작
Restart-Service RansomGuardAgent

# 완전 제거
.\scripts\uninstall_services.ps1
```

---

## 9. 보안 모범 사례

### Do ✓

- **경로 기반 허용 목록** 사용 (이름 대신).
- **Quarantine 모드**로 운영 중 오탐 확인 후 kill 모드 전환.
- **주기적 allowlist 검토** — 쓸모없는 항목 제거.
- **감시 폴더를 넓게** 설정 (C:\Users\ 등) — 더 많이 보호.
- **High-confidence 신호 (canary, 협박문확산)** 는 절대 허용하지 않음.

### Don't ✗

- **관리자 계정으로 험한 테스트** 실행 (격리 VM 에서만).
- **Name 기반 허용 목록만** 남용 (위장 가능).
- **Allowlist 에 wildcard 같은 것** 추가 (지원 안 함, 정확한 값만).
- **off 모드로 오래** 두기 (침해 위험).
- **공개 / 신뢰 안 하는 곳에서** allowlist.json 다운로드.

---

## 10. 대시보드 인증 설정

토큰을 설정하면 `/api/reset`, `/api/kill`, `/api/release`, 모든
`/api/admin/*` 엔드포인트가 인증을 요구합니다. Watchdog 용
`/api/heartbeat` 는 항상 공개입니다.

### 토큰 설정 방법 (추천 순서)

**① 환경변수 (가장 안전 — 디스크에 토큰 미저장)**

```powershell
$env:RANSOMGUARD_AUTH_TOKEN = "your-secret-token"
python agent.py --watch C:\Users
```

**② 설정 파일 (`ransomguard.toml`)**

```toml
[dashboard]
auth_token = "your-secret-token"
```

그 다음 에이전트 실행:

```powershell
python agent.py --config ransomguard.toml --watch C:\Users
```

**③ CLI 플래그 (프로세스 목록에 토큰 노출 — 비추천)**

```powershell
python agent.py --auth-token your-secret-token --watch C:\Users
```

> 우선순위: CLI 플래그 > 환경변수 > 설정 파일.

### API 호출 시 인증 헤더

```powershell
# X-API-Key 헤더
curl -X POST http://127.0.0.1:5000/api/reset `
  -H "X-API-Key: your-secret-token"

# 또는 Bearer 토큰
curl -X POST http://127.0.0.1:5000/api/kill `
  -H "Authorization: Bearer your-secret-token" `
  -H "Content-Type: application/json" `
  -d '{"pid": 1234}'

# 모드 변경
curl -X POST http://127.0.0.1:5000/api/admin/mode `
  -H "X-API-Key: your-secret-token" `
  -H "Content-Type: application/json" `
  -d '{"mode": "quarantine"}'

# Heartbeat — 항상 공개 (토큰 불필요)
curl http://127.0.0.1:5000/api/heartbeat
```

### 읽기 API 도 보호하기

기본적으로 `/api/status`, `/api/events` 같은 읽기 전용 엔드포인트는
인증 없이 접근 가능합니다. 인트라넷 외부에 노출되는 경우 설정 파일에
다음을 추가하세요:

```toml
[dashboard]
auth_required_for_reads = true
```

---

## 11. 중앙 설정 파일 사용

`ransomguard.toml` (또는 `.json`) 한 파일로 수백 대 엔드포인트의 정책을
일괄 배포할 수 있습니다 (GPO/Intune/Ansible).

### 설정 파일 예시

```toml
[general]
watch_dirs = ["C:\\Users"]
responder_mode = "kill"          # off | quarantine | kill
enable_minifilter = true

[dashboard]
host = "127.0.0.1"
port = 5000
auth_token = ""                  # 비우면 인증 비활성 — 운영에선 env 로 주입 권장
auth_required_for_reads = false

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

> `.toml` 은 Python 3.11+(`tomllib`)에서 동작합니다. 3.10 이하면
> 같은 구조의 `ransomguard.json` 을 사용하세요.

### 환경변수로 비밀 주입

설정 파일에 토큰/URL 을 평문으로 적는 대신 환경변수를 사용하세요.
환경변수는 항상 설정 파일 값을 덮어씁니다:

| 환경변수 | 효과 |
|----------|------|
| `RANSOMGUARD_AUTH_TOKEN` | 대시보드 API 토큰 설정 |
| `RANSOMGUARD_WEBHOOK_URL` | Webhook 활성화 + URL 설정 |
| `RANSOMGUARD_SYSLOG_HOST` | syslog 활성화 + 호스트 설정 |

```powershell
# 서비스 시작 전 환경변수 설정 예 (PowerShell)
$env:RANSOMGUARD_AUTH_TOKEN    = "prod-secret-token"
$env:RANSOMGUARD_WEBHOOK_URL   = "https://hooks.slack.com/services/XXX"
$env:RANSOMGUARD_SYSLOG_HOST   = "siem.corp.local"
python agent.py --config ransomguard.toml
```

### 설정 파일 경로 지정

```powershell
# 자동 탐지 (작업 폴더에서 ransomguard.toml / .json 검색)
python agent.py

# 경로 명시
python agent.py --config C:\ProgramData\RansomGuard\policy.toml
```

---

## 12. SIEM 및 Webhook 통합 설정

### SIEM (CEF over syslog)

Splunk, QRadar, ArcSight, Microsoft Sentinel 등 모든 CEF 파서와 호환.
HIGH 이상 이벤트를 비동기로 전송합니다 (fail-open — 통합 장애가 탐지를 멈추지 않음).

`ransomguard.toml` 의 `[syslog]` 섹션을 채우거나 환경변수를 설정하세요:

```toml
[syslog]
enabled = true
host = "siem.corp.local"   # 또는 IP
port = 514
protocol = "udp"           # udp | tcp
min_severity = "HIGH"      # INFO | LOW | MEDIUM | HIGH | CRITICAL
```

또는 환경변수로만:

```powershell
$env:RANSOMGUARD_SYSLOG_HOST = "siem.corp.local"
# enabled 와 기타 기본값은 자동 적용
```

### Webhook (Slack / Teams / PagerDuty / SOAR)

```toml
[webhook]
enabled = true
url = "https://hooks.example.com/services/XXX"
min_severity = "CRITICAL"
```

또는 환경변수로만:

```powershell
$env:RANSOMGUARD_WEBHOOK_URL = "https://hooks.slack.com/services/XXX"
```

> Webhook payload 는 범용 JSON 이므로 Slack incoming webhook, Teams
> connector, PagerDuty Events API v2, 임의 SOAR HTTP 트리거 모두 수신 가능.

### Heartbeat 는 항상 공개

watchdog 서비스가 `http://127.0.0.1:5000/api/heartbeat` 를 5초마다
호출합니다. 토큰이 설정돼 있어도 이 엔드포인트는 인증 없이 200 OK
를 반환합니다 — watchdog 의 재기동 루프가 끊기지 않도록.

---

---

## English

### Introduction

This guide is a practical handbook for **operating and administering** RansomGuard EDR
for system administrators. It covers reading the dashboard, choosing responder modes,
managing allowlists, and triaging false positives.

---

## 1. Reading the Admin Panel

### System Health

First section of the admin panel displays:

- **Responder Mode** — current mode (off / quarantine / kill).
- **Minifilter connected** — kernel driver connection. ✓ = OK, ✗ = driver load failed (user-mode only).
- **Uptime** — seconds since agent started.
- **Watch directories** — list of monitored folders.
- **Allowlist entries** — count of allowlist items.

### Per-PID Threat Breakdown

Table lists active processes; each row shows:

| Column | Meaning |
|--------|---------|
| **PID** | Process ID. |
| **Process name** | Executable name (e.g., `ransomware.exe`). |
| **Attack technique** | MITRE ATT&CK ID (e.g., `T1486 Data Encrypted for Impact`). Multiple → first + count (e.g., `T1490 (+2)`). |
| **Score contribution** | How much this process added to total (e.g., `45/150` points). |
| **Recent signals** | Signal names from last 30 s (e.g., `high_entropy_write, modify_burst`). |

**Reading tips:**
- See "T1486" → data encryption suspected.
- See "T1490" → VSS/BCD destruction suspected.
- See "T1562" → defense evasion (Defender disable, etc.).
- Score > 100 → investigate immediately.

---

## 2. Choosing Responder Mode

### When to use which mode

| Mode | Behavior | Recommended for |
|------|----------|-----------------|
| **off** | Detect only, no action. | Initial setup / tuning thresholds. |
| **quarantine** | Kernel-isolate process (block writes/renames) on HIGH/CRITICAL, but do NOT terminate. | Production (lower false-positive risk). |
| **kill** | Immediately terminate process on HIGH/CRITICAL. | Automated lab / high-trust systems. |

### Switching modes (real-time)

In admin panel, click **"Change Mode"** dropdown, select, and **"Apply"** — no restart needed:

```
Current: off
↓ click ↓
Select: kill
[Apply]
→ mode changed (no restart)
```

---

## 3. Allowlist Management

### 3.1 Add/remove via UI

Dashboard "Admin Panel" → "Allowlist" section:

1. **Add entry:**
   - Input: `Value` (process name or path), `Kind` (name or path), `Note` (optional, e.g., "in-house backup agent")
   - Example: Value=`veeamagent.exe`, Kind=`name`, Note=`Veeam backup`
   - Click **[Add]** → auto-saved to `allowlist.json`.

2. **Remove entry:**
   - Click **[Delete]** next to an item → immediately deleted and saved.

### 3.2 Manual JSON edit

Edit `allowlist.json` in repo root directly:

```json
{
  "entries": [
    {
      "kind": "name",
      "value": "veeamagent.exe",
      "note": "Veeam backup service",
      "added_at": 1718000000.0
    },
    {
      "kind": "path",
      "value": "C:\\Program Files\\Acronis\\",
      "note": "Acronis True Image",
      "added_at": 1718000010.0
    }
  ]
}
```

**Notes:**
- `kind` must be `"name"` (lowercase basename) or `"path"` (path prefix).
- `value` auto-normalizes to lowercase (Windows paths auto-normalize).
- After saving, refresh dashboard or restart agent to pick up changes.

### 3.3 CLI / REST API

If agent is running and dashboard open:

```powershell
# Add entry (name-based)
curl -X POST http://127.0.0.1:5000/api/admin/allowlist `
  -H "Content-Type: application/json" `
  -d '{"value":"7z.exe","kind":"name","note":"7-Zip compression"}'

# List entries
curl http://127.0.0.1:5000/api/admin/allowlist

# Delete entry
curl -X DELETE http://127.0.0.1:5000/api/admin/allowlist `
  -H "Content-Type: application/json" `
  -d '{"value":"7z.exe","kind":"name"}'
```

---

## 4. Allowlist Design — Name vs. Path

### Name-based (process name)

**Format:** executable basename (lowercase)  
**Examples:** `veeamagent.exe`, `7z.exe`, `rclone.exe`

**Pros:**
- Simple, intuitive.
- Easy to configure.

**Cons:**
- **Spoofing risk** — malware using the same name bypasses detection.
  Example: `%TEMP%\veeamagent.exe` (fake) also passes.

### Path-based (image path prefix)

**Format:** image path prefix (lowercase, normalized)  
**Examples:** `C:\Program Files\Veeam\`, `C:\Program Files\7-Zip\`

**Pros:**
- **Defeats spoofing** — path prefix must match exactly.
  `C:\Program Files\Veeam\` blocks `%TEMP%\veeamagent.exe`.
- More secure.

**Cons:**
- Must know the exact path.

### Recommended strategy

- **Legitimate software** → use **path-based** (safer).
  - `C:\Program Files\Veeam\` (Veeam)
  - `C:\Program Files (x86)\Acronis\` (Acronis)
  - `C:\Program Files\7-Zip\` (7-Zip)
- **Use name-based only if** path is unknown.
- **High-confidence signals always detected** — allowlist never exempts canary trips or ransom-note spreads.

---

## 5. Understanding ATT&CK Technique Tags

Dashboard and reports show **MITRE ATT&CK technique IDs** next to each signal/process.

### Common techniques

| Technique | ID | Meaning | Response |
|-----------|-----|---------|----------|
| Data Encrypted for Impact | T1486 | File encryption | Immediate response (HIGH+). |
| Inhibit System Recovery | T1490 | VSS/BCD destruction | Almost certain ransomware. |
| Impair Defenses | T1562.001 | Defender disable | Defense evasion attempt. |
| Indicator Removal | T1070.001 | Log deletion (wevtutil) | Cover-up attempt. |
| Scheduled Task/Job | T1053.005 | schtasks persistence | Reinfection prep. |
| Service Stop | T1489 | Service termination | Minimize damage. |

**Tips:**
- See T1486 + T1490 together → **advanced ransomware** almost certain.
- See T1562 alone without encryption → consider **false positive**, review allowlist.

---

## 6. False-positive Triage Workflow

### Scenario 1: Legitimate backup/compression app keeps firing

**Symptom:** `veeamagent.exe` or `7z.exe` repeatedly triggers HIGH/CRITICAL signals.

**Solution:**

1. **Verify process:** In dashboard "Processes" tab, confirm PID and path.
2. **Add path-based allowlist entry:**
   ```json
   {
     "kind": "path",
     "value": "C:\\Program Files\\Veeam\\",
     "note": "Veeam backup service"
   }
   ```
   Or UI: `Value=C:\Program Files\Veeam\`, `Kind=path` → **[Add]**.
3. **Retest:** Run the same operation → no signals = success.

### Scenario 2: Legitimate encryption tool triggers detection

**Symptom:** VeraCrypt or 7-Zip fires HIGH signal for high-entropy writes.

**Solution:**

1. **Check signal:** In dashboard, note signal name (`high_entropy_write`, etc.).
2. **Re-verify legitimacy:**
   - ✓ Known tool → add to allowlist.
   - ✗ Suspicious process → keep in quarantine mode.
3. **Add path-based entry:**
   ```json
   {
     "kind": "path",
     "value": "C:\\Program Files\\7-Zip\\",
     "note": "7-Zip compression tool"
   }
   ```

### Scenario 3: Signal fired but unsure if real attack

**Symptom:** `modify_burst` fired, but process name is unfamiliar.

**Recommended action:**

1. **Switch mode to `quarantine`** (not kill).
2. **Monitor for 5–10 minutes** — do more signals appear?
   - ✓ canary trip or ransom-note spread → **confirmed attack**, kill.
   - ✗ no additional signals → **false positive**, add to allowlist.
3. **Review past reports** if needed: `/api/reports`.

### Scenario 4: Same false positive on many machines

**Example:** Org's standard agent (`mycompany_agent.exe`) detected on all PCs.

**Solution:**

1. **Confirm path:** E.g., `C:\Program Files\MyCompany\Agent\` is standard everywhere.
2. **Deploy allowlist org-wide:**
   - Distribute `allowlist.json` to all PCs.
   - Or automate via central policy / CI/CD.
3. **Example entry:**
   ```json
   {
     "kind": "path",
     "value": "C:\\Program Files\\MyCompany\\Agent\\",
     "note": "Company standard deployment agent v1.2"
   }
   ```

---

## 7. System Health Monitoring

### Key metrics

| Metric | Target | Action if fails |
|--------|--------|-----------------|
| Minifilter connected | ✓ always | ✗ = driver load failed — reboot or reload. |
| Score (realtime) | 0-29 (INFO) | 60+ sustained → tune thresholds. |
| Allowlist entries | 5-50 typical | 100+ → review security policy. |
| Responder mode | quarantine (ops) / kill (lab) | off = no action (risky). |

### Check health via API

```powershell
# System health
curl http://127.0.0.1:5000/api/admin/health | ConvertFrom-Json | Format-Table

# Output example:
# responder_mode : quarantine
# minifilter_connected : True
# uptime_seconds : 3600
# watch_dirs : @("C:\Users\you\Documents", "C:\Users\you\Desktop")
# allowlist_count : 5
```

---

## 8. Driver / Service Management

### Check driver

```powershell
# Confirm driver loaded
fltmc filters | Select-String RansomGuard

# Output example:
# Filter Name           : RansomGuard
# Instances             : 3
# Frame                 : 0

# If not loaded, reload
fltmc load RansomGuard

# Or reboot and retry
```

### Service status (if running as service)

```powershell
# Check status
Get-Service -Name RansomGuardAgent, RansomGuardWatchdog

# Restart
Restart-Service RansomGuardAgent

# Full uninstall
.\scripts\uninstall_services.ps1
```

---

## 9. Security Best Practices

### Do ✓

- Use **path-based allowlist** (not name-only).
- Operate in **quarantine mode**, verify false positives, then switch to kill.
- **Periodically review allowlist** — remove stale entries.
- Set **watch folders broadly** (e.g., `C:\Users\`) for wider protection.
- **Never allow high-confidence signals** (canary, ransom-note-spread) via allowlist.

### Don't ✗

- Run **aggressive tests with admin accounts** (isolated VM only).
- Abuse **name-only allowlist** (spoofable).
- Add **wildcards to allowlist** (unsupported; exact values only).
- Leave agent in **off mode for long** (breach risk).
- Download **allowlist.json from untrusted sources.**

---

## 10. Enabling Dashboard Authentication

When a token is set, mutating endpoints (`/api/reset`, `/api/kill`,
`/api/release`) and **all** `/api/admin/*` endpoints require
authentication. The watchdog liveness probe `/api/heartbeat` is
**always open** regardless of token configuration.

### Setting the token (recommended order)

**① Environment variable (safest — token never written to disk)**

```powershell
$env:RANSOMGUARD_AUTH_TOKEN = "your-secret-token"
python agent.py --watch C:\Users
```

**② Config file (`ransomguard.toml`)**

```toml
[dashboard]
auth_token = "your-secret-token"
```

Then start the agent:

```powershell
python agent.py --config ransomguard.toml --watch C:\Users
```

**③ CLI flag (exposes token in process listing — not recommended)**

```powershell
python agent.py --auth-token your-secret-token --watch C:\Users
```

> Precedence: CLI flag > environment variable > config file.

### Passing the token in API calls

```powershell
# X-API-Key header
curl -X POST http://127.0.0.1:5000/api/reset `
  -H "X-API-Key: your-secret-token"

# Or Bearer token
curl -X POST http://127.0.0.1:5000/api/kill `
  -H "Authorization: Bearer your-secret-token" `
  -H "Content-Type: application/json" `
  -d '{"pid": 1234}'

# Change responder mode
curl -X POST http://127.0.0.1:5000/api/admin/mode `
  -H "X-API-Key: your-secret-token" `
  -H "Content-Type: application/json" `
  -d '{"mode": "quarantine"}'

# Heartbeat — always open, no token needed
curl http://127.0.0.1:5000/api/heartbeat
```

### Protecting read endpoints too

By default, read-only endpoints (`/api/status`, `/api/events`, etc.) are
open without authentication. If the dashboard is exposed outside a trusted
network, add this to the config:

```toml
[dashboard]
auth_required_for_reads = true
```

---

## 11. Central Config File

A single `ransomguard.toml` (or `.json`) file can deploy policy to an
entire fleet via GPO / Intune / Ansible.

### Example config

```toml
[general]
watch_dirs = ["C:\\Users"]
responder_mode = "kill"          # off | quarantine | kill
enable_minifilter = true

[dashboard]
host = "127.0.0.1"
port = 5000
auth_token = ""                  # leave empty to disable auth — inject via env var in production
auth_required_for_reads = false

[syslog]                         # SIEM (CEF over syslog)
enabled = true
host = "siem.corp.local"
port = 514
protocol = "udp"                 # udp | tcp
min_severity = "HIGH"

[webhook]                        # Slack / Teams / PagerDuty / SOAR
enabled = true
url = "https://hooks.example.com/services/XXX"
min_severity = "CRITICAL"
```

> `.toml` requires Python 3.11+ (`tomllib`). On Python 3.10 use
> `ransomguard.json` with the same structure.

### Secret injection via environment variables

Prefer environment variables over storing secrets in the config file.
Environment variables always override the file:

| Variable | Effect |
|----------|--------|
| `RANSOMGUARD_AUTH_TOKEN` | Set the dashboard API token |
| `RANSOMGUARD_WEBHOOK_URL` | Enable webhook and set the URL |
| `RANSOMGUARD_SYSLOG_HOST` | Enable syslog and set the host |

```powershell
# Example: set env vars before starting the agent
$env:RANSOMGUARD_AUTH_TOKEN    = "prod-secret-token"
$env:RANSOMGUARD_WEBHOOK_URL   = "https://hooks.slack.com/services/XXX"
$env:RANSOMGUARD_SYSLOG_HOST   = "siem.corp.local"
python agent.py --config ransomguard.toml
```

### Specifying the config path

```powershell
# Auto-detect (searches working directory for ransomguard.toml / .json)
python agent.py

# Explicit path
python agent.py --config C:\ProgramData\RansomGuard\policy.toml
```

---

## 12. SIEM and Webhook Integration

### SIEM (CEF over syslog)

Compatible with any CEF parser — Splunk, QRadar, ArcSight, Microsoft
Sentinel. HIGH+ events are forwarded asynchronously. Fail-open: an
integration failure is logged but never stops detection.

Fill in the `[syslog]` section of `ransomguard.toml`, or set the
environment variable:

```toml
[syslog]
enabled = true
host = "siem.corp.local"   # or IP address
port = 514
protocol = "udp"           # udp | tcp
min_severity = "HIGH"      # INFO | LOW | MEDIUM | HIGH | CRITICAL
```

Or via environment variable alone:

```powershell
$env:RANSOMGUARD_SYSLOG_HOST = "siem.corp.local"
# enabled and other defaults are applied automatically
```

### Webhook (Slack / Teams / PagerDuty / SOAR)

```toml
[webhook]
enabled = true
url = "https://hooks.example.com/services/XXX"
min_severity = "CRITICAL"
```

Or via environment variable alone:

```powershell
$env:RANSOMGUARD_WEBHOOK_URL = "https://hooks.slack.com/services/XXX"
```

> The webhook payload is generic JSON, so it works with Slack incoming
> webhooks, Teams connectors, PagerDuty Events API v2, and arbitrary
> SOAR HTTP triggers without modification.

### Heartbeat stays open

The watchdog service polls `http://127.0.0.1:5000/api/heartbeat` every
5 seconds. Even when a token is configured, this endpoint returns 200 OK
without authentication — ensuring the watchdog restart loop is never
broken by auth changes.
