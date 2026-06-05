"""
Incident Reporter
-----------------
Hooks the ``ProcessResponder``'s ``on_action`` callback.  Every time the
responder actually does something to a process (quarantine or terminate),
we

  1. write a self-contained markdown incident report under ``reports/``
     so the operator has an audit trail they can hand to IR / legal /
     ticket the post-mortem against, and
  2. push a desktop notification so the user knows immediately, even
     when the dashboard isn't in focus.

No-ops (self-pid refusal, never-kill list hits, OFF-mode would-be kills)
are intentionally skipped — they didn't actually do anything to the
target, so there's nothing to report.

Notifications are best-effort and run in a background thread so a
blocking native dialog can't stall the responder.
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Deque, Dict, List, Optional

from scoring import ScoringEngine, Signal

# Native desktop notifications are *best effort* and purely advisory: the
# authoritative record is the markdown report + the dashboard.  When an
# incident storm hits (e.g. ransomware fanning out, or a browser spawning
# dozens of child processes the moment the operator opens the dashboard),
# firing one native popup per incident floods the screen and — with the
# blocking fallbacks — can wedge the desktop.  So we cap how many native
# popups we raise per rolling window; anything beyond the cap is still
# written to disk and surfaced in the dashboard, just not popped natively.
_NOTIFY_MAX_PER_WINDOW = 3
_NOTIFY_WINDOW_SECS = 30.0

# Reports are deduped per (pid, terminated, quarantined) state, but only for
# a rolling window — not forever.  A time window (rather than a permanent set)
# matters for live operation: it bounds memory on a long-running agent, lets a
# *persistent* attacker re-alert if it's still tripping after the window, and
# avoids permanently muzzling a reused PID or one the operator manually
# released and which later re-offends.
_REPORT_DEDUP_SECS = 60.0
_REPORT_DEDUP_MAX = 2048  # hard cap on tracked states; prune when exceeded

# 통합(campaign) 보고서: 마지막 인시던트로부터 이 시간 안에 발생한 새 인시던트는
# *같은 공격*으로 간주해 한 건으로 묶는다.  점수 채점 윈도우(120초)와 맞춰,
# 부모 프로세스가 띄운 자식들(vssadmin/cmd 등)이 한 사건으로 통합되게 한다.
_CAMPAIGN_GAP_SECS = 120.0
_CAMPAIGN_MAX = 200  # 추적할 campaign 최대 개수 (오래된 것부터 정리)

# Spawning a console subprocess (e.g. powershell for a BurntToast popup) from a
# context that has no inherited console makes Windows allocate — and instantly
# tear down — a console window.  It flashes as a brief black rectangle, and a
# burst of notifications reads as the screen "blinking"/lagging right when an
# incident fires.  CREATE_NO_WINDOW suppresses it.  The attribute is Windows-
# only; on POSIX getattr falls back to 0, a valid no-op creationflags value.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# ---- 비전공자용 한글 표기 ------------------------------------------------
# 보고서는 운영자(주로 비전공자)가 바로 이해할 수 있게 한국어 + 평이한 설명
# 으로 작성한다.  기술 상세(신호 표, 원시 JSON)는 하단 "기술 상세" 섹션에
# 따로 보존해 전문가/포렌식 용도도 만족시킨다.
DETECTOR_KO = {
    "canary":          "미끼 파일 감시",
    "mass_io":         "대량 파일 변경 감지",
    "process_cmdline": "의심 명령어 감지",
    "process_watcher": "프로세스 감시",
    "minifilter":      "커널 파일 보호",
    "registry_kernel": "레지스트리 감시",
    "process_kernel":  "커널 프로세스 감시",
}

SEVERITY_KO = {
    "INFO": "정보", "LOW": "낮음", "MEDIUM": "주의",
    "HIGH": "경고", "CRITICAL": "위험",
}

MODE_KO = {"off": "감시만 (조치 안 함)", "quarantine": "격리", "kill": "강제 종료"}

# 신호 이름 -> 비전공자도 이해할 한 줄 설명
SIGNAL_KO = {
    # 백업/복구 무력화 (사전 암호화 정황)
    "vssadmin_delete_shadows":      "볼륨 섀도(자동 백업본) 삭제 시도 — 복구를 막으려는 랜섬웨어의 전형적 수법입니다.",
    "wmic_shadowcopy_delete":       "WMIC로 백업 섀도 복사본 삭제 시도 — 백업 무력화입니다.",
    "powershell_remove_shadowcopy": "PowerShell로 백업 섀도 복사본 삭제 시도 — 백업 무력화입니다.",
    "wbadmin_delete_catalog":       "Windows 백업 카탈로그 삭제 시도입니다.",
    "fsutil_usn_delete":            "파일 변경 이력(USN) 삭제 시도 — 흔적 지우기입니다.",
    "bcdedit_recovery_disabled":    "Windows 복구 환경 비활성화 시도입니다.",
    "bcdedit_ignore_failures":      "부팅 오류 무시 설정 — 복구 방해 시도입니다.",
    "bcdedit_safeboot":             "안전 모드 부팅 조작 시도입니다.",
    "bitlocker_disable":            "BitLocker 디스크 암호화 해제 시도입니다.",
    # 보안 기능 무력화
    "defender_add_exclusion":       "Windows Defender 검사 제외 추가 시도입니다.",
    "defender_disable_realtime":    "Windows Defender 실시간 보호 끄기 시도입니다.",
    "defender_disable_via_registry":"레지스트리로 Windows Defender 끄기 시도입니다.",
    "smartscreen_disable":          "SmartScreen 보호 끄기 시도입니다.",
    "netsh_firewall_off":           "Windows 방화벽 끄기 시도입니다.",
    # 흔적 삭제 / 지속성 / 의심 실행
    "wevtutil_clear_log":           "Windows 이벤트 로그 삭제 시도 — 흔적 지우기입니다.",
    "powershell_clear_eventlog":    "PowerShell로 이벤트 로그 삭제 시도입니다.",
    "cipher_wipe_free_space":       "빈 공간 완전 삭제(cipher) — 데이터 복구를 막으려는 시도입니다.",
    "run_key_persistence":          "재부팅 후 자동 실행 등록(지속성 확보) 시도입니다.",
    "schtasks_persistence":         "예약 작업 등록(지속성 확보) 시도입니다.",
    "powershell_bypass_policy":     "PowerShell 실행 정책 우회 시도입니다.",
    "powershell_obfuscated_exec":   "난독화된 PowerShell 명령 실행 — 악성 코드 은폐 정황입니다.",
    "powershell_downloader":        "PowerShell로 외부 파일 다운로드 시도입니다.",
    # 실제 암호화/파괴 정황 (파일 내용/커널)
    "high_entropy_write":           "파일을 알아볼 수 없는 무작위 데이터로 덮어씀 — 암호화 정황입니다.",
    "magic_bytes_lost":             "파일 형식 서명이 사라짐 — 파일 손상/암호화 정황입니다.",
    "modify_burst":                 "짧은 시간에 많은 파일이 한꺼번에 변경되었습니다.",
    "suspicious_extension":         "의심스러운 확장자로 파일 이름이 바뀌었습니다(예: .encrypted).",
    "file_delete":                  "원본 파일 삭제가 감지되었습니다.",
    "kernel_write_burst":           "커널 수준에서 대량 파일 쓰기가 감지되었습니다.",
    "kernel_rename_burst":          "커널 수준에서 대량 파일 이름 변경이 감지되었습니다.",
    "kernel_blocked_op":            "커널이 의심스러운 파일 작업을 차단했습니다.",
    "process_write_burst":          "한 프로그램이 짧은 시간에 다량의 파일을 기록했습니다.",
    # 미끼(canary) 파일
    "canary_modified":              "미끼 파일이 변경됨 — 무차별 암호화가 진행 중일 가능성이 있습니다.",
    "canary_deleted":               "미끼 파일이 삭제되었습니다.",
    # 프로세스 행위
    "child_fanout":                 "한 프로그램이 짧은 시간에 다수의 자식 프로세스를 생성 — 확산 정황입니다.",
    "suspicious_parent_child":      "비정상적인 프로그램 실행 체인이 감지되었습니다.",
    "tamper_blocked":               "보호 대상(보안 에이전트)에 대한 조작 시도가 차단되었습니다.",
}


def _ko_detector(name: str) -> str:
    return DETECTOR_KO.get(name, name)


def _ko_severity(value: str) -> str:
    return SEVERITY_KO.get(value, value)


def _signame_from_reason(reason: Optional[str]) -> str:
    """``"process_cmdline/vssadmin_delete_shadows [correlated]"`` -> 신호 이름."""
    parts = (reason or "").split("/", 1)
    sig = parts[1] if len(parts) > 1 else (parts[0] if parts else "")
    return sig.split()[0] if sig else ""


# ---- 피해 범위 추정 ------------------------------------------------------
# 차단 시점에 "이 프로세스가 실제로 무슨 파일을 건드렸나"를 보고서에 바로
# 넣기 위한 집계.  디스크를 새로 스캔하지 않고, 이미 들어온 신호의 metadata
# 에서 파일 경로를 모아 분류한다 — 따라서 *관측된 최소 추정치*이며, 정확한
# 디스크 단위 집계는 postmortem.py(디코이 기준)가 담당한다.
_PATH_KEYS = ("path", "dest", "src", "last_path", "new_path", "old_path", "target")

# 신호 이름 -> 피해 분류
_DMG_ENCRYPT = frozenset({
    "high_entropy_write", "magic_bytes_lost", "modify_burst",
    "kernel_write_burst", "process_write_burst", "canary_modified",
})
_DMG_RENAME = frozenset({"suspicious_extension", "kernel_rename_burst"})
_DMG_DELETE = frozenset({"file_delete", "canary_deleted"})


def _sig_paths(sig: "Signal") -> List[str]:
    meta = sig.metadata or {}
    out: List[str] = []
    for k in _PATH_KEYS:
        v = meta.get(k)
        if isinstance(v, str) and v:
            out.append(v)
    return out


def summarize_damage(signals: List["Signal"]) -> dict:
    """신호 목록에서 영향받은 파일을 분류 집계한다."""
    enc: set = set()
    ren: set = set()
    dele: set = set()
    max_modify_burst = 0
    max_rename_burst = 0
    max_write_bytes = 0
    canary = False
    for s in signals:
        name = s.name
        meta = s.metadata or {}
        paths = _sig_paths(s)
        if name in _DMG_ENCRYPT:
            enc.update(paths)
            if name == "modify_burst":
                max_modify_burst = max(max_modify_burst, int(meta.get("count", 0) or 0))
            elif name == "kernel_write_burst":
                max_write_bytes = max(max_write_bytes, int(meta.get("bytes", 0) or 0))
            elif name == "canary_modified":
                canary = True
        elif name in _DMG_RENAME:
            ren.update(paths)
            if name == "kernel_rename_burst":
                max_rename_burst = max(max_rename_burst, int(meta.get("count", 0) or 0))
        elif name in _DMG_DELETE:
            dele.update(paths)
            if name == "canary_deleted":
                canary = True
    distinct = enc | ren | dele
    return {
        "encrypted": enc,
        "renamed": ren,
        "deleted": dele,
        "distinct_total": len(distinct),
        "max_modify_burst": max_modify_burst,
        "max_rename_burst": max_rename_burst,
        "max_write_bytes": max_write_bytes,
        "canary": canary,
    }


def _damage_headline(d: dict) -> str:
    """한 줄 요약 (한눈에 보기 / campaign 헤더용)."""
    return (f"변조/암호화 {len(d['encrypted'])}개 · 이름변경 {len(d['renamed'])}개 "
            f"· 삭제 {len(d['deleted'])}개 (고유 합계 {d['distinct_total']}개)")


def _damage_lines(d: dict) -> List[str]:
    lines: List[str] = []
    lines.append(f"- **변조/암호화 정황 파일:** {len(d['encrypted'])}개")
    lines.append(f"- **이름이 바뀐 파일:** {len(d['renamed'])}개")
    lines.append(f"- **삭제된 파일:** {len(d['deleted'])}개")
    lines.append(f"- **영향받은 고유 파일(합계):** {d['distinct_total']}개")
    intensity: List[str] = []
    if d["max_modify_burst"]:
        intensity.append(f"한 번에 최대 {d['max_modify_burst']}개 동시 변경")
    if d["max_rename_burst"]:
        intensity.append(f"한 번에 최대 {d['max_rename_burst']}개 동시 이름변경")
    if d["max_write_bytes"]:
        intensity.append(f"관측된 최대 쓰기량 {d['max_write_bytes'] / (1024 * 1024):.1f} MB")
    if intensity:
        lines.append("- **활동 강도:** " + ", ".join(intensity))
    if d["canary"]:
        lines.append("- **미끼(canary) 파일 침해:** 예 — 무차별 암호화가 "
                     "진행 중이었다는 강한 정황입니다.")
    samples = (list(d["encrypted"])[:5]
               + list(d["renamed"])[:5]
               + list(d["deleted"])[:5])[:8]
    if samples:
        lines.append("- **영향받은 파일 예시:**")
        for p in samples:
            lines.append(f"  - `{p}`")
    lines.append("")
    lines.append("> 이 수치는 탐지기가 **관측한 신호 기준의 최소 추정치**입니다. "
                 "차단 직전 짧은 순간의 일부 작업은 누락될 수 있고, 디스크 단위의 "
                 "정확한 피해 집계는 `postmortem.py`(디코이 기준)를 참고하세요.")
    return lines


@dataclass
class IncidentRecord:
    timestamp: float
    pid: int
    process_name: str
    reason: str
    terminated: bool
    quarantined: bool
    filename: str
    path: str
    kind: str = "incident"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class _Campaign:
    """시간 윈도우로 묶인 하나의 공격 사건 (여러 PID를 한 건으로 통합)."""
    start_ts: float
    last_ts: float
    filename: str
    pids: set
    members: List[dict]   # {ts, pid, name, reason, terminated, quarantined, incident_file}


class IncidentReporter:
    def __init__(self,
                 engine: ScoringEngine,
                 *,
                 reports_dir: str = "reports",
                 notify: bool = True):
        self.engine = engine
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.notify = notify
        self._lock = threading.Lock()
        self._records: List[IncidentRecord] = []
        # (pid, terminated, quarantined) -> last time we reported that state.
        # A pid that keeps tripping the same detector (very common with the
        # kernel minifilter on — it re-flags the encrypting pid on every file
        # op) is deduped within a rolling window so it doesn't spawn a fresh
        # report + popup each time.  A genuine escalation (quarantine → later
        # kill) is a different tuple and is still reported immediately.
        self._reported_states: Dict[tuple, float] = {}
        # Rolling timestamps of native popups we've raised, for rate limiting.
        self._notify_window: Deque[float] = deque()
        self._notify_lock = threading.Lock()
        # 통합(campaign) 보고서 상태.  on_action 에서 시간 윈도우로 묶는다.
        self._campaigns: List[_Campaign] = []

    # -------------------------------------------------------------- callback

    def on_action(self, action) -> None:
        """Wired into ``ProcessResponder(on_action=...)``."""
        # We only report when the responder actually did something to the
        # target.  Refusals, OFF-mode passes, and never-kill hits leave
        # both flags False and carry an error string explaining why.
        if not (action.terminated or action.quarantined):
            return

        # Suppress duplicate reports for a pid we've already reported in this
        # exact state within the dedup window.  Repeated identical signals for
        # the same pid (the norm under the kernel minifilter) otherwise pile up
        # reports + popups even though nothing new happened to the process.
        state = (action.pid, bool(action.terminated), bool(action.quarantined))
        now = time.time()
        with self._lock:
            last = self._reported_states.get(state)
            if last is not None and (now - last) < _REPORT_DEDUP_SECS:
                return
            self._reported_states[state] = now
            # Bound memory: when the map grows too large, drop entries whose
            # window has fully elapsed (they can only ever re-report anyway).
            if len(self._reported_states) > _REPORT_DEDUP_MAX:
                cutoff = now - _REPORT_DEDUP_SECS
                self._reported_states = {
                    k: v for k, v in self._reported_states.items() if v >= cutoff
                }

        content = self._build_markdown(action)
        path = self._write_file(content, action)

        record = IncidentRecord(
            timestamp=action.timestamp,
            pid=action.pid,
            process_name=action.process_name or "unknown",
            reason=action.reason,
            terminated=bool(action.terminated),
            quarantined=bool(action.quarantined),
            filename=path.name,
            path=str(path),
        )
        with self._lock:
            self._records.append(record)
            if len(self._records) > 500:
                self._records = self._records[-500:]

        print(f"[reporter] incident report written: {path}")

        # 이 인시던트를 진행 중인 공격(campaign)에 합치고 통합 보고서를 갱신.
        try:
            self._update_campaign(action, path)
        except Exception as e:  # 통합 보고서 실패가 핵심 대응을 막으면 안 됨
            print(f"[reporter] campaign update failed: {e}")

        if self.notify and self._notify_rate_ok():
            t = threading.Thread(
                target=self._notify_user,
                args=(action, path),
                daemon=True,
            )
            t.start()

    # ------------------------------------------------------------------ API

    def recent(self, limit: int = 50) -> List[dict]:
        with self._lock:
            items = [r.to_dict() for r in self._records]
            # 2개 이상 프로세스를 묶은 공격만 통합 항목으로 노출한다.  단일
            # 프로세스 공격은 개별 인시던트만으로 충분히 설명되므로 중복 노출
            # 하지 않는다(목록이 시끄러워지는 것을 방지).
            for c in self._campaigns:
                if len(c.pids) >= 2:
                    items.append(self._campaign_record(c))
        items.sort(key=lambda d: d.get("timestamp", 0), reverse=True)
        return items[:limit]

    def _campaign_record(self, c: _Campaign) -> dict:
        lead = c.members[0] if c.members else {}
        lead_name = lead.get("name") or "알 수 없음"
        n = len(c.pids)
        terminated = any(m.get("terminated") for m in c.members)
        quarantined = any(m.get("quarantined") for m in c.members)
        return {
            "timestamp": c.last_ts,
            "pid": lead.get("pid", 0),
            "process_name": f"🛡 통합 사건 — {lead_name} 외 {n - 1}개 프로세스",
            "reason": f"campaign/{n}_processes",
            "terminated": terminated,
            "quarantined": quarantined,
            "filename": c.filename,
            "path": str(self.reports_dir / c.filename),
            "kind": "campaign",
        }

    def read_report(self, filename: str) -> Optional[str]:
        # Defence-in-depth: only allow plain filenames inside reports_dir.
        if not filename or "/" in filename or "\\" in filename or ".." in filename:
            return None
        p = self.reports_dir / filename
        try:
            p_resolved = p.resolve()
            if not str(p_resolved).startswith(str(self.reports_dir.resolve())):
                return None
            if not p_resolved.is_file():
                return None
            return p_resolved.read_text(encoding="utf-8")
        except OSError:
            return None

    # ------------------------------------------------------- markdown body

    def _build_markdown(self, action) -> str:
        ts_local = time.strftime(
            "%Y-%m-%d %H:%M:%S %Z", time.localtime(action.timestamp)
        )
        score = self.engine.current_score()
        level = self.engine.current_level().value
        recent = self.engine.recent_signals(limit=200)

        pid_signals = [s for s in recent if self._signal_pid(s) == action.pid]
        damage = summarize_damage(pid_signals)

        proc_name = action.process_name or "알 수 없음"
        cmd = action.cmdline or "(확인 불가)"

        # 평이한 요약
        what = SIGNAL_KO.get(_signame_from_reason(action.reason),
                             "의심스러운 보안 위협 행위가 탐지되었습니다.")
        if action.reason and "correlated" in action.reason:
            what += " (실제 파일 변경 활동과 연관 지어 탐지했습니다.)"

        if action.terminated and action.quarantined:
            did = "위협 프로그램을 **격리한 뒤 강제 종료**했습니다."
            safe = "예 — 해당 프로그램을 완전히 멈췄습니다."
        elif action.terminated:
            did = ("위협 프로그램을 **강제 종료**했습니다. "
                   "해당 프로그램은 더 이상 실행되지 않습니다.")
            safe = "예 — 해당 프로그램을 멈췄습니다."
        else:  # 격리만 수행
            did = ("위협 프로그램을 **격리**했습니다. 프로그램은 살아 있지만 "
                   "파일을 더 이상 바꾸지 못하도록 차단했습니다.")
            safe = ("추가 피해는 차단했습니다. 다만 프로그램 자체는 아직 실행 "
                    "중이라 주의가 필요합니다.")

        lines: List[str] = []
        lines.append(f"# 위협 처리 결과 — {proc_name} (PID {action.pid})")
        lines.append("")
        lines.append(f"> RansomGuard가 자동으로 탐지하고 처리했습니다 · {ts_local}")
        lines.append("")

        lines.append("## 한눈에 보기")
        lines.append("")
        lines.append(f"- **무슨 일이 있었나요?** {what}")
        lines.append(f"- **무엇을 했나요?** {did}")
        lines.append(f"- **지금 안전한가요?** {safe}")
        lines.append(f"- **추정 피해 규모:** {_damage_headline(damage)}")
        lines.append("- **무엇을 하면 되나요?** "
                     f"이 프로그램(`{proc_name}`)을 직접 실행한 적이 없다면, 최근 내려받은 "
                     "파일이나 설치한 프로그램을 점검하고 중요한 자료의 백업 상태를 "
                     "확인하세요. 정상 프로그램으로 의심되면 관리자에게 문의하세요.")
        lines.append("")

        lines.append("## 어떤 프로그램이었나요")
        lines.append("")
        lines.append(f"- **프로그램 이름:** `{proc_name}`")
        lines.append(f"- **프로세스 번호(PID):** `{action.pid}`")
        lines.append(f"- **탐지한 기능:** {_ko_detector(action.reason.split('/', 1)[0])}")
        lines.append("- **실행 명령어:**")
        lines.append("")
        lines.append("  ```")
        lines.append(f"  {cmd}")
        lines.append("  ```")
        lines.append("")

        lines.append("## 어떤 조치를 했나요")
        lines.append("")
        lines.append(f"- **격리(파일 접근 차단):** {'예' if action.quarantined else '아니오'}")
        lines.append(f"- **강제 종료:** {'예' if action.terminated else '아니오'}")
        lines.append(f"- **대응 모드:** {MODE_KO.get(str(action.mode), str(action.mode))}")
        if action.error:
            lines.append(f"- **참고(오류):** {action.error}")
        lines.append("")

        lines.append("## 위협 수준")
        lines.append("")
        lines.append(f"- **현재 위험 점수(최근 120초 누적):** {score} (150 이상이면 자동 차단)")
        lines.append(f"- **판정된 위협 수준:** **{_ko_severity(level)}** ({level})")
        lines.append("")

        lines.append("## 피해 범위 (이 프로그램이 건드린 파일)")
        lines.append("")
        lines.extend(_damage_lines(damage))
        lines.append("")

        # ---- 자세한 정보 (전문/포렌식용) ----
        lines.append("---")
        lines.append("")
        lines.append("## 자세한 정보")
        lines.append("")
        lines.append(f"- 탐지 사유 코드: `{action.reason}`")
        lines.append(f"- 호스트: `{platform.node()}` "
                     f"({platform.system()} {platform.release()})")
        lines.append("")

        if pid_signals:
            lines.append(f"### 이 프로세스(PID {action.pid})에 대한 탐지 신호")
            lines.append("")
            lines.extend(self._signal_table(pid_signals[-30:]))
            lines.append("")

        if recent:
            lines.append("### 최근 탐지 신호")
            lines.append("")
            lines.extend(self._signal_table(recent[-20:]))
            lines.append("")

        lines.append("### 처리 기록 원본 (JSON)")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(action.to_dict(), indent=2,
                                default=str, ensure_ascii=False))
        lines.append("```")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _signal_table(signals: List[Signal]) -> List[str]:
        out = [
            "| 시각 | 탐지기 | 신호 | 심각도 | 가중치 | 메시지 |",
            "|------|--------|------|--------|--------|--------|",
        ]
        for s in signals:
            t = time.strftime("%H:%M:%S", time.localtime(s.timestamp))
            msg = (s.message or "").replace("|", "\\|").replace("\n", " ")
            if len(msg) > 140:
                msg = msg[:137] + "..."
            out.append(
                f"| {t} | {_ko_detector(s.detector)} | {s.name} "
                f"| {_ko_severity(s.severity.value)} | {s.weight} | {msg} |"
            )
        return out

    @staticmethod
    def _signal_pid(sig: Signal) -> Optional[int]:
        meta = sig.metadata or {}
        for key in ("pid", "ProcessId", "child_pid", "process_id"):
            val = meta.get(key)
            if isinstance(val, int) and val > 0:
                return val
        return None

    # ------------------------------------------------------- file output

    def _write_file(self, content: str, action) -> Path:
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(action.timestamp))
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_",
                           action.process_name or "unknown")
        fname = f"incident_{ts}_pid{action.pid}_{safe_name}.md"
        path = self.reports_dir / fname
        path.write_text(content, encoding="utf-8")
        return path

    # ------------------------------------------------------- campaign rollup

    def _update_campaign(self, action, incident_path: Path) -> None:
        """이 인시던트를 진행 중 공격에 합치고 통합 보고서를 갱신한다."""
        ts = action.timestamp
        member = {
            "ts": ts,
            "pid": action.pid,
            "name": action.process_name or "알 수 없음",
            "reason": action.reason or "",
            "terminated": bool(action.terminated),
            "quarantined": bool(action.quarantined),
            "incident_file": incident_path.name,
        }
        with self._lock:
            camp = None
            if self._campaigns:
                last = self._campaigns[-1]
                if ts - last.last_ts <= _CAMPAIGN_GAP_SECS:
                    camp = last
            if camp is None:
                fname = ("campaign_"
                         + time.strftime("%Y%m%d_%H%M%S", time.localtime(ts))
                         + ".md")
                camp = _Campaign(start_ts=ts, last_ts=ts, filename=fname,
                                 pids=set(), members=[])
                self._campaigns.append(camp)
                if len(self._campaigns) > _CAMPAIGN_MAX:
                    self._campaigns = self._campaigns[-_CAMPAIGN_MAX:]
            camp.last_ts = max(camp.last_ts, ts)
            camp.pids.add(action.pid)
            camp.members.append(member)
            # 락을 들고 디스크 I/O·엔진 호출을 하지 않도록 스냅샷만 떠서 나간다.
            snap = _Campaign(start_ts=camp.start_ts, last_ts=camp.last_ts,
                             filename=camp.filename, pids=set(camp.pids),
                             members=list(camp.members))
        content = self._build_campaign_markdown(snap)
        (self.reports_dir / snap.filename).write_text(content, encoding="utf-8")

    def _build_campaign_markdown(self, camp: _Campaign) -> str:
        start_local = time.strftime("%Y-%m-%d %H:%M:%S %Z",
                                    time.localtime(camp.start_ts))
        last_local = time.strftime("%H:%M:%S", time.localtime(camp.last_ts))

        # 이 공격에 속한 모든 PID 의 신호를 모아 통합 피해를 집계한다.
        recent = self.engine.recent_signals(limit=500)
        camp_signals = [s for s in recent if self._signal_pid(s) in camp.pids]
        damage = summarize_damage(camp_signals)

        n_proc = len(camp.pids)
        killed = sum(1 for m in camp.members if m["terminated"])
        quar = sum(1 for m in camp.members if m["quarantined"])
        reasons = [m["reason"] for m in camp.members if m["reason"]]
        what = SIGNAL_KO.get(
            _signame_from_reason(reasons[0] if reasons else ""),
            "의심스러운 보안 위협 행위가 탐지되었습니다.")

        L: List[str] = []
        L.append(f"# 통합 위협 보고서 — 공격 사건 ({n_proc}개 프로세스)")
        L.append("")
        L.append(f"> RansomGuard 자동 탐지·대응 · {start_local} ~ {last_local}")
        L.append("")

        L.append("## 한눈에 보기")
        L.append("")
        L.append(f"- **무슨 공격이었나요?** {what}")
        L.append("- **관련 프로세스:** "
                 f"{n_proc}개 (PID {', '.join(str(p) for p in sorted(camp.pids))})")
        L.append(f"- **무엇을 했나요?** 강제 종료 {killed}개 · 격리 {quar}개")
        L.append(f"- **추정 피해 규모:** {_damage_headline(damage)}")
        if damage["canary"]:
            L.append("- **미끼(canary) 파일 침해:** 예 — 무차별 암호화 정황입니다.")
        L.append("")

        L.append("## 처리한 프로세스 목록")
        L.append("")
        L.append("| 시각 | PID | 프로세스 | 격리 | 종료 | 사유 | 개별 보고서 |")
        L.append("|------|-----|----------|------|------|------|-------------|")
        for m in sorted(camp.members, key=lambda x: x["ts"]):
            t = time.strftime("%H:%M:%S", time.localtime(m["ts"]))
            reason = (m["reason"] or "").replace("|", "\\|")
            name = (m["name"] or "").replace("|", "\\|")
            L.append(f"| {t} | {m['pid']} | `{name}` "
                     f"| {'예' if m['quarantined'] else '·'} "
                     f"| {'예' if m['terminated'] else '·'} "
                     f"| {reason} "
                     f"| [{m['incident_file']}]({m['incident_file']}) |")
        L.append("")

        L.append("## 통합 피해 범위")
        L.append("")
        L.extend(_damage_lines(damage))
        L.append("")

        if camp_signals:
            L.append("## 통합 탐지 타임라인")
            L.append("")
            L.extend(self._signal_table(camp_signals[-40:]))
            L.append("")

        L.append("---")
        L.append("")
        L.append("> 같은 시간대(120초 이내 연쇄)에 처리된 프로세스들을 하나의 "
                 "공격으로 묶은 통합 요약입니다. 프로세스별 상세·원본 JSON 은 위 "
                 "표의 개별 보고서를 참고하세요.")
        L.append("")
        return "\n".join(L)

    # ---------------------------------------------- desktop notifications

    def _notify_rate_ok(self) -> bool:
        """True if we're under the native-popup budget for the window.

        Prevents an incident storm from flooding the desktop with popups
        (and, with blocking fallbacks, wedging it).  Suppressed popups are
        still recorded on disk and shown in the dashboard.
        """
        now = time.time()
        with self._notify_lock:
            cutoff = now - _NOTIFY_WINDOW_SECS
            while self._notify_window and self._notify_window[0] < cutoff:
                self._notify_window.popleft()
            if len(self._notify_window) >= _NOTIFY_MAX_PER_WINDOW:
                if len(self._notify_window) == _NOTIFY_MAX_PER_WINDOW:
                    # Log the throttle exactly once per saturated window.
                    print("[reporter] notification rate limit hit; "
                          "suppressing native popups (reports still written)")
                    self._notify_window.append(now)  # mark as logged
                return False
            self._notify_window.append(now)
            return True

    def _notify_user(self, action, path: Path) -> None:
        verb = "Killed" if action.terminated else "Quarantined"
        title = (f"RansomGuard: {verb} {action.process_name or '?'} "
                 f"(PID {action.pid})")
        body = f"Reason: {action.reason}\nReport: {path.name}"
        sysname = platform.system()
        try:
            if sysname == "Windows":
                self._notify_windows(title, body)
            elif sysname == "Linux":
                self._notify_linux(title, body)
            elif sysname == "Darwin":
                self._notify_macos(title, body)
            else:
                # Console bell as last-resort signal.
                print(f"\a[NOTIFY] {title}\n         {body}")
        except Exception as e:
            print(f"[reporter] notification failed: {e}")

    def _notify_linux(self, title: str, body: str) -> None:
        if shutil.which("notify-send"):
            subprocess.run(
                ["notify-send", "-u", "critical",
                 "-i", "dialog-warning", title, body],
                timeout=5, check=False, creationflags=_NO_WINDOW,
            )
            return
        print(f"\a[NOTIFY] {title}\n         {body}")

    def _notify_macos(self, title: str, body: str) -> None:
        if shutil.which("osascript"):
            # Escape embedded double quotes for AppleScript.
            t = title.replace('"', '\\"')
            b = body.replace('"', '\\"').replace("\n", " — ")
            subprocess.run(
                ["osascript", "-e",
                 f'display notification "{b}" with title "{t}"'],
                timeout=5, check=False, creationflags=_NO_WINDOW,
            )
            return
        print(f"\a[NOTIFY] {title}\n         {body}")

    def _notify_windows(self, title: str, body: str) -> None:
        # Preferred: win10toast (pure-python, uses pywin32 under the hood).
        try:
            from win10toast import ToastNotifier  # type: ignore
            ToastNotifier().show_toast(title, body, duration=8, threaded=True)
            return
        except Exception:
            pass
        # Fallback: PowerShell BurntToast module if the operator has it.
        try:
            ps = (
                "$ErrorActionPreference='Stop';"
                "Import-Module BurntToast;"
                f"New-BurntToastNotification -Text {self._psq(title)},"
                f"{self._psq(body)}"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                timeout=6, capture_output=True, creationflags=_NO_WINDOW,
            )
            if r.returncode == 0:
                return
        except Exception:
            pass
        # Last resort: a non-blocking console line + bell.  We deliberately
        # do NOT pop a modal MessageBox here: a system-modal dialog steals
        # global input focus, and one per incident stacks into an
        # unclosable wall that wedges the desktop during an incident storm.
        # The report file and the dashboard remain the durable record.
        print(f"\a[NOTIFY] {title}\n         {body}")

    @staticmethod
    def _psq(s: str) -> str:
        """PowerShell single-quoted literal, with quotes escaped."""
        return "'" + s.replace("'", "''") + "'"
