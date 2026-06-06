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
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Deque, Dict, List, Optional

from scoring import ScoringEngine, Signal, ENCRYPTION_SIGNAL_NAMES

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

# 통합 보고서 "최종 확정" 타이밍: 마지막 인시던트로부터 _CAMPAIGN_GAP_SECS(=점수
# 채점 윈도우)만큼 새 사건이 없으면, 그 사이 모든 신호는 점수 윈도우에서 빠져
# 점수가 0(INFO)으로 초기화된다 = "사건 종료".  그 순간 잠정 보고서를 최종본으로
# 확정한다.  백그라운드 스레드가 이 주기로 깨어나 확정 대상을 점검한다.
_CAMPAIGN_FINALIZE_POLL_SECS = 5.0

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


# 신호 이름 -> "왜 차단했나" (그대로 두면 어떤 결과가 생기는지).  비전공자가
# "이걸 왜 막았지?" 를 바로 이해하도록 결과 중심으로 설명한다.
SIGNAL_WHY = {
    # 백업/복구 무력화
    "vssadmin_delete_shadows":      "그대로 두면 Windows가 자동 보관한 복원 지점(백업본)이 삭제되어, 암호화된 파일을 되돌릴 수 없게 되기 때문입니다.",
    "wmic_shadowcopy_delete":       "그대로 두면 백업 복사본이 삭제되어 파일을 복구할 수 없게 되기 때문입니다.",
    "powershell_remove_shadowcopy": "그대로 두면 백업 복사본이 삭제되어 파일을 복구할 수 없게 되기 때문입니다.",
    "wbadmin_delete_catalog":       "그대로 두면 백업 카탈로그가 삭제되어 백업으로 복구할 수 없게 되기 때문입니다.",
    "fsutil_usn_delete":            "그대로 두면 파일 변경 이력이 지워져 어떤 파일이 피해를 입었는지 추적할 수 없게 되기 때문입니다.",
    "bcdedit_recovery_disabled":    "그대로 두면 Windows 복구 환경이 꺼져 시스템 복구 기능을 쓸 수 없게 되기 때문입니다.",
    "bcdedit_ignore_failures":      "그대로 두면 부팅 오류를 무시하도록 바뀌어 정상 복구 절차가 작동하지 않게 되기 때문입니다.",
    "bcdedit_safeboot":             "그대로 두면 안전 모드 부팅이 조작되어 백신·복구 도구 실행을 방해할 수 있기 때문입니다.",
    "bitlocker_disable":            "그대로 두면 디스크 암호화가 해제되어 데이터 보호가 무력화되기 때문입니다.",
    # 보안 기능 무력화
    "defender_add_exclusion":       "그대로 두면 백신 검사에서 제외 항목이 생겨 악성코드가 감시를 피하게 되기 때문입니다.",
    "defender_disable_realtime":    "그대로 두면 백신 실시간 보호가 꺼져 이후 악성 행위를 막지 못하게 되기 때문입니다.",
    "defender_disable_via_registry":"그대로 두면 레지스트리 조작으로 백신이 꺼져 보호가 사라지기 때문입니다.",
    "smartscreen_disable":          "그대로 두면 SmartScreen이 꺼져 악성 다운로드·실행 경고가 사라지기 때문입니다.",
    "netsh_firewall_off":           "그대로 두면 방화벽이 꺼져 외부 공격·통신을 막지 못하게 되기 때문입니다.",
    # 흔적 삭제 / 지속성 / 의심 실행
    "wevtutil_clear_log":           "그대로 두면 이벤트 로그가 지워져 공격 흔적을 추적할 수 없게 되기 때문입니다.",
    "powershell_clear_eventlog":    "그대로 두면 이벤트 로그가 지워져 공격 흔적을 추적할 수 없게 되기 때문입니다.",
    "cipher_wipe_free_space":       "그대로 두면 빈 공간이 완전 삭제되어 지워진 파일을 복구할 수 없게 되기 때문입니다.",
    "run_key_persistence":          "그대로 두면 자동 실행에 등록되어 재부팅 후에도 악성 프로그램이 계속 살아나기 때문입니다.",
    "schtasks_persistence":         "그대로 두면 예약 작업으로 등록되어 주기적으로·재부팅 후 다시 실행되기 때문입니다.",
    "powershell_bypass_policy":     "그대로 두면 실행 정책을 우회해 차단됐어야 할 스크립트가 실행되기 때문입니다.",
    "powershell_obfuscated_exec":   "그대로 두면 백신 탐지를 피하려 숨겨둔 악성 명령이 실제로 실행되기 때문입니다.",
    "powershell_downloader":        "그대로 두면 외부에서 추가 악성코드를 내려받아 설치될 수 있기 때문입니다.",
    # 실제 암호화/파괴 정황
    "high_entropy_write":           "그대로 두면 파일이 무작위 데이터로 덮여 써져 원래 내용을 영영 잃게 되기 때문입니다.",
    "magic_bytes_lost":             "그대로 두면 파일 형식이 깨져 해당 파일을 더 이상 열 수 없게 되기 때문입니다.",
    "modify_burst":                 "그대로 두면 짧은 시간에 많은 파일이 한꺼번에 바뀌어 피해가 급격히 커지기 때문입니다.",
    "suspicious_extension":         "그대로 두면 파일들이 암호화 확장자(예: .encrypted)로 바뀌어 열 수 없게 되기 때문입니다.",
    "file_delete":                  "그대로 두면 원본 파일이 삭제되어(암호화본만 남아) 데이터를 잃게 되기 때문입니다.",
    "kernel_write_burst":           "그대로 두면 대량 파일 쓰기가 계속되어 다수의 파일이 빠르게 암호화·손상되기 때문입니다.",
    "kernel_rename_burst":          "그대로 두면 대량 이름 변경이 계속되어 다수의 파일이 암호화 표식으로 바뀌기 때문입니다.",
    "kernel_blocked_op":            "그대로 허용하면 파일이 손상·암호화될 수 있기 때문입니다.",
    "process_write_burst":          "그대로 두면 한 프로그램이 다량의 파일을 빠르게 기록해 대량 암호화로 이어질 수 있기 때문입니다.",
    # 미끼(canary)
    "canary_modified":              "건드릴 이유가 없는 미끼 파일까지 바뀐 것은 무차별 암호화 정황이라, 그대로 두면 전체 파일이 암호화되기 때문입니다.",
    "canary_deleted":               "건드릴 이유가 없는 미끼 파일이 삭제된 것은 무차별 파괴 정황이라, 그대로 두면 파일이 삭제·암호화되기 때문입니다.",
    # 프로세스 행위
    "child_fanout":                 "그대로 두면 다수의 자식 프로세스로 작업이 확산되어 피해가 커질 수 있기 때문입니다.",
    "suspicious_parent_child":      "정상적이지 않은 실행 체인(예: 문서·브라우저가 스크립트를 실행)은 공격 코드 실행 정황이기 때문입니다.",
    "tamper_blocked":               "그대로 두면 보안 에이전트가 조작·무력화되어 이후 위협을 막지 못하게 되기 때문입니다.",
}

# 종합 점수가 최고 수준(CRITICAL)에 도달했을 때, 같은 시간대에 활동한 PID 를
# 함께 차단하는 sweep 의 reason 코드.  responder._sweep_window 가 사용한다.
_SWEEP_REASON = "score_critical_sweep"


def _ko_detector(name: str) -> str:
    return DETECTOR_KO.get(name, name)


def _detector_from_reason(reason: Optional[str]) -> str:
    """``"minifilter/kernel_write_burst"`` -> ``"minifilter"`` (없으면 빈 문자열)."""
    parts = (reason or "").split("/", 1)
    return parts[0].strip() if parts and "/" in (reason or "") else ""


def _explain_reason(reason: Optional[str]) -> tuple:
    """차단 사유를 (무슨 일이 있었나, 왜 차단했나) 평문으로 풀어준다.

    SIGNAL_KO/SIGNAL_WHY 에 없는 신호나 sweep 같은 특수 사유도 제네릭
    문구 대신 구체적으로 설명한다.
    """
    raw = reason or ""
    signame = _signame_from_reason(raw)

    # 1) 종합 점수 폭증으로 일괄 차단된 경우 (svchost·unknown 등이 흔히 해당)
    if signame == _SWEEP_REASON or raw.startswith(_SWEEP_REASON):
        what = ("여러 위험 신호가 짧은 시간에 한꺼번에 쌓여 전체 위험도가 "
                "최고 수준에 도달했고, 같은 시간대에 활동한 이 프로세스를 함께 "
                "차단했습니다.")
        why = ("그대로 두면 동시에 진행되던 공격 활동에 이 프로세스도 가담해 "
               "피해를 키울 수 있기 때문입니다.")
        return what, why

    # 2) 알려진 신호
    what = SIGNAL_KO.get(signame)
    why = SIGNAL_WHY.get(signame)
    if what:
        # 부모 프로세스로 확대 차단된 경우 한 줄 덧붙임
        if "parent of pid" in raw:
            what += " (이 악성 명령을 실제로 지시한 부모 프로그램이라 함께 차단했습니다.)"
        if not why:
            why = "그대로 두면 위와 같은 위협 행위가 계속되어 피해가 커지기 때문입니다."
        return what, why

    # 3) 처음 보는 신호 — 제네릭 대신 탐지기/신호명으로 최대한 구체화
    det = _detector_from_reason(raw)
    det_ko = _ko_detector(det) if det else ""
    sig_label = signame or raw or "알 수 없는 신호"
    if det_ko:
        what = f"'{det_ko}' 가 위협 신호('{sig_label}')를 감지했습니다."
    else:
        what = f"위협 신호('{sig_label}')가 감지되었습니다."
    why = "그대로 두면 위협 행위가 계속되어 피해로 이어질 수 있기 때문입니다."
    return what, why


# 프로세스 이름을 못 가져온 경우의 표기들.  responder._lookup 이 실패하면
# (프로세스가 이미 종료/접근 거부) 빈 문자열이 오고, 파일명/레코드에서는
# "unknown" 으로도 남는다.  이들을 한데 모아 "알 수 없음"으로 통일한다.
_UNKNOWN_NAMES = frozenset({"", "unknown", "알 수 없음", "?", "<unknown>", "n/a"})


def _is_unknown_name(name: Optional[str]) -> bool:
    return (name or "").strip().lower() in _UNKNOWN_NAMES


def _unknown_name_note() -> str:
    """프로그램 이름이 'unknown'인 이유를 비전공자에게 설명한다."""
    return ("`unknown` 은 프로그램 **이름을 확인하지 못했다**는 뜻입니다. "
            "차단하는 순간 그 프로그램이 **이미 스스로 종료**했거나, 시스템이 "
            "이름 조회를 거부해서입니다. 랜섬웨어가 백업 삭제·암호화 같은 작업을 "
            "위해 잠깐 띄웠다가 곧바로 사라지는 **도우미 프로세스**(예: vssadmin, "
            "cmd, powershell)일 때 흔히 이렇게 나옵니다. 이름은 몰라도 아래 "
            "**프로세스 번호(PID)** 와 **실행 명령어** 로 추적할 수 있습니다.")


# 프로그램(프로세스) 이름 -> "이게 뭐 하는 프로그램인지" 한 줄 설명.  랜섬웨어가
# 흔히 악용하는 정상 Windows 도구(LOLBin)와 셸을 비전공자도 알 수 있게 풀이한다.
PROGRAM_KO = {
    "vssadmin.exe":  "Windows의 **볼륨 섀도(자동 백업본) 관리 도구**입니다. 정상적으로도 쓰이지만, 랜섬웨어가 복구를 막으려 백업을 지울 때 악용합니다.",
    "wmic.exe":      "Windows 관리 명령 도구(WMIC)입니다. 시스템 정보 조회·관리에 쓰이지만, 랜섬웨어가 백업 삭제 등 파괴 명령에 악용합니다.",
    "wbadmin.exe":   "Windows **백업 관리 도구**입니다. 랜섬웨어가 백업 카탈로그를 지워 복구를 막을 때 악용합니다.",
    "bcdedit.exe":   "Windows **부팅 설정 편집 도구**입니다. 랜섬웨어가 복구 환경을 끄거나 부팅을 망가뜨릴 때 악용합니다.",
    "manage-bde.exe":"BitLocker **디스크 암호화 관리 도구**입니다. 랜섬웨어가 디스크 보호를 해제할 때 악용할 수 있습니다.",
    "powershell.exe":"Windows **자동화 스크립트 실행기(PowerShell)**입니다. 강력해서 관리에 쓰이지만, 랜섬웨어가 악성 명령·다운로드·은폐 실행에 가장 많이 악용합니다.",
    "pwsh.exe":      "PowerShell(최신판) **스크립트 실행기**입니다. 악성 스크립트 실행에 악용될 수 있습니다.",
    "cmd.exe":       "Windows **명령 프롬프트(셸)**입니다. 다른 명령들을 실행하는 통로로, 랜섬웨어가 파괴 명령을 줄줄이 실행할 때 부모 셸로 자주 씁니다.",
    "wscript.exe":   "Windows **스크립트 실행기**(VBScript/JScript)입니다. 악성 스크립트 실행에 악용됩니다.",
    "cscript.exe":   "콘솔용 Windows **스크립트 실행기**입니다. 악성 스크립트 실행에 악용됩니다.",
    "mshta.exe":     "HTML 응용프로그램 실행기입니다. 랜섬웨어가 악성 코드를 숨겨 실행할 때 악용합니다.",
    "regsvr32.exe":  "DLL 등록 도구입니다. 보안 우회용으로 악성 코드를 실행하는 데 악용됩니다(LOLBin).",
    "rundll32.exe":  "DLL 함수 실행 도구입니다. 악성 코드를 정상 프로세스처럼 실행하는 데 악용됩니다(LOLBin).",
    "reg.exe":       "Windows **레지스트리 편집 도구**입니다. 랜섬웨어가 백신을 끄거나 자동 실행을 등록할 때 악용합니다.",
    "schtasks.exe":  "**예약 작업 등록 도구**입니다. 랜섬웨어가 재부팅 후에도 살아남도록(지속성) 악용합니다.",
    "wevtutil.exe":  "Windows **이벤트 로그 관리 도구**입니다. 랜섬웨어가 침입 흔적을 지울 때 악용합니다.",
    "fsutil.exe":    "파일시스템 관리 도구입니다. 랜섬웨어가 파일 변경 이력(USN)을 지워 추적을 방해할 때 악용합니다.",
    "cipher.exe":    "파일 암호화/완전삭제 도구입니다. 랜섬웨어가 빈 공간을 덮어써 복구를 막을 때 악용합니다.",
    "netsh.exe":     "Windows **네트워크 설정 도구**입니다. 랜섬웨어가 방화벽을 끌 때 악용합니다.",
    "bitsadmin.exe": "백그라운드 전송 도구입니다. 랜섬웨어가 추가 악성코드를 몰래 내려받을 때 악용합니다(LOLBin).",
    "certutil.exe":  "인증서 관리 도구입니다. 랜섬웨어가 파일 다운로드·디코딩에 악용합니다(LOLBin).",
    "svchost.exe":   "Windows **서비스 호스트**(정상 핵심 프로세스)입니다. 진짜는 보호되지만, 랜섬웨어가 이 이름으로 **위장**해 시스템 폴더 밖에서 실행되면 차단됩니다.",
    "explorer.exe":  "Windows **파일 탐색기**입니다. 정상 프로세스지만, 악성 스크립트를 띄운 부모로 지목되면 표시될 수 있습니다.",
    "rundll.exe":    "DLL 실행 도구입니다(구형). 악성 코드 실행에 악용될 수 있습니다.",
}


def _ko_program(name: Optional[str]) -> Optional[str]:
    """프로세스 이름에 대한 평이한 설명.  모르는 이름이면 None."""
    return PROGRAM_KO.get((name or "").strip().lower())


def _program_note(name: str) -> str:
    """'어떤 프로그램이었나요'에 붙일 한 줄 설명.

    알려진 도구면 그 설명을, 모르는 이름이면 '정체불명' 안내를 준다.
    """
    desc = _ko_program(name)
    if desc:
        return desc
    return ("이 시스템에 표준으로 들어있는 알려진 도구가 아닙니다. 직접 설치했거나 "
            "최근 내려받은 프로그램이 아니라면, 정상으로 위장한 악성 실행 파일일 수 "
            "있으니 아래 **실행 명령어**의 경로를 확인하세요.")


def _explain_cmdline(cmd: Optional[str]) -> str:
    """실행 명령어를 비전공자용으로 한 줄 풀이한다.

    cmdline 본문에서 랜섬웨어가 흔히 쓰는 키워드를 찾아 '무엇을 하려는
    명령인지' 평이하게 설명한다.  여러 개면 대표적인 것들을 모아 보여준다.
    """
    if not cmd or cmd == "(확인 불가)":
        return ("실행 명령어를 확인하지 못했습니다(프로그램이 이미 종료됨). "
                "위 프로그램 이름과 PID로 판단하세요.")
    low = cmd.lower()
    notes: List[str] = []
    # (키워드들, 설명) — 순서대로 검사, 중복 설명은 한 번만.
    table = [
        (("delete shadows", "shadowcopy delete", "shadowstorage", "win32_shadowcopy"),
         "자동 백업(볼륨 섀도)을 삭제하려는 명령입니다 — 복구 방해."),
        (("delete catalog", "wbadmin delete"),
         "Windows 백업 카탈로그를 삭제하려는 명령입니다 — 복구 방해."),
        (("recoveryenabled no", "bootstatuspolicy", "safeboot", "bcdedit"),
         "Windows 부팅·복구 설정을 망가뜨리려는 명령입니다."),
        (("disablerealtimemonitoring", "disableantispyware", "add-mppreference",
          "set-mppreference", "defender"),
         "백신(Windows Defender)을 끄거나 검사 예외를 추가하려는 명령입니다."),
        (("clear-eventlog", "wevtutil cl", "wevtutil clear"),
         "Windows 이벤트 로그를 지워 흔적을 없애려는 명령입니다."),
        (("usn deletejournal", "fsutil usn"),
         "파일 변경 이력(USN)을 삭제해 추적을 방해하려는 명령입니다."),
        (("cipher /w", "cipher.exe /w"),
         "빈 디스크 공간을 덮어써 삭제된 파일 복구를 막으려는 명령입니다."),
        (("firewall set", "advfirewall", "netsh "),
         "Windows 방화벽 설정을 바꾸려는(주로 끄려는) 명령입니다."),
        (("manage-bde", "disable-bitlocker"),
         "BitLocker 디스크 암호화를 해제하려는 명령입니다."),
        (("schtasks", "/create"),
         "예약 작업을 등록해 재부팅 후에도 다시 실행되게 하려는(지속성) 명령입니다."),
        (("currentversion\\run", "\\run "),
         "자동 실행 목록에 등록해 재부팅 후에도 살아남으려는(지속성) 명령입니다."),
        (("-enc ", "-encodedcommand", "frombase64string", "-nop", "-noprofile",
          "-w hidden", "-windowstyle hidden", "iex", "invoke-expression"),
         "정체를 숨긴(난독화된) PowerShell 명령을 실행하려는 시도입니다."),
        (("downloadstring", "downloadfile", "invoke-webrequest", "bitsadmin",
          "certutil -urlcache", "start-bitstransfer"),
         "외부에서 추가 파일(주로 악성코드)을 내려받으려는 명령입니다."),
    ]
    seen: set = set()
    for keys, desc in table:
        if any(k in low for k in keys) and desc not in seen:
            seen.add(desc)
            notes.append(desc)
    if not notes:
        return ("이 프로그램이 실행될 때 사용된 명령(인자)입니다. 특별히 알려진 "
                "공격 키워드는 없지만, 차단 사유와 함께 참고하세요.")
    return " ".join(f"• {n}" for n in notes)


def _campaign_behaviors(camp) -> List[dict]:
    """공격에서 관측된 *모든* 고유 위협 행위를 시간순으로 모은다.

    캡처해둔 신호(camp.signals) + 각 인시던트의 차단 사유(reason)를 합쳐,
    같은 종류는 한 번만, 처음 관측된 시각 순서로 정렬한다.  통합 보고서가
    "첫 사건 하나"가 아니라 "그동안의 모든 행위"를 보여주게 하기 위함.
    """
    # PID -> 처리된 프로세스 이름 (각 행위를 "누가 했는지" 표기하기 위함)
    pid_to_name = {m["pid"]: (m["name"] or "unknown") for m in camp.members}

    def _pid_of(sig) -> Optional[int]:
        meta = sig.metadata or {}
        for k in ("pid", "ProcessId", "child_pid", "process_id"):
            v = meta.get(k)
            if isinstance(v, int) and v > 0:
                return v
        return None

    # 행위로 인정할 신호를 한정한다.  통합 보고서가 "차단과 무관한 부수
    # 신호"(예: svchost 가 정상적으로 Run 키를 쓰며 낸 run_key_persistence)까지
    # 행위로 부풀리지 않게 하기 위함 — 개별 보고서의 차단 사유와 어긋나던 원인.
    #   포함 = (1) 실제 차단 사유로 쓰인 신호  ∪  (2) 실제 암호화/파괴 신호
    reason_signals = set()
    for m in camp.members:
        sn = _signame_from_reason(m.get("reason"))
        if sn and sn != _SWEEP_REASON:
            reason_signals.add(sn)

    def _is_behavior(name: str) -> bool:
        return name in reason_signals or name in ENCRYPTION_SIGNAL_NAMES

    first_ts: dict = {}
    # 행위 종류별로 "그 행위를 한 모든 프로세스"를 모은다 (처음 관측 순서 보존).
    procs: dict = {}
    # 행위 종류별 {프로세스: 처음 발생 시각} — 시간순 목록을 프로세스 단위로
    # 펼치기 위함 (같은 종류라도 프로세스가 다르면 각각 한 줄).
    proc_first_ts: dict = {}

    def _consider(name: str, ts: float, proc: Optional[str]) -> None:
        if name not in first_ts or ts < first_ts[name]:
            first_ts[name] = ts
        proc_label = "unknown" if _is_unknown_name(proc) else proc
        bucket = procs.setdefault(name, [])
        if proc_label not in bucket:
            bucket.append(proc_label)
        pf = proc_first_ts.setdefault(name, {})
        if proc_label not in pf or ts < pf[proc_label]:
            pf[proc_label] = ts

    def _note_ts(name: str, ts: float) -> None:
        if name not in first_ts or ts < first_ts[name]:
            first_ts[name] = ts
        procs.setdefault(name, [])

    for s in camp.signals:
        if not _is_behavior(s.name):
            continue
        pid = _pid_of(s)
        proc = pid_to_name.get(pid)
        # 신호의 pid 가 '실제로 차단된 프로세스'가 아니면(예: vssadmin/wmic 을
        # 실행한 부모 셸 cmd.exe — 명령줄에만 스쳐갈 뿐 차단 대상이 아님)
        # '누가 했나'에 넣지 않는다.  행위 시각만 기록하고, 실제 수행
        # 프로세스는 차단 기록(members)에서 채운다.
        if _is_unknown_name(proc):
            _note_ts(s.name, s.timestamp)
            continue
        _consider(s.name, s.timestamp, proc)
    for m in camp.members:
        sn = _signame_from_reason(m.get("reason"))
        if not sn or sn == _SWEEP_REASON:
            continue
        _consider(sn, m["ts"], m["name"] or "unknown")

    out: List[dict] = []
    for name in sorted(first_ts, key=lambda n: first_ts[n]):
        bucket = procs.get(name) or ["unknown"]
        # 실제 이름들을 앞에, 'unknown'은 맨 뒤로 정렬(가독성).
        named = [p for p in bucket if not _is_unknown_name(p)]
        proc_list = named + (["unknown"] if len(named) != len(bucket) else [])
        if not proc_list:
            proc_list = ["unknown"]
        # 시간순 목록용: (시각, 프로세스) 발생을 시간순으로.  실제 차단된
        # 프로세스가 하나도 없으면(부모 셸만 신호를 낸 경우) unknown 1건으로.
        events = sorted((ts, p) for p, ts in proc_first_ts.get(name, {}).items())
        if not events:
            events = [(first_ts[name], "unknown")]
        out.append({
            "ts": first_ts[name],
            "name": name,
            "what": SIGNAL_KO.get(name) or f"위협 신호({name})가 감지되었습니다.",
            "why": SIGNAL_WHY.get(name),
            "procs": proc_list,
            "events": events,
        })
    return out


def _short_action(what: str) -> str:
    """SIGNAL_KO 설명에서 앞쪽 '행위' 부분만 짧게 뽑는다.

    예) "WMIC로 백업 섀도 복사본 삭제 시도 — 백업 무력화입니다." -> "WMIC로 …삭제 시도"
        "Windows 백업 카탈로그 삭제 시도입니다." -> "Windows 백업 카탈로그 삭제 시도"
    """
    head = what.split(" — ")[0].strip().rstrip(".")
    if head.endswith("입니다"):
        head = head[:-3].rstrip()
    return head


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
                 "차단 직전 짧은 순간의 일부 작업은 누락될 수 있습니다.")
    return lines


# 이미 압축/이미지인 확장자는 원래부터 무작위처럼 보이므로 '암호화 정황'
# 엔트로피 판정에서 제외한다(정상 파일 오판 방지).
_HIGH_ENTROPY_SKIP_EXTS = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".jpg", ".jpeg", ".png",
    ".gif", ".mp4", ".mov", ".mkv", ".avi", ".mp3", ".pdf", ".docx",
    ".xlsx", ".pptx",
}

# 커널 신호의 디바이스 경로(\Device\HarddiskVolumeN\..) -> 드라이브 경로.
_DEVICE_PATH_RE = re.compile(r"\\Device\\HarddiskVolume\d+\\(.*)", re.IGNORECASE)


def _norm_disk_path(p: str) -> str:
    m = _DEVICE_PATH_RE.match(p or "")
    if m:
        # 볼륨 번호->드라이브 문자 매핑은 알 수 없어 C: 로 가정(best-effort).
        return "C:\\" + m.group(1)
    return p


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter as _C
    counts = _C(data)
    n = len(data)
    import math as _m
    return -sum((c / n) * _m.log2(c / n) for c in counts.values())


def verify_damage_on_disk(d: dict) -> dict:
    """summarize_damage 결과의 신호 경로들을 *실제 디스크*에서 확인한다.

    폴더 전체를 훑지 않고, 랜섬웨어가 실제로 건드린 경로만 본다(빠르고 정확).
    각 파일이 지금 사라졌는지/내용이 암호화됐는지 실측한다.
    """
    # 검사 대상: 변조/암호화·이름변경으로 '현재 존재할 법한' 경로 + 삭제 경로.
    touched = {_norm_disk_path(p) for p in (d["encrypted"] | d["renamed"])}
    deleted_paths = {_norm_disk_path(p) for p in d["deleted"]}

    gone: List[str] = []
    encrypted_now: List[str] = []
    present: List[str] = []

    for p in sorted(touched):
        try:
            fp = Path(p)
            if not fp.exists():
                gone.append(p)
                continue
            present.append(p)
            if fp.suffix.lower() in _HIGH_ENTROPY_SKIP_EXTS:
                continue
            try:
                head = fp.read_bytes()[:4096]
            except OSError:
                continue
            if _shannon_entropy(head) > 7.5:
                encrypted_now.append(p)
        except OSError:
            continue

    # 신호가 '삭제'로 본 경로 중 실제로 사라진 것 (위 touched 의 gone 과 중복 제거).
    gone_set = set(gone)
    deleted_confirmed = []
    for p in sorted(deleted_paths):
        if p in gone_set:
            continue
        try:
            if not Path(p).exists():
                deleted_confirmed.append(p)
                gone_set.add(p)
        except OSError:
            pass

    # 전체 검사 대상(중복 제거).
    all_checked = touched | deleted_paths
    return {
        "checked": len(all_checked),
        "present": present,
        "gone": gone,
        "encrypted_now": encrypted_now,
        "deleted_confirmed": deleted_confirmed,
    }


def _disk_verify_lines(v: dict) -> List[str]:
    lines: List[str] = []
    if v["checked"] == 0:
        lines.append("- 디스크에서 확인할 파일 경로가 신호에 없습니다 "
                     "(경로 없는 신호만 있었던 경우).")
        return lines
    gone_total = len(set(v["gone"]) | set(v["deleted_confirmed"]))
    lines.append(f"- **확인한 파일 경로:** {v['checked']}개 (랜섬웨어가 실제로 "
                 "건드린 경로만 검사 — 폴더 전체 스캔 아님)")
    lines.append(f"- **현재 사라진(삭제된) 파일:** {gone_total}개")
    lines.append(f"- **현재 내용이 암호화로 확인된 파일:** {len(v['encrypted_now'])}개")
    lines.append(f"- **아직 멀쩡히 남아있는 파일:** "
                 f"{max(0, len(v['present']) - len(v['encrypted_now']))}개")
    gone_all = list(dict.fromkeys(v["gone"] + v["deleted_confirmed"]))  # 순서보존 중복제거
    if v["encrypted_now"] or gone_all:
        lines.append("- **실측 예시:**")
        for p in v["encrypted_now"][:5]:
            lines.append(f"  - 🔒 `{p}` (내용 암호화 확인)")
        for p in gone_all[:3]:
            lines.append(f"  - 🗑 `{p}` (사라짐)")
    lines.append("")
    lines.append("> 차단 직후 **디스크를 직접 확인한 결과**입니다. 위 '추정 피해 "
                 "범위'(신호 기준)와 달리, 실제로 파일이 어떻게 됐는지 보여줍니다.")
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
    """시간 윈도우로 묶인 하나의 공격 사건 (여러 PID를 한 건으로 통합).

    핵심: 신호는 *인시던트가 발생한 시점*에 캡처해 ``signals`` 에 쌓아둔다.
    점수 윈도우(120초)가 지나면 엔진에서는 신호가 사라지므로, 최종 확정은
    엔진이 아니라 이 캡처본을 근거로 만들어야 한다.
    """
    start_ts: float
    last_ts: float
    filename: str
    pids: set
    members: List[dict]   # {ts, pid, name, reason, terminated, quarantined, incident_file}
    signals: List = field(default_factory=list)   # 캡처한 Signal 객체들
    sig_keys: set = field(default_factory=set)     # 신호 중복 제거용 키
    finalized: bool = False                        # 사건 종료 후 최종 확정됨
    finalized_ts: float = 0.0                      # 최종 확정된 시각(목록 정렬용)


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
        # 사건이 조용해지면(점수 초기화) 통합 보고서를 최종 확정하는 백그라운드
        # 스레드.  데몬이라 메인이 끝나면 함께 종료된다.  close() 로 명시적
        # 종료 + 잔여 campaign 강제 확정도 가능.
        self._stop = threading.Event()
        self._finalizer = threading.Thread(
            target=self._finalizer_loop, name="campaign-finalizer", daemon=True)
        self._finalizer.start()

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
            # 통합 항목은 (1) 2개 이상 프로세스를 묶었고 (2) 사건이 종료되어
            # 최종 확정된 것만 노출한다.  진행 중(잠정) 통합 보고서는 디스크에는
            # 남지만(크래시 대비) 목록에는 띄우지 않는다 — 사용자가 "최종본만
            # 보이게" 요청.  개별 인시던트는 실시간으로 그대로 보인다.
            for c in self._campaigns:
                if c.finalized and len(c.pids) >= 2:
                    items.append(self._campaign_record(c))
        items.sort(key=lambda d: d.get("timestamp", 0), reverse=True)
        return items[:limit]

    def _campaign_record(self, c: _Campaign) -> dict:
        lead = c.members[0] if c.members else {}
        lead_name = lead.get("name") or "알 수 없음"
        n = len(c.pids)
        terminated = any(m.get("terminated") for m in c.members)
        quarantined = any(m.get("quarantined") for m in c.members)
        # 목록 정렬용 시각: 확정된 순간(finalized_ts)을 쓴다.  사건 종료 후
        # 보고서가 만들어지므로, 그 시점 기준으로 목록 맨 위(가장 최근)에
        # 자연스럽게 나타나게 한다 — 과거 인시던트 사이에 끼어들지 않는다.
        return {
            "timestamp": c.finalized_ts or c.last_ts,
            "pid": lead.get("pid", 0),
            "process_name": f"🛡 통합 사건 — {lead_name} 외 {n - 1}개 프로세스",
            "reason": f"campaign/{n}_processes",
            "terminated": terminated,
            "quarantined": quarantined,
            "filename": c.filename,
            "path": str(self.reports_dir / c.filename),
            "kind": "campaign",
            "finalized": c.finalized,
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

        name_unknown = _is_unknown_name(action.process_name)
        # 이름을 못 가져온 경우엔 'unknown' 표기를 그대로 유지하고(설명만 덧붙임),
        # 실제 이름이 있으면 그 이름을 쓴다.
        proc_name = "unknown" if name_unknown else action.process_name
        cmd = action.cmdline or "(확인 불가)"

        # 평이한 요약 (무슨 일 / 왜 차단)
        what, why = _explain_reason(action.reason)
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
        lines.append(f"- **왜 차단했나요?** {why}")
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
        if name_unknown:
            lines.append(f"  - ℹ️ {_unknown_name_note()}")
        else:
            lines.append(f"  - ℹ️ {_program_note(proc_name)}")
        lines.append(f"- **프로세스 번호(PID):** `{action.pid}`")
        det = _detector_from_reason(action.reason)
        det_label = _ko_detector(det) if det else "종합 위험도 판정"
        lines.append(f"- **탐지한 기능:** {det_label}")
        lines.append("- **실행 명령어:**")
        lines.append("")
        lines.append("  ```")
        lines.append(f"  {cmd}")
        lines.append("  ```")
        lines.append(f"  - ℹ️ **명령어 풀이:** {_explain_cmdline(action.cmdline)}")
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
        """이 인시던트를 진행 중 공격에 합쳐 *메모리에만* 누적한다.

        파일은 여기서 쓰지 않는다 — 사건이 조용해져 점수가 초기화되면(또는
        에이전트 종료 시) 백그라운드 finalizer 가 통합 보고서를 *한 번만*
        최종본으로 생성한다.  진행 중에 잠정 파일을 만들지 않으므로, 개별
        인시던트 보고서 흐름 중간에 통합 보고서가 끼어드는 일이 없다.
        """
        ts = action.timestamp
        member = {
            "ts": ts,
            "pid": action.pid,
            "name": action.process_name or "unknown",
            "reason": action.reason or "",
            "terminated": bool(action.terminated),
            "quarantined": bool(action.quarantined),
            "incident_file": incident_path.name,
        }
        # 신호는 *지금* 캡처한다.  나중(점수 초기화 후)엔 엔진에서 사라진다.
        recent = self.engine.recent_signals(limit=500)
        with self._lock:
            camp = None
            if self._campaigns:
                last = self._campaigns[-1]
                # 아직 확정되지 않았고 시간 윈도우 안이면 같은 공격으로 합친다.
                if not last.finalized and ts - last.last_ts <= _CAMPAIGN_GAP_SECS:
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
            # 이 인시던트와 같은 PID 의 신호를 캡처해 누적(중복 제거).
            for s in recent:
                if self._signal_pid(s) != action.pid:
                    continue
                key = (round(s.timestamp, 3), s.detector, s.name,
                       action.pid, tuple(sorted(_sig_paths(s))))
                if key in camp.sig_keys:
                    continue
                camp.sig_keys.add(key)
                camp.signals.append(s)

    @staticmethod
    def _snapshot_campaign(c: _Campaign) -> _Campaign:
        """락을 들고 있는 동안 안전하게 복사 (디스크 I/O 는 락 밖에서)."""
        return _Campaign(
            start_ts=c.start_ts, last_ts=c.last_ts, filename=c.filename,
            pids=set(c.pids), members=list(c.members),
            signals=list(c.signals), sig_keys=set(c.sig_keys),
            finalized=c.finalized, finalized_ts=c.finalized_ts,
        )

    # ------------------------------------------------- campaign finalization

    def _finalizer_loop(self) -> None:
        """주기적으로 깨어나 조용해진(점수 초기화된) 공격을 최종 확정한다."""
        while not self._stop.wait(_CAMPAIGN_FINALIZE_POLL_SECS):
            try:
                self._finalize_due()
            except Exception as e:  # 확정 실패가 스레드를 죽이면 안 됨
                print(f"[reporter] campaign finalize error: {e}")

    def _finalize_due(self, force: bool = False) -> None:
        """마지막 인시던트로부터 윈도우가 지난 공격을 최종본으로 확정한다.

        ``force=True`` 면 종료 시점에 미확정 공격을 모두 확정한다.
        """
        now = time.time()
        pending: List[_Campaign] = []
        with self._lock:
            for c in self._campaigns:
                if c.finalized:
                    continue
                if force or (now - c.last_ts) > _CAMPAIGN_GAP_SECS:
                    c.finalized = True          # 먼저 선점(중복 확정 방지)
                    c.finalized_ts = now        # 목록에서 "확정된 순간"에 노출
                    pending.append(self._snapshot_campaign(c))
        for snap in pending:
            try:
                content = self._build_campaign_markdown(snap)
                (self.reports_dir / snap.filename).write_text(
                    content, encoding="utf-8")
                n = len(snap.pids)
                if n >= 2:
                    print(f"[reporter] campaign finalized: {snap.filename} "
                          f"({n} processes)")
            except OSError as e:
                print(f"[reporter] campaign finalize write failed: {e}")

    def close(self) -> None:
        """종료 시 호출: finalizer 를 멈추고 잔여 공격을 모두 확정한다."""
        self._stop.set()
        try:
            self._finalize_due(force=True)
        except Exception as e:
            print(f"[reporter] campaign final flush error: {e}")

    def _build_campaign_markdown(self, camp: _Campaign) -> str:
        start_local = time.strftime("%Y-%m-%d %H:%M:%S %Z",
                                    time.localtime(camp.start_ts))
        last_local = time.strftime("%H:%M:%S", time.localtime(camp.last_ts))

        # 인시던트 시점에 캡처해둔 신호로 통합 피해를 집계한다.  엔진을 다시
        # 조회하지 않는 이유: 최종 확정 시점엔 점수 윈도우가 지나 신호가 이미
        # 사라졌기 때문(이게 "초기화 후 보고"의 핵심).
        camp_signals = sorted(camp.signals, key=lambda s: s.timestamp)
        damage = summarize_damage(camp_signals)

        n_proc = len(camp.pids)
        killed = sum(1 for m in camp.members if m["terminated"])
        quar = sum(1 for m in camp.members if m["quarantined"])
        reasons = [m["reason"] for m in camp.members if m["reason"]]
        # 그동안 관측된 *모든* 고유 위협 행위 (시간순).  통합 보고서의 핵심.
        behaviors = _campaign_behaviors(camp)

        # 이 보고서는 사건 종료(점수 초기화) 후 한 번만 생성되는 최종본이다.
        status = ("✅ **최종 확정** — 사건이 종료되어(약 "
                  f"{_CAMPAIGN_GAP_SECS:.0f}초간 추가 활동 없음, 위험 점수 "
                  "초기화) 그동안의 모든 사건을 합산했습니다.")

        L: List[str] = []
        L.append(f"# 통합 위협 보고서 — 공격 사건 ({n_proc}개 프로세스)")
        L.append("")
        L.append(f"> RansomGuard 자동 탐지·대응 · {start_local} ~ {last_local}")
        L.append("")
        L.append(f"> {status}")
        L.append("")

        L.append("## 한눈에 보기")
        L.append("")
        if behaviors:
            # 행위마다 줄을 바꿔 "무엇을 시도 — 왜 위험" 형태로 보여준다.
            _SUMMARY_MAX = 6
            L.append(f"- **무슨 공격이었나요?** 이 공격에서 "
                     f"**{len(behaviors)}가지** 위협 행위가 관측되었습니다:")
            for b in behaviors[:_SUMMARY_MAX]:
                # 형식: "무엇을 했나: 어떤 프로세스들이 — 왜 위험한가"
                procs_txt = ", ".join(f"`{p}`" for p in b["procs"])
                line = f"  - **{_short_action(b['what'])}**: {procs_txt}"
                if b["why"]:
                    line += f" — **왜 위험하냐면,** {b['why']}"
                L.append(line)
            if len(behaviors) > _SUMMARY_MAX:
                L.append(f"  - …그 외 {len(behaviors) - _SUMMARY_MAX}가지 행위가 "
                         "더 있습니다.")
            L.append("  - _시간순 전체 내역은 아래 **'관측된 위협 행위'** 를 "
                     "참고하세요._")
        else:
            # 행위를 특정할 신호가 없으면(예: 종합 점수 sweep 단독) 단일 사유로 설명.
            what, _why = _explain_reason(reasons[0] if reasons else "")
            L.append(f"- **무슨 공격이었나요?** {what}")
        L.append("- **관련 프로세스:** "
                 f"{n_proc}개 (PID {', '.join(str(p) for p in sorted(camp.pids))})")
        L.append(f"- **무엇을 했나요?** 강제 종료 {killed}개 · 격리 {quar}개")
        L.append(f"- **추정 피해 규모:** {_damage_headline(damage)}")
        if damage["canary"]:
            L.append("- **미끼(canary) 파일 침해:** 예 — 무차별 암호화 정황입니다.")
        L.append("")

        if behaviors:
            L.append("## 관측된 위협 행위 (시간순)")
            L.append("")
            L.append("이 공격이 진행되는 동안 탐지된 행위를 "
                     "**프로세스별로 시간순** 나열했습니다.")
            L.append("")
            # 각 행위를 (프로세스, 시각) 단위로 펼쳐 전체를 시간순 정렬한다.
            timeline = []
            for b in behaviors:
                for ts, proc in b["events"]:
                    timeline.append((ts, proc, b["what"]))
            timeline.sort(key=lambda x: x[0])
            for ts, proc, what in timeline:
                t = time.strftime("%H:%M:%S", time.localtime(ts))
                L.append(f"- `{t}` `{proc}` — {what}")
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

        L.append("## 통합 피해 범위 (탐지 신호 기준 추정)")
        L.append("")
        L.extend(_damage_lines(damage))
        L.append("")

        # 차단 직후 디스크 실측: 신호에 기록된 경로만 확인(폴더 전체 스캔 아님).
        disk = verify_damage_on_disk(damage)
        if disk["checked"]:
            L.append("## 실제 피해 검증 (차단 후 디스크 확인)")
            L.append("")
            L.extend(_disk_verify_lines(disk))
            L.append("")

        if camp_signals:
            L.append("## 통합 탐지 타임라인")
            L.append("")
            L.extend(self._signal_table(camp_signals[-60:]))
            L.append("")

        L.append("---")
        L.append("")
        L.append(f"> 같은 공격으로 묶인 프로세스들을 하나로 합친 통합 요약입니다 "
                 f"(마지막 활동 후 {_CAMPAIGN_GAP_SECS:.0f}초간 추가 사건이 없으면 "
                 "최종 확정). 프로세스별 상세·원본 JSON 은 위 표의 개별 보고서를 "
                 "참고하세요.")
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
