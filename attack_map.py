"""
MITRE ATT&CK Mapping
--------------------
탐지 신호(Signal.name)를 MITRE ATT&CK 기법(technique)에 연결한다.

왜 필요한가 (보고서 5.x / SOC 운영 관점):
  RansomGuard 의 신호 이름은 내부 구현 용어다("vssadmin_delete_shadows" 등).
  보안 운영자/침해대응(IR) 담당자는 **표준 분류체계**(ATT&CK)로 위협을 읽고
  티켓을 끊고 룰을 매핑한다.  각 신호에 ATT&CK 기법 ID 를 달아주면

    - 대시보드/보고서가 "T1490 Inhibit System Recovery" 같은 표준 명칭을 보여주고
    - 외부 SIEM/EDR 룰, 위협 인텔, 플레이북과 곧바로 연결되며
    - 비전문가에게도 "복구 방해 / 방어 무력화 / 데이터 암호화" 같은 전술(tactic)
      단위로 공격 단계를 한눈에 보여줄 수 있다.

이 모듈은 순수 데이터 + 조회 함수다 (외부 의존성 없음).  탐지 로직을 바꾸지
않으며, 표시/보고 계층에서만 사용한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Technique:
    """하나의 ATT&CK 기법 (또는 하위 기법)."""
    tid: str            # 예: "T1486"
    name: str           # 예: "Data Encrypted for Impact"
    tactic: str         # 예: "Impact"
    tactic_ko: str      # 예: "임팩트(피해)"
    url: str            # ATT&CK 참조 URL

    def to_dict(self) -> dict:
        return {
            "id": self.tid,
            "name": self.name,
            "tactic": self.tactic,
            "tactic_ko": self.tactic_ko,
            "url": self.url,
        }


def _t(tid: str, name: str, tactic: str, tactic_ko: str) -> Technique:
    # 하위 기법(T1562.001)은 URL 경로가 T1562/001 형태다.
    path = tid.replace(".", "/")
    return Technique(tid, name, tactic, tactic_ko,
                     f"https://attack.mitre.org/techniques/{path}/")


# 자주 쓰는 기법 정의 (랜섬웨어 킬체인 중심)
_DATA_ENCRYPTED   = _t("T1486", "Data Encrypted for Impact", "Impact", "임팩트(피해)")
_INHIBIT_RECOVERY = _t("T1490", "Inhibit System Recovery", "Impact", "임팩트(피해)")
_SERVICE_STOP     = _t("T1489", "Service Stop", "Impact", "임팩트(피해)")
_DATA_DESTRUCTION = _t("T1485", "Data Destruction", "Impact", "임팩트(피해)")
_IMPAIR_DEFENSES  = _t("T1562.001", "Impair Defenses: Disable or Modify Tools",
                       "Defense Evasion", "방어 회피")
_DISABLE_FW       = _t("T1562.004", "Impair Defenses: Disable or Modify System Firewall",
                       "Defense Evasion", "방어 회피")
_INDICATOR_REMOVAL = _t("T1070.001", "Indicator Removal: Clear Windows Event Logs",
                        "Defense Evasion", "방어 회피")
_FILE_DELETION    = _t("T1070.004", "Indicator Removal: File Deletion",
                       "Defense Evasion", "방어 회피")
_DEOBFUSCATE      = _t("T1140", "Deobfuscate/Decode Files or Information",
                       "Defense Evasion", "방어 회피")
_SCHED_TASK       = _t("T1053.005", "Scheduled Task/Job: Scheduled Task",
                       "Persistence", "지속성")
_RUN_KEYS         = _t("T1547.001",
                       "Boot or Logon Autostart Execution: Registry Run Keys",
                       "Persistence", "지속성")
_POWERSHELL       = _t("T1059.001", "Command and Scripting Interpreter: PowerShell",
                       "Execution", "실행")
_CMD_SHELL        = _t("T1059.003", "Command and Scripting Interpreter: Windows Command Shell",
                       "Execution", "실행")
_INGRESS_TOOL     = _t("T1105", "Ingress Tool Transfer", "Command and Control", "명령·제어")
_MASQUERADING     = _t("T1036.005", "Masquerading: Match Legitimate Name or Location",
                       "Defense Evasion", "방어 회피")
_PROC_INJECTION   = _t("T1055", "Process Injection", "Defense Evasion", "방어 회피")
_PROXY_EXEC       = _t("T1218", "System Binary Proxy Execution",
                       "Defense Evasion", "방어 회피")
_BITS_JOBS        = _t("T1197", "BITS Jobs", "Defense Evasion", "방어 회피")
_CREATE_SERVICE   = _t("T1543.003", "Create or Modify System Process: Windows Service",
                       "Persistence", "지속성")
_WMI              = _t("T1047", "Windows Management Instrumentation", "Execution", "실행")
_ARCHIVE_UTIL     = _t("T1560.001", "Archive Collected Data: Archive via Utility",
                       "Collection", "수집")
_EXFIL_CLOUD      = _t("T1567.002", "Exfiltration Over Web Service: Exfiltration to "
                       "Cloud Storage", "Exfiltration", "유출")


# 신호 이름 -> ATT&CK 기법.  탐지기에서 emit 하는 Signal.name 과 1:1 또는 1:N.
# 새 신호를 추가하면 여기에도 한 줄 더하면 된다(없으면 조회 시 None).
_SIGNAL_TECHNIQUES: Dict[str, List[Technique]] = {
    # --- 실제 암호화/파괴 (Impact) ---
    "high_entropy_write":   [_DATA_ENCRYPTED],
    "magic_bytes_lost":     [_DATA_ENCRYPTED],
    "modify_burst":         [_DATA_ENCRYPTED],
    "suspicious_extension": [_DATA_ENCRYPTED],
    "kernel_write_burst":   [_DATA_ENCRYPTED],
    "kernel_rename_burst":  [_DATA_ENCRYPTED],
    "kernel_blocked_op":    [_DATA_ENCRYPTED],
    "process_write_burst":  [_DATA_ENCRYPTED],
    "canary_modified":      [_DATA_ENCRYPTED],
    "canary_deleted":       [_DATA_ENCRYPTED, _DATA_DESTRUCTION],
    "file_delete":          [_FILE_DELETION],
    "ransom_note_dropped":  [_DATA_ENCRYPTED],
    "ransom_note_spread":   [_DATA_ENCRYPTED],

    # --- 복구 무력화 (Inhibit System Recovery) ---
    "vssadmin_delete_shadows":      [_INHIBIT_RECOVERY],
    "wmic_shadowcopy_delete":       [_INHIBIT_RECOVERY],
    "powershell_remove_shadowcopy": [_INHIBIT_RECOVERY, _POWERSHELL],
    "wbadmin_delete_catalog":       [_INHIBIT_RECOVERY],
    "bcdedit_recovery_disabled":    [_INHIBIT_RECOVERY],
    "bcdedit_ignore_failures":      [_INHIBIT_RECOVERY],
    "bcdedit_safeboot":             [_INHIBIT_RECOVERY],
    "bitlocker_disable":            [_INHIBIT_RECOVERY],
    "vssadmin_resize_shadowstorage": [_INHIBIT_RECOVERY],

    # --- 내장 도구를 암호화 엔진으로 악용 (living-off-the-land, Impact) ---
    "cipher_efs_encrypt":      [_DATA_ENCRYPTED],
    "bitlocker_abuse_enable":  [_DATA_ENCRYPTED, _INHIBIT_RECOVERY],

    # --- LOLBin 프록시 실행 / 스테이징 (Defense Evasion / C2) ---
    "certutil_download":        [_PROXY_EXEC, _INGRESS_TOOL],
    "certutil_decode_payload":  [_PROXY_EXEC, _DEOBFUSCATE],
    "bitsadmin_transfer":       [_BITS_JOBS, _INGRESS_TOOL],
    "esentutl_raw_copy":        [_PROXY_EXEC],
    "wmic_process_call_create": [_WMI],
    "kernel_service_create":    [_CREATE_SERVICE],

    # --- 이중 갈취: 데이터 스테이징 / 유출 ---
    "archive_password_staging": [_ARCHIVE_UTIL],
    "rclone_exfil":             [_EXFIL_CLOUD],

    # --- 정상 프로세스 내부에서의 암호화 = 인젝션/위장 증거 ---
    "trusted_process_encrypting": [_PROC_INJECTION, _DATA_ENCRYPTED],

    # --- 방어 무력화 (Defense Evasion) ---
    "defender_disable_realtime":     [_IMPAIR_DEFENSES, _SERVICE_STOP],
    "defender_add_exclusion":        [_IMPAIR_DEFENSES],
    "defender_disable_via_registry": [_IMPAIR_DEFENSES],
    "defender_self_disable":         [_IMPAIR_DEFENSES],
    "smartscreen_disable":           [_IMPAIR_DEFENSES],
    "netsh_firewall_off":            [_DISABLE_FW],

    # --- 흔적 삭제 (Defense Evasion) ---
    "wevtutil_clear_log":        [_INDICATOR_REMOVAL],
    "powershell_clear_eventlog": [_INDICATOR_REMOVAL, _POWERSHELL],
    "fsutil_usn_delete":         [_INDICATOR_REMOVAL],
    "cipher_wipe_free_space":    [_FILE_DELETION],

    # --- 지속성 (Persistence) ---
    "schtasks_persistence": [_SCHED_TASK],
    "run_key_persistence":  [_RUN_KEYS],

    # --- 실행 / 스테이징 (Execution / C2) ---
    "powershell_obfuscated_exec": [_POWERSHELL, _DEOBFUSCATE],
    "powershell_downloader":      [_POWERSHELL, _INGRESS_TOOL],
    "powershell_bypass_policy":   [_POWERSHELL],
    "suspicious_parent_child":    [_CMD_SHELL],
    "child_fanout":               [_CMD_SHELL],

    # --- 위장 (Defense Evasion) ---
    "process_masquerade": [_MASQUERADING],
    "tamper_blocked":     [_IMPAIR_DEFENSES],
}


def techniques_for(signal_name: Optional[str]) -> List[Technique]:
    """신호 이름에 매핑된 ATT&CK 기법 목록 (없으면 빈 리스트)."""
    if not signal_name:
        return []
    return list(_SIGNAL_TECHNIQUES.get(signal_name, ()))


def technique_dicts_for(signal_name: Optional[str]) -> List[dict]:
    """대시보드/보고서용 직렬화 형태."""
    return [t.to_dict() for t in techniques_for(signal_name)]


def primary_technique(signal_name: Optional[str]) -> Optional[Technique]:
    """대표 기법 하나 (첫 번째).  뱃지 한 개만 보여줄 때 사용."""
    techs = techniques_for(signal_name)
    return techs[0] if techs else None


def annotate_signal_dict(sig: dict) -> dict:
    """``Signal.to_dict()`` 결과에 ``attack`` 키(기법 목록)를 덧붙여 반환한다.

    원본을 수정하지 않고 얕은 복사본을 돌려준다 — 표시 계층 전용.
    """
    out = dict(sig)
    out["attack"] = technique_dicts_for(sig.get("name"))
    return out


def label_for(signal_name: Optional[str]) -> str:
    """한 줄 라벨: "T1490 Inhibit System Recovery (+1)" 형태.

    여러 기법이면 대표 1개 + 나머지 개수를 표기한다.  뱃지/요약용.
    """
    techs = techniques_for(signal_name)
    if not techs:
        return ""
    head = f"{techs[0].tid} {techs[0].name}"
    if len(techs) > 1:
        head += f" (+{len(techs) - 1})"
    return head
