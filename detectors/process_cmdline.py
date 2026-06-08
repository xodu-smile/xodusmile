"""
Process Command Line Detector (Windows 11)
------------------------------------------
보고서 2.3 (VSS 삭제) + 2.9 (BCD 조작) 통합. 본 프로토타입은 Windows 11 전용.

원리: 새 프로세스가 생성될 때마다 그 커맨드라인을 정규식으로 검사.
Pre-encryption 시그널이라 매우 가치가 높다 (보고서 5.2).

구현:
  - WMI ExecNotificationQuery 로 Win32_Process 생성 이벤트 구독
  - psutil 기반 ProcessWatcher 와 RULES 를 공유 (evaluate_cmdline)

룰셋은 Win11 환경 가정:
  - VSS / Volume Shadow Copy 조작
  - BCD 부트 설정 변조
  - Microsoft Defender / SmartScreen 무력화
  - wevtutil / fsutil / cipher 기반 anti-forensics
  - schtasks / Run 키 지속화
  - 난독화된 PowerShell 실행 패턴
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Pattern

from .base import Detector
from scoring import Signal, Severity


@dataclass
class Rule:
    name: str
    pattern: Pattern
    weight: int
    severity: Severity
    message: str


# 정규식은 case-insensitive
def _rx(s: str) -> Pattern:
    return re.compile(s, re.IGNORECASE)


RULES: List[Rule] = [
    # --- VSS 삭제 (보고서 2.3) ---
    Rule(
        name="vssadmin_delete_shadows",
        pattern=_rx(r"vssadmin(\.exe)?\s+delete\s+shadows"),
        weight=70,
        severity=Severity.CRITICAL,
        message="VSS shadow copy deletion (vssadmin)",
    ),
    Rule(
        name="wmic_shadowcopy_delete",
        pattern=_rx(r"wmic(\.exe)?\s+shadowcopy\s+delete"),
        weight=70,
        severity=Severity.CRITICAL,
        message="VSS shadow copy deletion (wmic)",
    ),
    Rule(
        name="wbadmin_delete_catalog",
        pattern=_rx(r"wbadmin(\.exe)?\s+delete\s+catalog"),
        weight=60,
        severity=Severity.HIGH,
        message="Windows Backup catalog deletion (wbadmin)",
    ),
    Rule(
        name="powershell_remove_shadowcopy",
        pattern=_rx(
            r"(get-wmiobject|gwmi|get-ciminstance).{0,40}shadowcopy.{0,40}"
            r"(remove-wmiobject|remove-ciminstance)"
        ),
        weight=70,
        severity=Severity.CRITICAL,
        message="PowerShell-based shadow copy removal",
    ),

    # --- BCD 조작 (보고서 2.9) ---
    Rule(
        name="bcdedit_safeboot",
        pattern=_rx(r"bcdedit(\.exe)?.*safeboot\s+(minimal|network)"),
        weight=60,
        severity=Severity.HIGH,
        message="BCD modification: forced safe boot",
    ),
    Rule(
        name="bcdedit_recovery_disabled",
        pattern=_rx(r"bcdedit(\.exe)?.*recoveryenabled\s+no"),
        weight=55,
        severity=Severity.HIGH,
        message="BCD modification: recovery disabled",
    ),
    Rule(
        name="bcdedit_ignore_failures",
        pattern=_rx(r"bcdedit(\.exe)?.*bootstatuspolicy\s+ignoreallfailures"),
        weight=50,
        severity=Severity.HIGH,
        message="BCD modification: ignore boot failures",
    ),

    # --- Microsoft Defender 무력화 (Win11 MITRE T1562.001) ---
    Rule(
        name="defender_disable_realtime",
        pattern=_rx(
            r"set-mppreference.*-disablerealtimemonitoring\s+\$?true"
            r"|sc(\.exe)?\s+(stop|delete|config)\s+(windefend|sense|wdnissvc|wdfilter)"
        ),
        weight=55,
        severity=Severity.HIGH,
        message="Microsoft Defender realtime protection disablement",
    ),
    Rule(
        name="defender_add_exclusion",
        pattern=_rx(
            r"add-mppreference\s+.*-exclusion(path|extension|process)"
        ),
        weight=45,
        severity=Severity.HIGH,
        message="Microsoft Defender exclusion added (pre-encryption staging)",
    ),
    Rule(
        name="defender_disable_via_registry",
        pattern=_rx(
            r"reg(\.exe)?\s+add\s+.*\\Windows\s+Defender\b.*"
            r"(disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring)"
        ),
        weight=55,
        severity=Severity.HIGH,
        message="Microsoft Defender disabled via registry edit",
    ),
    Rule(
        name="smartscreen_disable",
        pattern=_rx(
            r"set-mppreference\s+.*-puaprotection\s+0"
            r"|reg(\.exe)?\s+add\s+.*\\System\b.*EnableSmartScreen.*\s+0"
        ),
        weight=35,
        severity=Severity.MEDIUM,
        message="SmartScreen / PUA protection disabled",
    ),

    # --- 로그/포렌식 인공물 삭제 (Win11) ---
    Rule(
        name="wevtutil_clear_log",
        pattern=_rx(r"wevtutil(\.exe)?\s+(cl|clear-log)\s+\S+"),
        weight=55,
        severity=Severity.HIGH,
        message="Windows event log cleared (wevtutil)",
    ),
    Rule(
        name="powershell_clear_eventlog",
        pattern=_rx(
            r"(clear-eventlog|remove-eventlog|clear-winevent|clear-eventlogfile)"
        ),
        weight=55,
        severity=Severity.HIGH,
        message="Windows event log cleared (PowerShell)",
    ),
    Rule(
        name="fsutil_usn_delete",
        pattern=_rx(r"fsutil(\.exe)?\s+usn\s+deletejournal"),
        weight=60,
        severity=Severity.HIGH,
        message="NTFS USN journal deleted (anti-forensics)",
    ),
    Rule(
        name="cipher_wipe_free_space",
        pattern=_rx(r"\bcipher(\.exe)?\s+/w(:|\s)"),
        weight=55,
        severity=Severity.HIGH,
        message="cipher /w used to wipe free space (anti-recovery)",
    ),

    # --- 복구/방어 인프라 차단 ---
    Rule(
        name="netsh_firewall_off",
        pattern=_rx(
            r"netsh(\.exe)?\s+advfirewall\s+set\s+(allprofiles|domainprofile|"
            r"privateprofile|publicprofile)\s+state\s+off"
        ),
        weight=45,
        severity=Severity.HIGH,
        message="Windows Firewall turned off (netsh)",
    ),
    Rule(
        name="bitlocker_disable",
        pattern=_rx(
            r"(manage-bde(\.exe)?\s+-off|disable-bitlocker)\b"
        ),
        weight=50,
        severity=Severity.HIGH,
        message="BitLocker disablement (pre-encryption staging)",
    ),

    # === 정상/내장 도구를 *암호화 엔진* 으로 악용 (T1486) =====================
    # 자체 암호화 루틴 대신 OS 에 내장된 신뢰 도구로 파일을 암호화하는
    # "living-off-the-land" 랜섬웨어.  바이너리가 서명돼 있어 정적 탐지를 피한다.
    Rule(
        name="cipher_efs_encrypt",
        pattern=_rx(r"\bcipher(\.exe)?\s+/e\b"),
        weight=45,
        severity=Severity.HIGH,
        message="EFS encryption via built-in cipher /e (living-off-the-land)",
    ),
    Rule(
        name="bitlocker_abuse_enable",
        pattern=_rx(
            r"(manage-bde(\.exe)?\s+.*-on\b"
            r"|enable-bitlocker\b"
            r"|manage-bde(\.exe)?\s+-on\b)"
        ),
        # HIGH(not CRITICAL): enabling BitLocker is also a legitimate IT action,
        # so we score it strongly and corroborate via the window rather than
        # single-handedly forcing a CRITICAL score.  Still pre-encryption-grade.
        weight=60,
        severity=Severity.HIGH,
        message="BitLocker volume encryption being enabled (possible ransomware "
                "abusing native disk encryption)",
    ),
    Rule(
        name="vssadmin_resize_shadowstorage",
        pattern=_rx(r"vssadmin(\.exe)?\s+resize\s+shadowstorage"),
        weight=55,
        severity=Severity.HIGH,
        message="VSS shadowstorage resized (shadow-copy starvation / recovery sabotage)",
    ),

    # === LOLBin: 신뢰 시스템 바이너리를 프록시 실행/스테이징에 악용 ============
    Rule(
        name="certutil_download",
        pattern=_rx(
            r"certutil(\.exe)?\s+.*-(urlcache|verifyctl)\b.*\bhttp"
            r"|certutil(\.exe)?\s+.*-urlcache\b.*-f\b"
        ),
        weight=45,
        severity=Severity.HIGH,
        message="certutil used to download a file (LOLBin ingress tool transfer)",
    ),
    Rule(
        name="certutil_decode_payload",
        pattern=_rx(r"certutil(\.exe)?\s+.*-(decode|decodehex)\b"),
        weight=35,
        severity=Severity.MEDIUM,
        message="certutil decoding a payload (LOLBin deobfuscation/staging)",
    ),
    Rule(
        name="bitsadmin_transfer",
        pattern=_rx(r"bitsadmin(\.exe)?\s+.*/transfer\b"),
        weight=35,
        severity=Severity.MEDIUM,
        message="bitsadmin background transfer (LOLBin download via BITS jobs)",
    ),
    Rule(
        name="esentutl_raw_copy",
        pattern=_rx(r"esentutl(\.exe)?\s+.*/y\b"),
        weight=35,
        severity=Severity.MEDIUM,
        message="esentutl raw copy of a locked file (LOLBin file access)",
    ),
    Rule(
        name="wmic_process_call_create",
        pattern=_rx(r"wmic(\.exe)?\s+.*process\s+call\s+create"),
        weight=40,
        severity=Severity.HIGH,
        message="WMIC process call create (LOLBin proxy execution / lateral spawn)",
    ),

    # === BYOVD — 취약 드라이버를 적재해 커널에서 EDR 을 무력화 (T1543.003) =====
    Rule(
        name="kernel_service_create",
        pattern=_rx(r"sc(\.exe)?\s+create\b.*type=\s*kernel"),
        weight=55,
        severity=Severity.HIGH,
        message="Kernel-mode service created via sc.exe (possible BYOVD to kill EDR)",
    ),

    # === 이중 갈취 — 암호화 전 데이터 스테이징/유출 (T1560.001 / T1567.002) ====
    Rule(
        name="archive_password_staging",
        pattern=_rx(
            r"\b(7z|7za|7zr|rar|winrar|winzip)(\.exe)?\s+a\b.*\s-p"
        ),
        weight=30,
        severity=Severity.MEDIUM,
        message="Password-protected archive being built (data staging / "
                "double-extortion exfil prep)",
    ),
    Rule(
        name="rclone_exfil",
        pattern=_rx(r"\brclone(\.exe)?\s+(copy|sync|move|cat)\b"),
        weight=35,
        severity=Severity.MEDIUM,
        message="rclone bulk data movement (possible cloud exfiltration)",
    ),

    # --- 지속화 (T1053.005 schtasks, T1547.001 Run keys) ---
    Rule(
        name="schtasks_persistence",
        pattern=_rx(
            r"schtasks(\.exe)?\s+/create\b.*"
            r"/sc\s+(onlogon|onstart|onidle|minute)\b.*"
            r"/(rl|ru)\s+\S*system"
        ),
        weight=35,
        severity=Severity.MEDIUM,
        message="Scheduled task created with SYSTEM/auto-trigger (persistence)",
    ),
    Rule(
        name="run_key_persistence",
        pattern=_rx(
            r"reg(\.exe)?\s+add\s+.*\\Microsoft\\Windows\\CurrentVersion\\"
            r"Run(Once)?\b"
        ),
        weight=30,
        severity=Severity.MEDIUM,
        message="Run/RunOnce registry key written (persistence)",
    ),

    # --- 의심스러운 PowerShell 호출 패턴 ---
    Rule(
        name="powershell_obfuscated_exec",
        pattern=_rx(
            r"powershell(\.exe)?\b.*"
            r"-(enc(odedcommand)?|e)\b\s+[A-Za-z0-9+/=]{40,}"
        ),
        weight=40,
        severity=Severity.HIGH,
        message="PowerShell encoded command (likely obfuscation)",
    ),
    Rule(
        name="powershell_downloader",
        pattern=_rx(
            r"powershell(\.exe)?\b.*"
            r"(invoke-webrequest|iwr|invoke-restmethod|irm|"
            r"\(new-object\s+net\.webclient\)\.downloadstring|"
            r"net\.webclient\)\.downloadfile)"
        ),
        weight=35,
        severity=Severity.MEDIUM,
        message="PowerShell in-memory downloader (stager pattern)",
    ),
    Rule(
        name="powershell_bypass_policy",
        pattern=_rx(
            r"powershell(\.exe)?\b.*-ex(ecutionpolicy)?\s+bypass\b.*"
            r"-(w|windowstyle)\s+hidden"
        ),
        weight=30,
        severity=Severity.MEDIUM,
        message="PowerShell ExecutionPolicy bypass + hidden window",
    ),
]


class ProcessCmdlineDetector(Detector):
    """WMI ExecNotificationQuery 기반 프로세스 생성 감시기 (Windows 11 전용)."""

    name = "process_cmdline"

    def __init__(self, engine):
        super().__init__(engine)
        self._wmi_conn = None

    def submit_external(self, process_name: str, cmdline: str,
                        pid: Optional[int] = None,
                        ppid: Optional[int] = None) -> None:
        """테스트 시뮬레이터가 가짜 이벤트를 주입하기 위한 진입점."""
        self._evaluate(process_name, cmdline, pid, ppid)

    def run(self) -> None:
        try:
            import wmi  # type: ignore
            import pythoncom  # type: ignore
        except ImportError:
            print(f"[{self.name}] wmi / pywin32 not installed — "
                  f"this build targets Windows 11. Install requirements.txt "
                  f"on Windows.")
            self._stop_event.wait()
            return

        pythoncom.CoInitialize()
        try:
            self._wmi_conn = wmi.WMI()
            watcher = self._wmi_conn.Win32_Process.watch_for("creation")
            print(f"[{self.name}] WMI Win32_Process watcher started")
            while not self._stop_event.is_set():
                try:
                    proc = watcher(timeout_ms=1000)
                    if proc is None:
                        continue
                    name = (proc.Name or "").strip()
                    cmd = (proc.CommandLine or "").strip()
                    pid = int(proc.ProcessId or 0)
                    ppid = int(proc.ParentProcessId or 0)
                    self._evaluate(name, cmd, pid, ppid)
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    print(f"[{self.name}] watcher error: {e}")
        finally:
            pythoncom.CoUninitialize()

    def _evaluate(self, process_name: str, cmdline: str,
                  pid: Optional[int], ppid: Optional[int]) -> None:
        for sig in evaluate_cmdline(self.name, process_name, cmdline, pid, ppid):
            self.emit(sig)


def evaluate_cmdline(detector_name: str, process_name: str, cmdline: str,
                     pid: Optional[int] = None,
                     ppid: Optional[int] = None) -> List[Signal]:
    """Run every rule against a cmdline and produce signals.

    Shared with ProcessWatcher so both Windows-WMI and psutil polling
    paths apply identical detection logic.
    """
    if not cmdline:
        return []
    out: List[Signal] = []
    for rule in RULES:
        if rule.pattern.search(cmdline):
            out.append(Signal(
                detector=detector_name,
                name=rule.name,
                weight=rule.weight,
                severity=rule.severity,
                message=rule.message,
                metadata={
                    "process": process_name,
                    "cmdline": cmdline[:512],
                    "pid": pid,
                    "ppid": ppid,
                },
            ))
    return out
