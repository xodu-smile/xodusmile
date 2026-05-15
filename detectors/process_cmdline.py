"""
Process Command Line Detector
-----------------------------
보고서 2.3 (VSS 삭제) + 2.9 (BCD 조작) 통합.

원리: 새 프로세스가 생성될 때마다 그 커맨드라인을 정규식으로 검사.
Pre-encryption 시그널이라 매우 가치가 높다 (보고서 5.2).

구현:
  - Windows: WMI ExecNotificationQuery로 Win32_ProcessStartTrace 구독
  - 비-Windows: 데모 모드 — 시뮬레이터가 직접 시그널 주입 가능

화이트리스트 (보고서 3.1):
  - 정상 백업 솔루션 / IT 운영 도구는 단독 발생만으로는 차단하지 않고
    다른 시그널과 결합 시에만 가중치 부여 — 이 프로토타입에서는
    가중치를 낮게 잡아서 같은 효과를 낸다 (단일 시그널로는 임계값 미달).
"""

import platform
import re
import threading
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

    # --- 보너스: 일반 보안 무력화 ---
    Rule(
        name="defender_disable",
        pattern=_rx(
            r"set-mppreference.*-disablerealtimemonitoring\s+\$?true"
            r"|sc(\.exe)?\s+(stop|delete)\s+(windefend|sense|wdnissvc)"
        ),
        weight=45,
        severity=Severity.HIGH,
        message="Windows Defender disablement attempt",
    ),
]


class ProcessCmdlineDetector(Detector):
    name = "process_cmdline"

    def __init__(self, engine):
        super().__init__(engine)
        self._is_windows = platform.system() == "Windows"
        self._wmi_conn = None

    def submit_external(self, process_name: str, cmdline: str,
                        pid: Optional[int] = None,
                        ppid: Optional[int] = None) -> None:
        """
        외부에서 (예: 테스트 시뮬레이터, 또는 다른 OS의 프로세스 모니터에서)
        프로세스 생성 이벤트를 주입할 수 있는 진입점.
        """
        self._evaluate(process_name, cmdline, pid, ppid)

    def run(self) -> None:
        if not self._is_windows:
            print(f"[{self.name}] non-Windows OS — running in passive mode "
                  f"(accept submit_external() only)")
            self._stop_event.wait()
            return

        try:
            import wmi  # type: ignore
            import pythoncom  # type: ignore
        except ImportError:
            print(f"[{self.name}] wmi / pywin32 not installed — passive mode")
            self._stop_event.wait()
            return

        pythoncom.CoInitialize()
        try:
            self._wmi_conn = wmi.WMI()
            watcher = self._wmi_conn.Win32_Process.watch_for("creation")
            print(f"[{self.name}] WMI process watcher started")
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
        if not cmdline:
            return
        for rule in RULES:
            if rule.pattern.search(cmdline):
                self.emit(Signal(
                    detector=self.name,
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
