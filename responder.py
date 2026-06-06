"""
Process Responder
-----------------
Active-response component: when the scoring engine raises a high-severity
signal that names a PID, the responder

  1. asks the kernel minifilter to quarantine the PID (block further file
     mutations from it), and then
  2. terminates the process.

Operating modes:

  - ``ResponderMode.OFF``        no action, just records what would happen
  - ``ResponderMode.QUARANTINE`` only step 1: stop the bleeding, keep the
                                 process alive for forensic capture
  - ``ResponderMode.KILL``       step 1 + step 2 (default for production)

The default trigger fires when a single signal of severity HIGH or
CRITICAL carries a ``pid`` in its metadata.  We also fire when the
rolling score crosses the CRITICAL threshold, in which case we kill every
PID that has contributed to the score in the active window.

Termination strategy on Windows:

  - ``psutil.Process(pid).kill()`` first (uses TerminateProcess under the
    hood, no signal semantics).
  - On failure, raw ``OpenProcess(PROCESS_TERMINATE) + TerminateProcess``
    via ctypes so we are independent of psutil's caching.
"""

from __future__ import annotations

import os
import platform
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Dict, List, Optional, Set

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from scoring import ScoringEngine, Signal, Severity, THRESHOLD_CRITICAL


class ResponderMode(str, Enum):
    OFF        = "off"
    QUARANTINE = "quarantine"
    KILL       = "kill"


# Hard never-kill list.  These are critical OS processes; killing one of
# them bluescreens the box.  We treat any match as a hard refusal even
# when the user has explicitly requested KILL mode.
NEVER_KILL = {
    # OS 핵심 프로세스 (기존)
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "fontdrvhost.exe",
    "dwm.exe", "memcompression",
    
    # Python (기존)
    "python.exe", "py.exe", "pythonw.exe",
    
    # 브라우저 (추가) — 캐시 정리로 오탐 잘 일어남
    "chrome.exe", "msedge.exe", "edge.exe", "firefox.exe",
    "iexplore.exe", "brave.exe", "opera.exe",
    
    # Windows 탐색기 / UI (추가)
    "explorer.exe", "systemsettings.exe", "shellexperiencehost.exe",
    "searchhost.exe", "startmenuexperiencehost.exe",
    
    # 시스템 서비스 (추가)
    "svchost.exe", "wininit.exe", "spoolsv.exe", "audiodg.exe",
    "conhost.exe", "taskhostw.exe", "runtimebroker.exe",
    
    # 개발 도구 (추가)
    "devenv.exe", "code.exe", "node.exe", "powershell.exe",
    "powershell_ise.exe", "cmd.exe", "wt.exe",
    
    # Windows Update / 백그라운드 (추가)
    "backgrounddownload.exe", "wmiprvse.exe", "trustedinstaller.exe",
    "tiworker.exe", "musnotification.exe",
    
    # 보안 (추가) — 자신 외 다른 EDR 등
    "msmpeng.exe", "mssense.exe", "securityhealthservice.exe",
}


# LOLBin / 도구 목록.  랜섬웨어는 이것들을 통해 파괴 행위(VSS 삭제, 로그
# 삭제, BCD 변조 등)를 실행한다.  이 중 하나가 고-위험 cmdline 을 들고
# 나타나면, 종료해야 할 대상은 (일회성이거나 never-kill 인) 그 도구가 아니라
# 그 도구를 띄운 부모 프로세스 — 즉 랜섬웨어 본체다.
ESCALATE_CHILD_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe",
    "wevtutil.exe", "fsutil.exe", "schtasks.exe", "reg.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "cipher.exe",
    "bitsadmin.exe", "certutil.exe", "manage-bde.exe", "netsh.exe",
}


# Of the names above, these are core Windows binaries that ONLY ever run
# from the system directory (System32 / SysWOW64).  Ransomware commonly
# copies itself to a user-writable path under one of these names — e.g.
# %TEMP%\svchost.exe — purely to inherit the never-kill immunity above.
# For these we additionally verify the image path: a process bearing one
# of these names from *outside* the trusted system dirs is an impostor and
# is NOT protected.  The genuine ones — and any whose path we cannot read
# (PPL-protected lsass/csrss, etc.) — stay protected: we only strip
# immunity on positive evidence of an untrusted path, never on a guess.
PATH_VERIFIED = {
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "lsaiso.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe",
    "svchost.exe", "spoolsv.exe", "audiodg.exe", "conhost.exe",
    "taskhostw.exe", "runtimebroker.exe", "wmiprvse.exe", "sihost.exe",
    "dllhost.exe", "ctfmon.exe",
}

# Pseudo processes with no on-disk image (psutil returns no path for
# them); they can't be terminated anyway, so protect purely by name.
_PSEUDO_PROCS = {"system", "registry", "memcompression", "secure system"}

_SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")
_TRUSTED_DIRS = tuple(
    os.path.normcase(os.path.join(_SYSROOT, sub))
    for sub in ("System32", "SysWOW64")
)


@dataclass
class KillAction:
    timestamp: float
    pid: int
    process_name: str
    cmdline: str
    reason: str
    mode: str
    quarantined: bool
    terminated: bool
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class ProcessResponder:
    """Listens to the ScoringEngine and reacts to malicious activity.

    The responder is intentionally framework-light: it just exposes
    ``handle_signal`` and ``handle_score`` methods that ``Agent`` wires
    into the engine via ``subscribe``.  All terminations are recorded so
    the dashboard can show what happened and the operator can audit.
    """

    def __init__(self,
                 engine: ScoringEngine,
                 *,
                 mode: ResponderMode = ResponderMode.KILL,
                 minifilter=None,
                 critical_threshold: int = THRESHOLD_CRITICAL,
                 on_action: Optional[Callable[[KillAction], None]] = None):
        self.engine = engine
        self.mode = mode
        self.minifilter = minifilter
        self.critical_threshold = critical_threshold
        self._on_action = on_action
        self._lock = threading.Lock()
        self._actions: List[KillAction] = []
        self._already_killed: Set[int] = set()
        self._already_quarantined: Set[int] = set()
        self._own_pid = os.getpid()

    # ---------------------------------------------------------- public API

    def attach(self) -> None:
        """Subscribe to the scoring engine.  Idempotent."""
        self.engine.subscribe(self._dispatch)

    def actions(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [a.to_dict() for a in self._actions[-limit:]]

    def manual_kill(self, pid: int, reason: str = "manual") -> KillAction:
        return self._respond_to_pid(pid, reason)

    def manual_release(self, pid: int) -> bool:
        """Forget that we touched ``pid`` and remove the kernel block."""
        with self._lock:
            self._already_killed.discard(pid)
            self._already_quarantined.discard(pid)
        if self.minifilter is not None:
            return self.minifilter.release_pid(pid)
        return True

    # ---------------------------------------------------- signal callbacks

    def _dispatch(self, sig: Signal, score: int, level: Severity) -> None:
        # 1. PID-scoped reaction: any HIGH/CRITICAL signal that names a PID.
        pid = self._extract_pid(sig)
        if pid and sig.severity in (Severity.HIGH, Severity.CRITICAL):
            # 탐지 시점에 신호가 들고 온 프로세스 이름/명령줄.  일회성 도구
            # (vssadmin/wmic 등)는 차단 시점엔 이미 종료돼 psutil 조회가
            # 실패하므로, 이 값들을 표시용 폴백으로 넘긴다.
            meta = sig.metadata or {}
            hint = meta.get("process") or ""
            cmd_hint = meta.get("cmdline") or ""
            self._respond_to_pid(pid, f"{sig.detector}/{sig.name}",
                                  name_hint=hint, cmd_hint=cmd_hint)

            # 1b. Parent escalation: ransomware drives destruction through
            #     LOLBins/tools (vssadmin, powershell, cmd, wbadmin, ...) that
            #     are either transient or on the never-kill list.  Killing the
            #     tool is too late or refused, so also terminate the PARENT that
            #     issued the command — that is the actual malware body.
            ppid = self._extract_parent_pid(sig)
            if ppid and ppid != pid and self._is_lolbin_signal(sig):
                self._respond_to_pid(
                    ppid, f"{sig.detector}/{sig.name} (parent of pid={pid})")

        # 2. Score-wide reaction: if the rolling score went CRITICAL, sweep
        #    every PID that has contributed in the current window.
        if score >= self.critical_threshold:
            self._sweep_window()

    def _extract_pid(self, sig: Signal) -> Optional[int]:
        meta = sig.metadata or {}
        for key in ("pid", "ProcessId", "child_pid", "process_id"):
            val = meta.get(key)
            if isinstance(val, int) and val > 0:
                return val
        return None

    def _extract_parent_pid(self, sig: Signal) -> Optional[int]:
        meta = sig.metadata or {}
        for key in ("ppid", "parent_pid", "ParentProcessId"):
            val = meta.get(key)
            if isinstance(val, int) and val > 0:
                return val
        return None

    def _is_lolbin_signal(self, sig: Signal) -> bool:
        """True when the signal's named process is a LOLBin/tool malware abuses
        (so the real culprit is its parent).  Uses the process name captured at
        detection time, so it works even after a transient tool has exited."""
        meta = sig.metadata or {}
        name = (meta.get("process") or "").lower()
        return name in ESCALATE_CHILD_NAMES

    # Severities that make a PID a sweep target.  We deliberately exclude
    # INFO/LOW: a benign process that merely deleted a temp/cache file
    # (e.g. file_delete, weight 3, LOW) shows up in the window but must NOT
    # be terminated just because the *aggregate* score is CRITICAL.  Only
    # PIDs that themselves emitted a genuinely suspicious signal
    # (persistence, shadow-copy/BCD tampering, mass rename, canary, …) are
    # swept.  Without this filter the sweep massacres bystander processes.
    _SWEEP_SEVERITIES = (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)

    def _sweep_window(self) -> None:
        pids: Set[int] = set()
        for sig in self.engine.recent_signals(limit=200):
            if sig.severity not in self._SWEEP_SEVERITIES:
                continue
            pid = self._extract_pid(sig)
            if pid:
                pids.add(pid)
        for pid in pids:
            self._respond_to_pid(pid, "score_critical_sweep")

    # ---------------------------------------------------- core kill logic

    def _respond_to_pid(self, pid: int, reason: str,
                        name_hint: str = "", cmd_hint: str = "") -> KillAction:
        if pid == self._own_pid:
            return self._noop(pid, reason, "refusing to kill self")

        proc_name, cmdline, exe_path = self._lookup(pid)

        # never-kill 판정은 *조회된* 이름/경로로만 한다(힌트로 판정을 바꾸지
        # 않음).  판정 후, 표시용 이름/명령줄이 비어 있을 때만 탐지 시점
        # 힌트로 채워 보고서에 'unknown'·'확인 불가' 대신 실제 도구 이름과
        # 명령줄이 남게 한다.
        if self._is_never_kill(proc_name, exe_path):
            return self._noop(pid, reason,
                              f"{proc_name!r} is on the never-kill list")
        if not proc_name and name_hint:
            proc_name = name_hint
        if not cmdline and cmd_hint:
            cmdline = cmd_hint

        with self._lock:
            already_killed = pid in self._already_killed
            already_quar   = pid in self._already_quarantined

        # Dedupe: if we've already done everything this mode calls for on
        # this PID, return silently WITHOUT recording another action or
        # writing a duplicate incident report.  The critical-score sweep
        # re-visits the same PIDs on every signal tick; without this guard
        # a single ransomware run produces thousands of repeat reports.
        fully_handled = (
            (self.mode == ResponderMode.KILL and already_killed) or
            (self.mode == ResponderMode.QUARANTINE and already_quar)
        )
        if fully_handled:
            return KillAction(time.time(), pid, proc_name, cmdline, reason,
                              self.mode.value, quarantined=already_quar,
                              terminated=already_killed,
                              error="already handled")

        quarantined = already_quar
        terminated  = already_killed
        error: Optional[str] = None

        if self.mode == ResponderMode.OFF:
            action = KillAction(time.time(), pid, proc_name, cmdline, reason,
                                self.mode.value, quarantined=False,
                                terminated=False,
                                error="responder mode = off")
            return self._record(action)

        if self.minifilter is not None and not already_quar:
            try:
                quarantined = bool(self.minifilter.quarantine_pid(pid))
            except Exception as e:
                error = f"quarantine failed: {e}"
                quarantined = False
            if quarantined:
                with self._lock:
                    self._already_quarantined.add(pid)

        if self.mode == ResponderMode.KILL and not already_killed:
            ok, err = self._terminate(pid)
            terminated = ok
            if not ok:
                error = err if error is None else f"{error}; {err}"
            else:
                with self._lock:
                    self._already_killed.add(pid)

        action = KillAction(time.time(), pid, proc_name, cmdline, reason,
                            self.mode.value, quarantined=quarantined,
                            terminated=terminated, error=error)
        return self._record(action)

    def _noop(self, pid: int, reason: str, why: str) -> KillAction:
        action = KillAction(time.time(), pid, "", "", reason,
                            self.mode.value, quarantined=False,
                            terminated=False, error=why)
        return self._record(action)

    def _record(self, action: KillAction) -> KillAction:
        with self._lock:
            self._actions.append(action)
            # Cap history so we don't grow unbounded over long sessions.
            if len(self._actions) > 1000:
                self._actions = self._actions[-1000:]
        bar = "█" if action.terminated else ("▒" if action.quarantined else "·")
        msg = (f"[responder] {bar} pid={action.pid} ({action.process_name}) "
               f"reason={action.reason} "
               f"quarantined={action.quarantined} "
               f"terminated={action.terminated}")
        if action.error:
            msg += f" err={action.error}"
        print(msg)
        if self._on_action:
            try:
                self._on_action(action)
            except Exception as e:
                print(f"[responder] on_action error: {e}")
        return action

    # ------------------------------------------------------------ helpers

    def _is_never_kill(self, proc_name: str, exe_path: str = "") -> bool:
        name = (proc_name or "").lower()
        # Pseudo processes (System/Registry/…) have no image path and
        # can't be killed anyway — protect by name.
        if name in _PSEUDO_PROCS:
            return True
        if name not in NEVER_KILL:
            return False
        # Core system binary names are only honoured when the image
        # actually lives in a trusted system dir.  A match from elsewhere
        # is an impostor (e.g. ransomware copied to %TEMP%\svchost.exe)
        # and gets no immunity.
        if name in PATH_VERIFIED and self._path_is_untrusted(exe_path):
            return False
        return True

    @staticmethod
    def _path_is_untrusted(exe_path: str) -> bool:
        # No path (empty, or unreadable for PPL-protected procs) → fail
        # safe to "trusted" so we never strip immunity without proof.
        if not exe_path:
            return False
        p = os.path.normcase(exe_path)
        return not any(p.startswith(d) for d in _TRUSTED_DIRS)

    def _lookup(self, pid: int) -> tuple[str, str, str]:
        if not HAS_PSUTIL:
            return ("", "", "")
        try:
            p = psutil.Process(pid)
            name = p.name()
            cmd = " ".join(p.cmdline())[:512]
        except Exception:
            return ("", "", "")
        # exe() can raise (AccessDenied on PPL procs, process gone, …)
        # independently of name()/cmdline(); don't let that wipe the name
        # we already have — just fall back to an empty (= unverifiable) path.
        try:
            exe = p.exe()
        except Exception:
            exe = ""
        return (name, cmd, exe)

    def _terminate(self, pid: int) -> tuple[bool, Optional[str]]:
        # Prefer psutil — it works cross-platform and handles permissions.
        if HAS_PSUTIL:
            try:
                p = psutil.Process(pid)
                p.kill()
                # Give the OS a moment, then verify.
                gone, _ = psutil.wait_procs([p], timeout=2.0)
                if gone:
                    return (True, None)
            except psutil.NoSuchProcess:
                return (True, None)
            except Exception as e:
                # Fall through to Win32 path; psutil errors on protected
                # processes (PPL/PsProtectedSigner) are recoverable when
                # we run elevated and the target is not actually protected.
                first_err = str(e)
            else:
                first_err = "psutil kill did not exit process"
        else:
            first_err = "psutil unavailable"

        if platform.system() != "Windows":
            return (False, first_err)

        try:
            import ctypes
            from ctypes import wintypes
            PROCESS_TERMINATE = 0x0001
            k32 = ctypes.windll.kernel32
            handle = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if not handle:
                err = ctypes.get_last_error()
                return (False, f"{first_err}; OpenProcess GLE={err}")
            try:
                ok = bool(k32.TerminateProcess(handle, 1))
                if not ok:
                    err = ctypes.get_last_error()
                    return (False, f"{first_err}; TerminateProcess GLE={err}")
            finally:
                k32.CloseHandle(handle)
            return (True, None)
        except Exception as e:
            return (False, f"{first_err}; win32 path: {e}")
