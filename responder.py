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
            self._respond_to_pid(pid, f"{sig.detector}/{sig.name}")

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

    def _sweep_window(self) -> None:
        pids: Set[int] = set()
        for sig in self.engine.recent_signals(limit=200):
            pid = self._extract_pid(sig)
            if pid:
                pids.add(pid)
        for pid in pids:
            self._respond_to_pid(pid, "score_critical_sweep")

    # ---------------------------------------------------- core kill logic

    def _respond_to_pid(self, pid: int, reason: str) -> KillAction:
        if pid == self._own_pid:
            return self._noop(pid, reason, "refusing to kill self")

        proc_name, cmdline = self._lookup(pid)

        if self._is_never_kill(proc_name):
            return self._noop(pid, reason,
                              f"{proc_name!r} is on the never-kill list")

        with self._lock:
            already_killed = pid in self._already_killed
            already_quar   = pid in self._already_quarantined

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

    def _is_never_kill(self, proc_name: str) -> bool:
        return (proc_name or "").lower() in NEVER_KILL

    def _lookup(self, pid: int) -> tuple[str, str]:
        if not HAS_PSUTIL:
            return ("", "")
        try:
            p = psutil.Process(pid)
            name = p.name()
            cmd = " ".join(p.cmdline())[:512]
            return (name, cmd)
        except Exception:
            return ("", "")

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
