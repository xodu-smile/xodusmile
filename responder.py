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

Targeting is deliberately *narrow*.  We only ever act on the exact PID a
signal names — there is no "score crossed CRITICAL, sweep every PID in
the window" path (that turned isolated false positives into mass kills,
and leaned entirely on the never-kill list to spare benign processes).

A PID is acted on only when the evidence is strong enough:

  - a CRITICAL signal (e.g. ``vssadmin delete shadows``) — unambiguous
    pre-encryption sabotage, high-confidence on its own; or
  - a HIGH signal *corroborated* by independent evidence: real
    file-encryption activity somewhere in the window (see
    ``ScoringEngine.has_encryption_activity``), or a second distinct
    detector that also flagged the same PID.

A lone HIGH heuristic (e.g. ``explorer.exe -> rundll32.exe``) with no
corroboration is recorded but NOT acted on — the never-kill list is a
backstop, not the primary defence.

Termination strategy on Windows:

  - ``psutil.Process(pid).kill()`` first (uses TerminateProcess under the
    hood, no signal semantics).
  - On failure, raw ``OpenProcess(PROCESS_TERMINATE) + TerminateProcess``
    via ctypes so we are independent of psutil's caching.
"""

from __future__ import annotations

import os
import platform
import queue
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

from scoring import (ScoringEngine, Signal, Severity, THRESHOLD_CRITICAL,
                     ENCRYPTION_SIGNAL_NAMES)


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

    # Win11 셸/호스트 헬퍼 (추가) — 정상 부모-자식 체인의 단골 오탐 대상
    "rundll32.exe", "regsvr32.exe", "dllhost.exe", "sihost.exe",
    "ctfmon.exe", "dashost.exe", "wmiprvse.exe",
    
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

        # Active response runs on a dedicated worker thread, NOT inline on
        # the detector/kernel-bridge callback thread.  Terminating a process
        # (psutil.kill + up-to-2s confirmation) and writing the markdown
        # incident report to disk are slow; doing them inside the
        # ScoringEngine.submit() -> listener call would stall the kernel
        # FilterGetMessage pump that fed the signal.  Kernel events then back
        # up and the desktop lags exactly when ransomware is fanning out.
        # We make the dispatch decision inline (cheap deque scans) and hand
        # the blocking work to the worker.
        self._queue: "queue.Queue[Optional[tuple]]" = queue.Queue()
        self._inflight: Set[int] = set()
        self._worker: Optional[threading.Thread] = None

    # ---------------------------------------------------------- public API

    def attach(self) -> None:
        """Subscribe to the scoring engine.  Idempotent."""
        self._ensure_worker()
        self.engine.subscribe(self._dispatch)

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(
                target=self._worker_loop,
                name="responder-worker",
                daemon=True,
            )
            self._worker.start()

    def _worker_loop(self) -> None:
        while True:
            job = self._queue.get()
            try:
                if job is None:        # sentinel: shut the worker down
                    return
                pid, reason, cap = job
                try:
                    self._respond_to_pid(pid, reason, cap_quarantine=cap)
                except Exception as e:
                    print(f"[responder] worker error on pid={pid}: {e}")
                finally:
                    with self._lock:
                        self._inflight.discard(pid)
            finally:
                self._queue.task_done()

    def _enqueue(self, pid: int, reason: str,
                 *, cap_quarantine: bool = False) -> None:
        """Queue an action for the worker, skipping work already done.

        Under the kernel minifilter the same pid is re-flagged on *every*
        file op, so the naive path would enqueue (and psutil-look-up, and
        report) hundreds of times for one process.  We drop anything that
        is already in flight or has already reached its terminal state.
        """
        with self._lock:
            if pid in self._inflight:
                return
            if pid in self._already_killed:
                return  # terminal — nothing left to do for this pid
            if cap_quarantine and pid in self._already_quarantined:
                return  # correlated quarantine already applied
            self._inflight.add(pid)
        self._queue.put((pid, reason, cap_quarantine))

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
        # PID-scoped reaction only — no score-wide sweep.  A signal must
        # both name a PID and clear the confidence bar before we touch it.
        if sig.severity not in (Severity.HIGH, Severity.CRITICAL):
            return

        reason = f"{sig.detector}/{sig.name}"
        pid = self._extract_pid(sig)

        # Pre-emptive path: a high-confidence indicator that names NO pid
        # (e.g. the file-polling canary) would otherwise just add to the
        # score and never trigger a response.  Attribute it to the dominant
        # file-mutating pid in the window and act *immediately* — without
        # waiting for the global score to crawl up to CRITICAL.  Since the
        # pid is inferred (not named by the signal) we cap the action at
        # QUARANTINE so a mis-attribution can't kill the wrong process.
        if pid is None:
            if sig.name in ENCRYPTION_SIGNAL_NAMES:
                culprit = self._correlate_pid(sig)
                if culprit is not None:
                    self._enqueue(culprit, f"{reason} [correlated]",
                                  cap_quarantine=True)
                else:
                    self._record_observed(0, f"{reason} [no pid to attribute]")
            return

        if self._is_confident(pid, sig):
            self._enqueue(pid, reason)
        else:
            # Suspicious but uncorroborated — log intent, take no action.
            # The dashboard still shows it so an operator can judge.
            self._record_observed(pid, reason)

    def _extract_pid(self, sig: Signal) -> Optional[int]:
        meta = sig.metadata or {}
        for key in ("pid", "ProcessId", "child_pid", "process_id"):
            val = meta.get(key)
            if isinstance(val, int) and val > 0:
                return val
        return None

    def _is_confident(self, pid: int, sig: Signal) -> bool:
        """Decide whether the evidence justifies acting on ``pid``.

        CRITICAL signals (pre-encryption sabotage like VSS deletion) act on
        their own.  A HIGH signal needs corroboration: real encryption
        activity in the window, or a second distinct detector naming the
        same PID.
        """
        if sig.severity == Severity.CRITICAL:
            return True

        # Real file-encryption/destruction observed elsewhere (excluding the
        # triggering signal itself) corroborates a HIGH heuristic.
        if self.engine.has_encryption_activity(exclude=sig):
            return True

        # Or: two or more distinct detectors independently flagged this PID.
        detectors: Set[str] = set()
        for other in self.engine.recent_signals(limit=200):
            if self._extract_pid(other) == pid:
                detectors.add(other.detector)
            if len(detectors) >= 2:
                return True
        return False

    def _correlate_pid(self, sig: Signal) -> Optional[int]:
        """Best-guess the pid behind a pid-less indicator (e.g. canary).

        Tally how many file-mutation signals each pid produced in the
        current window and return the clear leader.  If a runner-up is at
        least half as active we return ``None`` (ambiguous → don't guess),
        so a mis-attributed quarantine stays unlikely.
        """
        counts: Dict[int, int] = {}
        for other in self.engine.recent_signals(limit=500):
            p = self._extract_pid(other)
            if not p or p == self._own_pid:
                continue
            if (other.name in ENCRYPTION_SIGNAL_NAMES
                    or other.detector in ("minifilter", "mass_io")):
                counts[p] = counts.get(p, 0) + 1
        if not counts:
            return None
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        top_pid, top_n = ranked[0]
        if len(ranked) > 1 and ranked[1][1] * 2 >= top_n:
            return None  # ambiguous — two pids comparably active
        return top_pid

    # ---------------------------------------------------- core kill logic

    def _respond_to_pid(self, pid: int, reason: str,
                        *, cap_quarantine: bool = False) -> KillAction:
        if pid == self._own_pid:
            return self._noop(pid, reason, "refusing to kill self")

        proc_name, cmdline = self._lookup(pid)

        if self._is_never_kill(proc_name):
            return self._noop(pid, reason,
                              f"{proc_name!r} is on the never-kill list")

        # When the pid was *inferred* (correlated from a pid-less signal) we
        # downgrade KILL → QUARANTINE: block the process but don't terminate
        # something we only guessed at.  OFF stays OFF.
        eff_mode = self.mode
        if cap_quarantine and eff_mode == ResponderMode.KILL:
            eff_mode = ResponderMode.QUARANTINE

        with self._lock:
            already_killed = pid in self._already_killed
            already_quar   = pid in self._already_quarantined

        quarantined = already_quar
        terminated  = already_killed
        error: Optional[str] = None

        if eff_mode == ResponderMode.OFF:
            action = KillAction(time.time(), pid, proc_name, cmdline, reason,
                                eff_mode.value, quarantined=False,
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

        if eff_mode == ResponderMode.KILL and not already_killed:
            ok, err = self._terminate(pid)
            terminated = ok
            if not ok:
                error = err if error is None else f"{error}; {err}"
            else:
                with self._lock:
                    self._already_killed.add(pid)

        action = KillAction(time.time(), pid, proc_name, cmdline, reason,
                            eff_mode.value, quarantined=quarantined,
                            terminated=terminated, error=error)
        return self._record(action)

    def _noop(self, pid: int, reason: str, why: str) -> KillAction:
        action = KillAction(time.time(), pid, "", "", reason,
                            self.mode.value, quarantined=False,
                            terminated=False, error=why)
        return self._record(action)

    def _record_observed(self, pid: int, reason: str) -> KillAction:
        """A suspicious-but-uncorroborated HIGH signal: record, don't act."""
        proc_name, cmdline = self._lookup(pid)
        action = KillAction(time.time(), pid, proc_name, cmdline, reason,
                            self.mode.value, quarantined=False,
                            terminated=False,
                            error="observed only (no corroboration)")
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
