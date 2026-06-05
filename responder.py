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


# ---- 프로세스 위장(masquerade) 방어 -------------------------------------
# never-kill 리스트는 *이름*만 본다.  랜섬웨어가 자기 실행 파일을
# "svchost.exe" 같은 핵심 OS 프로세스 이름으로 위장하면 보호를 가로채
# 차단을 회피한다.  방어책: 진짜 OS 핵심 프로세스는 *항상* 시스템 폴더에서
# 실행된다는 점을 이용해, never-kill 이름이라도 실행 경로가 시스템 루트가
# 아니면 "가짜(imposter)"로 보고 보호를 해제한다.
_WINDIR = (os.environ.get("SystemRoot")
           or os.environ.get("windir")
           or r"C:\Windows").rstrip("\\")

# 진짜 인스턴스가 반드시 이 아래에서 실행되는 경로들.  하나라도 prefix 가
# 맞으면 정상 위치로 본다.  (소문자 비교)
_SYSTEM_PROCESS_ROOTS = (
    (_WINDIR + "\\system32\\").lower(),
    (_WINDIR + "\\syswow64\\").lower(),
    (_WINDIR + "\\winsxs\\").lower(),
    (_WINDIR + "\\systemapps\\").lower(),   # 셸/스토어 호스트(SearchHost 등)
    (_WINDIR + "\\").lower(),               # explorer.exe 등 Windows 직속
)

# 경로 검증이 *신뢰 가능한* never-kill 이름들.  진짜가 늘 시스템 폴더에서만
# 도는 프로세스로 한정한다.  브라우저·개발도구·Defender 처럼 경로가 제각각인
# 것은 제외(정상인데 가짜로 오판하면 안 됨) — 그쪽은 항상 "보호" 취급한다.
_PATH_VERIFIED_NAMES = frozenset({
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "fontdrvhost.exe", "dwm.exe", "svchost.exe",
    "spoolsv.exe", "audiodg.exe", "conhost.exe", "taskhostw.exe",
    "runtimebroker.exe", "rundll32.exe", "regsvr32.exe", "dllhost.exe",
    "sihost.exe", "ctfmon.exe", "dashost.exe", "wmiprvse.exe",
    "trustedinstaller.exe", "tiworker.exe", "musnotification.exe",
    "explorer.exe", "searchhost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "systemsettings.exe",
})


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


@dataclass
class PendingDecision:
    """never-kill 리스트에 걸린 프로세스가 악성으로 의심될 때, 운영자에게
    '죽일지/살릴지' 묻기 위해 보류 중인 결정."""
    timestamp: float
    pid: int
    process_name: str
    cmdline: str
    reason: str
    image_path: str
    quarantined: bool
    status: str = "pending"   # pending | killed | spared | kill-failed

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
        # never-kill 후보지만 악성 의심이라 운영자 결정을 기다리는 항목.
        self._pending: Dict[int, PendingDecision] = {}
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
        # A manual kill is an explicit operator action, so it overrides the
        # never-kill list (``force=True``).  The list is an *automatic*
        # backstop against false positives — a human who deliberately clicks
        # kill has already made the call.
        return self._respond_to_pid(pid, reason, force=True)

    def manual_release(self, pid: int) -> bool:
        """Forget that we touched ``pid`` and remove the kernel block."""
        with self._lock:
            self._already_killed.discard(pid)
            self._already_quarantined.discard(pid)
        if self.minifilter is not None:
            return self.minifilter.release_pid(pid)
        return True

    # -------------------------------------------- operator kill decisions

    def pending_decisions(self, include_resolved: bool = False) -> List[dict]:
        """never-kill 보호 때문에 자동 차단을 보류하고 운영자 결정을 기다리는
        프로세스 목록.  대시보드가 폴링해서 '죽이기/살리기' 버튼을 띄운다."""
        with self._lock:
            items = list(self._pending.values())
        return [p.to_dict() for p in items
                if include_resolved or p.status == "pending"]

    def resolve_decision(self, pid: int, approve: bool,
                         by: str = "operator") -> Optional[KillAction]:
        """운영자가 보류된 never-kill 프로세스에 대해 내린 결정을 집행한다.

        ``approve=True``  -> never-kill 을 무시하고 강제 종료.
        ``approve=False`` -> 격리 해제하고 살려둔다(오탐으로 판단).
        """
        with self._lock:
            pend = self._pending.get(pid)
        if pend is None or pend.status != "pending":
            return None

        if approve:
            action = self._respond_to_pid(
                pid, f"{pend.reason} [operator-approved:{by}]", force=True)
            with self._lock:
                p = self._pending.get(pid)
                if p is not None:
                    p.status = "killed" if action.terminated else "kill-failed"
            return action

        # 살리기: 커널 격리를 풀고 보류 해제.
        self.manual_release(pid)
        with self._lock:
            p = self._pending.get(pid)
            if p is not None:
                p.status = "spared"
        action = KillAction(
            time.time(), pid, pend.process_name, pend.cmdline,
            f"{pend.reason} [operator-spared:{by}]", self.mode.value,
            quarantined=False, terminated=False,
            error="operator chose to spare (never-kill override declined)")
        return self._record(action)

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
                        *, cap_quarantine: bool = False,
                        force: bool = False) -> KillAction:
        if pid == self._own_pid:
            return self._noop(pid, reason, "refusing to kill self")

        proc_name, cmdline = self._lookup(pid)

        # never-kill 처리.  ``force`` (운영자 직접 결정)면 통째로 건너뛴다.
        if not force and self._is_never_kill(proc_name):
            verdict, detail = self._classify_never_kill(pid, proc_name)
            if verdict == "imposter":
                # 이름은 핵심 프로세스인데 실행 경로가 시스템 폴더가 아니다 →
                # 위장한 가짜다.  진짜는 시스템 폴더에 따로 살아있으므로 안전하게
                # 죽인다.  never-kill 보호를 적용하지 않고 아래로 통과시킨다.
                print(f"[responder] ⚠ 위장 탐지: {proc_name!r} 가 "
                      f"{detail!r} 에서 실행 중 — 진짜 시스템 프로세스가 "
                      f"아니므로 never-kill 보호를 해제하고 차단합니다")
            elif self.mode == ResponderMode.KILL:
                # 이름·경로 모두 정상인 진짜 핵심 프로세스인데 악성 의심이다.
                # 자동으로 죽이면 시스템이 불안정해질 수 있으니, 격리로 출혈을
                # 막고 운영자에게 죽일지 물어본다(보류).
                return self._defer_decision(pid, proc_name, cmdline,
                                            reason, detail)
            else:
                # KILL 모드가 아니면 종전대로 그냥 보호.
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
        result = self._record(action)

        # The culprit is dead — drop its signals from the live scoring window
        # so the global threat level falls back to "안전" on its own once every
        # active threat is neutralized, instead of staying RED until the
        # operator hits the reset button.  Done *after* _record(): on_action
        # builds the incident report from engine.recent_signals(), so the
        # evidence must still be in the window at report time.  Other pids'
        # signals — and the permanent audit trail — are untouched.
        if result.terminated:
            self.engine.forget_pid(pid)

        return result

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

    def _image_path(self, pid: int) -> str:
        if not HAS_PSUTIL:
            return ""
        try:
            return psutil.Process(pid).exe() or ""
        except Exception:
            # 접근 거부/소멸 등 → 경로를 모른다.  호출부에서 안전측(보호)으로
            # 처리한다.
            return ""

    def _classify_never_kill(self, pid: int, proc_name: str) -> tuple[str, str]:
        """never-kill 이름을 가진 프로세스를 분류한다.

        반환: ("imposter", 실행경로)  — 위장한 가짜, 죽여도 안전
              ("protected", 실행경로) — 진짜(또는 판단불가), 운영자 확인 필요
        """
        low = (proc_name or "").lower()
        if low not in _PATH_VERIFIED_NAMES:
            # 경로로 진위를 가릴 수 없는 이름(브라우저/개발도구 등) → 항상 보호.
            return ("protected", "")
        path = self._image_path(pid)
        if not path:
            # 경로를 못 읽으면 진짜일 수 있으니 보호측으로(가짜로 단정하지 않음).
            return ("protected", "(경로 확인 불가)")
        norm = path.replace("/", "\\").lower()
        if any(norm.startswith(root) for root in _SYSTEM_PROCESS_ROOTS):
            return ("protected", path)   # 정상 시스템 폴더 → 진짜
        return ("imposter", path)        # 시스템 폴더 밖 → 위장한 가짜

    def _defer_decision(self, pid: int, proc_name: str, cmdline: str,
                        reason: str, image_path: str) -> KillAction:
        """진짜 never-kill 프로세스가 악성 의심일 때: 격리로 출혈을 막고
        운영자 결정을 보류 목록에 올린다(자동 종료하지 않음)."""
        quarantined = False
        with self._lock:
            already_quar = pid in self._already_quarantined
        if already_quar:
            quarantined = True
        elif self.minifilter is not None:
            try:
                quarantined = bool(self.minifilter.quarantine_pid(pid))
            except Exception:
                quarantined = False
            if quarantined:
                with self._lock:
                    self._already_quarantined.add(pid)

        with self._lock:
            self._pending[pid] = PendingDecision(
                timestamp=time.time(), pid=pid, process_name=proc_name,
                cmdline=cmdline, reason=reason, image_path=image_path,
                quarantined=quarantined, status="pending")
            # 메모리 보호: 해결된 항목이 너무 많이 쌓이면 정리.
            if len(self._pending) > 256:
                self._pending = {k: v for k, v in self._pending.items()
                                 if v.status == "pending"}

        print(f"[responder] ⏸ 결정 보류: {proc_name!r} (PID {pid}) 는 "
              f"never-kill 목록에 있지만 악성으로 의심됩니다 "
              f"(사유 {reason}). "
              f"{'격리로 추가 피해는 차단했습니다. ' if quarantined else ''}"
              f"죽일지 살릴지 대시보드에서 결정하세요 "
              f"(http://127.0.0.1:5000 → 결정 대기).")

        action = KillAction(
            time.time(), pid, proc_name, cmdline, reason, self.mode.value,
            quarantined=quarantined, terminated=False,
            error="awaiting operator decision (never-kill list)")
        return self._record(action)

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
