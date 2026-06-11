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

Trigger policy (corroborated precise kill — 보고서 5-2 / WIKI §6):

  The responder reacts ONLY to signals that name a PID — there is no
  "score crossed CRITICAL, sweep every PID in the window" path.  The
  sweep was removed on purpose: one false-positive heuristic plus an
  unrelated benign burst could push the aggregate score over the line
  and massacre every bystander PID at once, relying solely on the
  never-kill list.

  - CRITICAL signal (canary trip, VSS deletion, note spread …) is
    high-confidence on its own → act immediately.
  - HIGH signal is a heuristic → requires corroboration before we act:
    real encryption/destruction activity in the window (via
    ``ScoringEngine.has_encryption_activity``), or a second distinct
    detector independently naming the same PID.  An uncorroborated
    HIGH is recorded as "observed only" so the operator still sees it
    on the dashboard, but nothing is killed.

Termination strategy on Windows:

  - ``psutil.Process(pid).kill()`` first (uses TerminateProcess under the
    hood, no signal semantics).
  - On failure, raw ``OpenProcess(PROCESS_TERMINATE) + TerminateProcess``
    via ctypes so we are independent of psutil's caching.
"""

from __future__ import annotations

import hashlib
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

from scoring import ScoringEngine, Signal, Severity


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
    # ---- 행동 시점 포렌식 컨텍스트 (보고서 5.x) -------------------------
    # 보고서는 이 캡처를 1차 근거로 쓴다.  생성 시점에 라이브 엔진을 재조회
    # 하면 120초 윈도우 퇴거 때문에 "차단은 했는데 근거 신호·점수가 0" 인
    # 자기모순 보고서가 나올 수 있다(실제 사례: RustyStealer 인시던트 PDF).
    # 모든 필드는 기본값을 가져 기존 생성자 호출과 호환된다.
    exe_path: str = ""              # 실행 이미지 경로 (psutil, best-effort)
    exe_sha256: str = ""            # 이미지 SHA-256 (위협 인텔/VT 조회용)
    username: str = ""              # 프로세스 소유 계정
    ppid: Optional[int] = None      # 부모 PID (감염 경로 추적)
    parent_name: str = ""           # 부모 프로세스 이름
    score_at_action: Optional[int] = None   # 차단 시점 누적 점수
    level_at_action: str = ""               # 차단 시점 위협 수준
    trigger_signal: Optional[dict] = None   # 차단을 유발한 신호(Signal.to_dict)
    detect_ts: Optional[float] = None       # 트리거 신호 발생 시각

    def to_dict(self) -> dict:
        return asdict(self)


# 이미지 해시 상한: 이보다 큰 파일은 해시하지 않는다 (대응 경로 지연 방지).
_HASH_MAX_BYTES = 64 * 1024 * 1024


def _hash_exe(path: str) -> str:
    """실행 이미지의 SHA-256 (best-effort).

    실패(경로 없음/접근 거부/크기 초과)는 빈 문자열 — 대응을 막지 않는다.
    차단 직전·직후의 이미지 파일은 보통 디스크에 남아 있으므로 여기서 한 번
    계산해 두면 IR 가 VirusTotal/위협 인텔에 바로 조회할 수 있다.
    """
    if not path:
        return ""
    # UNC/네트워크 경로는 열기만 해도 수십 초를 매달릴 수 있다(SMB 타임아웃).
    # 이 함수는 탐지 펌프 스레드에서 돌므로, 로컬 디스크 이미지가 아니면
    # 해시를 포기한다 — 보고서에는 '확인 불가'로 남는다.
    if path.startswith(("\\\\", "//")):
        return ""
    try:
        # 크기 상한은 읽으면서 검사한다 — getsize 선검사는 TOCTOU 틈과
        # 불필요한 syscall 만 더한다.
        h = hashlib.sha256()
        read = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                read += len(chunk)
                if read > _HASH_MAX_BYTES:
                    return ""
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


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
                 on_action: Optional[Callable[[KillAction], None]] = None,
                 allowlist=None):
        self.engine = engine
        self.mode = mode
        self.minifilter = minifilter
        self._on_action = on_action
        # Operator allowlist (allowlist.Allowlist | None).  A PID whose verified
        # image is allowlisted is treated as never-kill — a trusted third-party
        # app (backup/sync/build tooling) the admin explicitly exempted must not
        # be terminated even if its bulk file activity scores.  Path-prefix
        # entries also defeat name spoofing.  Left None → no allowlist behaviour.
        self.allowlist = allowlist
        self._lock = threading.Lock()
        self._actions: List[KillAction] = []
        self._already_killed: Set[int] = set()
        self._already_quarantined: Set[int] = set()
        self._own_pid = os.getpid()

    # ---------------------------------------------------------- public API

    def attach(self) -> None:
        """Subscribe to the scoring engine.  Idempotent."""
        self.engine.subscribe(self._dispatch)

    def set_mode(self, mode: ResponderMode) -> ResponderMode:
        """Change the responder mode at runtime (admin control).

        Returns the new mode.  Switching to a less aggressive mode does not
        revive already-terminated processes; switching to a more aggressive
        one only affects *future* signals — we never retro-kill on a mode bump.
        """
        if not isinstance(mode, ResponderMode):
            mode = ResponderMode(str(mode))
        with self._lock:
            self.mode = mode
        print(f"[responder] mode changed to {mode.value}")
        return mode

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
        # PID-scoped reaction ONLY — a signal must name the PID it accuses.
        # (점수 기반 전체 sweep 은 의도적으로 없다: 오탐 1건 + 무관한 정상
        # burst 가 합산 점수만 넘겨도 윈도우의 모든 PID 가 종료되는 참사를
        # never-kill 목록 하나에 기대 막아야 했기 때문.  ab743d1 참조.)
        pid = self._extract_pid(sig)
        if not pid or sig.severity not in (Severity.HIGH, Severity.CRITICAL):
            return

        # 탐지 시점에 신호가 들고 온 프로세스 이름/명령줄.  일회성 도구
        # (vssadmin/wmic 등)는 차단 시점엔 이미 종료돼 psutil 조회가
        # 실패하므로, 이 값들을 표시용 폴백으로 넘긴다.
        meta = sig.metadata or {}
        hint = meta.get("process") or ""
        cmd_hint = meta.get("cmdline") or ""
        reason = f"{sig.detector}/{sig.name}"

        if not self._is_confident(pid, sig):
            # Suspicious but uncorroborated — record intent, take no action.
            # The dashboard still shows it so an operator can judge.
            self._record_observed(pid, reason,
                                  name_hint=hint, cmd_hint=cmd_hint)
            return

        # trigger/score/level: 행동 시점 포렌식 컨텍스트 — 보고서가 라이브
        # 엔진을 재조회하지 않고 이 캡처를 1차 근거로 쓴다 (120초 윈도우
        # 퇴거로 인한 "차단했는데 근거 0" 자기모순 방지).
        self._respond_to_pid(pid, reason, name_hint=hint, cmd_hint=cmd_hint,
                             trigger=sig, score=score, level=level)

        # Parent escalation: ransomware drives destruction through
        # LOLBins/tools (vssadmin, powershell, cmd, wbadmin, ...) that
        # are either transient or on the never-kill list.  Killing the
        # tool is too late or refused, so also terminate the PARENT that
        # issued the command — that is the actual malware body.
        ppid = self._extract_parent_pid(sig)
        if ppid and ppid != pid and self._is_lolbin_signal(sig):
            self._respond_to_pid(
                ppid, f"{reason} (parent of pid={pid})",
                trigger=sig, score=score, level=level)

    def _is_confident(self, pid: int, sig: Signal) -> bool:
        """Decide whether the evidence justifies acting on ``pid``.

        CRITICAL signals (canary trip, VSS deletion, note spread …) act on
        their own — they are either ground-truth encryption evidence or
        pre-encryption sabotage no benign process performs.  A HIGH signal
        is a heuristic and needs corroboration: real encryption activity
        in the window (excluding the triggering signal itself), or a
        second distinct detector independently naming the same PID.
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

    # ---------------------------------------------------- core kill logic

    def _respond_to_pid(self, pid: int, reason: str,
                        name_hint: str = "", cmd_hint: str = "",
                        trigger: Optional[Signal] = None,
                        score: Optional[int] = None,
                        level: Optional[Severity] = None) -> KillAction:
        if pid == self._own_pid:
            return self._noop(pid, reason, "refusing to kill self")

        proc_name, cmdline, exe_path = self._lookup(pid)
        # 행동 시점 포렌식 캡처: 프로세스가 살아 있는 지금이 마지막 기회다.
        # (종료 후에는 username/ppid 조회가 실패하고, 일회성 도구는 이미지
        # 경로조차 못 얻는다.)  보고서가 라이브 엔진 대신 이 값을 쓴다.
        # 이미지 SHA-256 은 여기서 계산하지 *않는다* — 최대 64MB 디스크 읽기를
        # 차단 앞에 두면 그 시간만큼 암호화가 진행된다.  경로 문자열만 캡처해
        # 두고, 격리/종료가 끝난 뒤 해시한다(이미지 파일은 디스크에 남는다).
        username, ppid, parent_name = self._proc_owner(pid)
        ctx = {
            "exe_path": exe_path,
            "exe_sha256": "",
            "username": username,
            "ppid": ppid,
            "parent_name": parent_name,
            "score_at_action": score,
            "level_at_action": level.value if level is not None else "",
            "trigger_signal": trigger.to_dict() if trigger is not None else None,
            "detect_ts": trigger.timestamp if trigger is not None else None,
        }

        # never-kill 판정은 *조회된* 이름/경로로만 한다(힌트로 판정을 바꾸지
        # 않음).  판정 후, 표시용 이름/명령줄이 비어 있을 때만 탐지 시점
        # 힌트로 채워 보고서에 'unknown'·'확인 불가' 대신 실제 도구 이름과
        # 명령줄이 남게 한다.
        if self._is_never_kill(proc_name, exe_path):
            return self._noop(pid, reason,
                              f"{proc_name!r} is on the never-kill list")
        # Operator allowlist: a verified-image match means the admin explicitly
        # trusts this app.  Check by PID (verifies the on-disk image, so a
        # %TEMP%\veeamagent.exe impostor against a path-prefix entry won't pass).
        if self.allowlist is not None:
            try:
                if self.allowlist.pid_allowed(pid):
                    return self._noop(pid, reason,
                                      f"{proc_name or pid!r} is on the operator allowlist")
            except Exception as e:
                print(f"[responder] allowlist check error: {e}")
        if not proc_name and name_hint:
            proc_name = name_hint
        if not cmdline and cmd_hint:
            cmdline = cmd_hint

        with self._lock:
            already_killed = pid in self._already_killed
            already_quar   = pid in self._already_quarantined

        # Dedupe: if we've already done everything this mode calls for on
        # this PID, return silently WITHOUT recording another action or
        # writing a duplicate incident report.  An active ransomware PID
        # re-fires HIGH/CRITICAL signals on every burst tick; without this
        # guard a single run produces thousands of repeat reports.
        fully_handled = (
            (self.mode == ResponderMode.KILL and already_killed) or
            (self.mode == ResponderMode.QUARANTINE and already_quar)
        )
        if fully_handled:
            return KillAction(time.time(), pid, proc_name, cmdline, reason,
                              self.mode.value, quarantined=already_quar,
                              terminated=already_killed,
                              error="already handled", **ctx)

        quarantined = already_quar
        terminated  = already_killed
        error: Optional[str] = None

        if self.mode == ResponderMode.OFF:
            # OFF 모드는 차단하지 않으므로 지연 걱정 없이 지금 해시해도 된다.
            ctx["exe_sha256"] = _hash_exe(exe_path)
            action = KillAction(time.time(), pid, proc_name, cmdline, reason,
                                self.mode.value, quarantined=False,
                                terminated=False,
                                error="responder mode = off", **ctx)
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

        killed_now = False
        if self.mode == ResponderMode.KILL and not already_killed:
            ok, err = self._terminate(pid)
            terminated = ok
            if not ok:
                error = err if error is None else f"{error}; {err}"
            else:
                with self._lock:
                    self._already_killed.add(pid)
                killed_now = True

        if killed_now:
            # 이 PID 가 가하던 위협은 종료됐다.  라이브 점수 윈도우에서 그 PID 의
            # 시그널을 즉시 제거해, 모든 활성 공격자가 사라지면 대시보드 위협
            # 등급이 운영자의 수동 초기화 없이도 스스로 "안전" 으로 복귀하게 한다.
            # 이 호출이 없으면 종료된 PID 의 시그널이 120초 윈도우가 만료될 때까지
            # 점수를 CRITICAL 로 유지해 대시보드가 "위험" 에 고착된다.
            # (회귀 주의: 1ee4263 에서 이 호출이 실수로 빠진 적이 있다.)
            # _record() 전에 호출해도 보고서 근거는 잃지 않는다 — 보고서의
            # 1차 근거는 위의 행동 시점 캡처(ctx)이지 라이브 엔진이 아니다.
            try:
                self.engine.forget_pid(pid)
            except Exception as e:
                print(f"[responder] forget_pid failed: {e}")

        # 위협이 멈춘 *뒤에* 이미지를 해시한다 — 차단 경로에 디스크 I/O 를
        # 더하지 않으면서, 보고서·사이드카에는 해시가 담기게 (_record 이전).
        ctx["exe_sha256"] = _hash_exe(exe_path)
        action = KillAction(time.time(), pid, proc_name, cmdline, reason,
                            self.mode.value, quarantined=quarantined,
                            terminated=terminated, error=error, **ctx)
        return self._record(action)

    def _noop(self, pid: int, reason: str, why: str) -> KillAction:
        action = KillAction(time.time(), pid, "", "", reason,
                            self.mode.value, quarantined=False,
                            terminated=False, error=why)
        return self._record(action)

    def _record_observed(self, pid: int, reason: str,
                         name_hint: str = "", cmd_hint: str = "") -> KillAction:
        """A suspicious-but-uncorroborated HIGH signal: record, don't act."""
        proc_name, cmdline, _exe = self._lookup(pid)
        action = KillAction(time.time(), pid, proc_name or name_hint,
                            cmdline or cmd_hint, reason,
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

    def _proc_owner(self, pid: int) -> tuple[str, Optional[int], str]:
        """``(username, ppid, parent_name)`` — 감염 경로 추적용 (best-effort).

        각 조회는 독립적으로 실패할 수 있으므로(AccessDenied, 프로세스 소멸)
        하나가 실패해도 나머지는 채운다.  실패 값은 ""/None.
        """
        if not HAS_PSUTIL:
            return ("", None, "")
        try:
            p = psutil.Process(pid)
        except Exception:
            return ("", None, "")
        username = ""
        ppid: Optional[int] = None
        parent_name = ""
        try:
            username = p.username() or ""
        except Exception:
            pass
        # p.parent() 는 부모의 생성 시각까지 대조해 PID 재사용을 걸러낸다 —
        # ppid 숫자로 psutil.Process(ppid) 를 새로 여는 것보다 안전하다
        # (그 사이 부모가 죽고 PID 가 재활용되면 엉뚱한 프로세스를 보고한다).
        try:
            parent = p.parent()
            if parent is not None:
                ppid = parent.pid
                try:
                    parent_name = parent.name() or ""
                except Exception:
                    pass
            else:
                ppid = p.ppid() or None
        except Exception:
            try:
                ppid = p.ppid() or None
            except Exception:
                pass
        return (username, ppid, parent_name)

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
