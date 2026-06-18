"""
Tests for responder.ProcessResponder
--------------------------------------
psutil-dependent kill tests are guarded with @pytest.mark.windows.
Pure-logic tests (never-kill list, path verification, mode switching,
allowlist noop, lolbin detection, pid extraction) run on any platform.
"""

import pytest

from responder import (
    ESCALATE_CHILD_NAMES,
    NEVER_KILL,
    PATH_VERIFIED,
    ProcessResponder,
    ResponderMode,
    _TRUSTED_DIRS,
)
from scoring import ScoringEngine, Signal, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine():
    return ScoringEngine()


def _make_responder(engine=None, mode=ResponderMode.OFF, allowlist=None):
    if engine is None:
        engine = _make_engine()
    return ProcessResponder(engine, mode=mode, allowlist=allowlist)


def _make_signal(name="high_entropy_write", severity=Severity.HIGH, metadata=None):
    return Signal(
        detector="test", name=name, weight=10,
        severity=severity, message="test",
        metadata=metadata or {},
    )


class FakeAllowlist:
    """Minimal allowlist stub exposing pid_allowed."""

    def __init__(self, allowed_pids=None):
        self._allowed = set(allowed_pids or [])

    def pid_allowed(self, pid):
        return pid in self._allowed


# ---------------------------------------------------------------------------
# NEVER_KILL set contents
# ---------------------------------------------------------------------------

class TestNeverKillSet:
    def test_lsass_in_never_kill(self):
        assert "lsass.exe" in NEVER_KILL

    def test_csrss_in_never_kill(self):
        assert "csrss.exe" in NEVER_KILL

    def test_explorer_in_never_kill(self):
        assert "explorer.exe" in NEVER_KILL

    def test_svchost_in_never_kill(self):
        assert "svchost.exe" in NEVER_KILL

    def test_winlogon_in_never_kill(self):
        assert "winlogon.exe" in NEVER_KILL

    def test_services_in_never_kill(self):
        assert "services.exe" in NEVER_KILL

    def test_smss_in_never_kill(self):
        assert "smss.exe" in NEVER_KILL

    def test_set_is_all_lowercase(self):
        for name in NEVER_KILL:
            assert name == name.lower(), f"{name!r} is not all lowercase"


# ---------------------------------------------------------------------------
# _is_never_kill
# ---------------------------------------------------------------------------

class TestIsNeverKill:
    def _responder(self):
        return _make_responder()

    def test_lsass_is_always_never_kill(self):
        r = self._responder()
        assert r._is_never_kill("lsass.exe", "") is True

    def test_lsass_with_system32_path_is_never_kill(self):
        r = self._responder()
        import os
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        path = os.path.join(sysroot, "System32", "lsass.exe")
        assert r._is_never_kill("lsass.exe", path) is True

    def test_svchost_impostor_in_temp_is_not_protected(self):
        """svchost.exe from C:\\Temp is not protected (PATH_VERIFIED impostor)."""
        r = self._responder()
        assert r._is_never_kill("svchost.exe", r"C:\Temp\svchost.exe") is False

    def test_svchost_from_system32_is_protected(self):
        import os
        r = self._responder()
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        path = os.path.join(sysroot, "System32", "svchost.exe")
        assert r._is_never_kill("svchost.exe", path) is True

    def test_unknown_process_is_not_never_kill(self):
        r = self._responder()
        assert r._is_never_kill("evilware.exe", "") is False

    def test_name_check_is_case_insensitive(self):
        r = self._responder()
        assert r._is_never_kill("LSASS.EXE", "") is True

    def test_csrss_impostor_in_temp_is_not_protected(self):
        r = self._responder()
        assert r._is_never_kill("csrss.exe", r"C:\Temp\csrss.exe") is False

    def test_python_exe_is_always_protected(self):
        """python.exe is in NEVER_KILL but NOT in PATH_VERIFIED → always protected."""
        r = self._responder()
        assert r._is_never_kill("python.exe", r"C:\Temp\python.exe") is True


# ---------------------------------------------------------------------------
# _path_is_untrusted
# ---------------------------------------------------------------------------

class TestPathIsUntrusted:
    def test_empty_path_is_not_untrusted(self):
        """Empty path → fail safe → not stripped of immunity."""
        assert ProcessResponder._path_is_untrusted("") is False

    def test_system32_path_is_not_untrusted(self):
        import os
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        path = os.path.join(sysroot, "System32", "svchost.exe")
        assert ProcessResponder._path_is_untrusted(path) is False

    def test_temp_path_is_untrusted(self):
        import os
        # A path clearly outside System32/SysWOW64
        path = r"C:\Temp\svchost.exe"
        # normcase it to match the implementation
        assert ProcessResponder._path_is_untrusted(path) is True

    def test_user_appdata_path_is_untrusted(self):
        path = r"C:\Users\victim\AppData\Local\Temp\malware.exe"
        assert ProcessResponder._path_is_untrusted(path) is True

    def test_syswow64_path_is_not_untrusted(self):
        import os
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        path = os.path.join(sysroot, "SysWOW64", "svchost.exe")
        assert ProcessResponder._path_is_untrusted(path) is False


# ---------------------------------------------------------------------------
# set_mode
# ---------------------------------------------------------------------------

class TestSetMode:
    def test_set_mode_quarantine_changes_mode(self):
        r = _make_responder(mode=ResponderMode.OFF)
        r.set_mode(ResponderMode.QUARANTINE)
        assert r.mode == ResponderMode.QUARANTINE

    def test_set_mode_kill_changes_mode(self):
        r = _make_responder(mode=ResponderMode.OFF)
        r.set_mode(ResponderMode.KILL)
        assert r.mode == ResponderMode.KILL

    def test_set_mode_off_changes_mode(self):
        r = _make_responder(mode=ResponderMode.KILL)
        r.set_mode(ResponderMode.OFF)
        assert r.mode == ResponderMode.OFF

    def test_set_mode_returns_new_mode(self):
        r = _make_responder()
        result = r.set_mode(ResponderMode.QUARANTINE)
        assert result == ResponderMode.QUARANTINE

    def test_set_mode_accepts_string_value(self):
        r = _make_responder()
        r.set_mode(ResponderMode("quarantine"))
        assert r.mode == ResponderMode.QUARANTINE


# ---------------------------------------------------------------------------
# Allowlist integration — noop when pid is allowlisted
# ---------------------------------------------------------------------------

class TestAllowlistIntegration:
    def _make_lookup_patcher(self, responder, name, cmdline="", exe=""):
        """Monkeypatch _lookup to return a fixed (name, cmdline, exe_path) tuple."""
        responder._lookup = lambda pid: (name, cmdline, exe)

    def test_allowlisted_pid_produces_noop_action(self):
        """A pid that the allowlist approves is never killed regardless of mode."""
        engine = _make_engine()
        fake_al = FakeAllowlist(allowed_pids={1234})
        # Use KILL mode so that without the allowlist the pid would be killed
        r = _make_responder(engine=engine, mode=ResponderMode.KILL, allowlist=fake_al)
        self._make_lookup_patcher(r, "myapp.exe", "", r"C:\app\myapp.exe")
        action = r._respond_to_pid(1234, "test/high_entropy_write")
        assert action.error is not None
        assert "allowlist" in action.error.lower()

    def test_allowlisted_pid_is_not_terminated(self):
        engine = _make_engine()
        fake_al = FakeAllowlist(allowed_pids={1234})
        r = _make_responder(engine=engine, mode=ResponderMode.KILL, allowlist=fake_al)
        self._make_lookup_patcher(r, "myapp.exe", "", r"C:\app\myapp.exe")
        action = r._respond_to_pid(1234, "test/high_entropy_write")
        assert action.terminated is False

    def test_allowlisted_pid_is_not_quarantined(self):
        engine = _make_engine()
        fake_al = FakeAllowlist(allowed_pids={1234})
        r = _make_responder(engine=engine, mode=ResponderMode.KILL, allowlist=fake_al)
        self._make_lookup_patcher(r, "myapp.exe", "", r"C:\app\myapp.exe")
        action = r._respond_to_pid(1234, "test/high_entropy_write")
        assert action.quarantined is False

    def test_non_allowlisted_pid_in_off_mode_records_action(self):
        engine = _make_engine()
        fake_al = FakeAllowlist(allowed_pids=set())  # nobody allowed
        r = _make_responder(engine=engine, mode=ResponderMode.OFF, allowlist=fake_al)
        self._make_lookup_patcher(r, "badapp.exe", "badapp.exe --encrypt", r"C:\Temp\badapp.exe")
        action = r._respond_to_pid(9999, "test/high_entropy_write")
        # OFF mode records but does not terminate
        assert action.terminated is False
        assert action.error is not None  # "responder mode = off"


# ---------------------------------------------------------------------------
# _is_lolbin_signal
# ---------------------------------------------------------------------------

class TestIsLolbinSignal:
    def test_vssadmin_process_is_lolbin(self):
        r = _make_responder()
        sig = _make_signal(metadata={"process": "vssadmin.exe"})
        assert r._is_lolbin_signal(sig) is True

    def test_powershell_is_lolbin(self):
        r = _make_responder()
        sig = _make_signal(metadata={"process": "powershell.exe"})
        assert r._is_lolbin_signal(sig) is True

    def test_cmd_is_lolbin(self):
        r = _make_responder()
        sig = _make_signal(metadata={"process": "cmd.exe"})
        assert r._is_lolbin_signal(sig) is True

    def test_wmic_is_lolbin(self):
        r = _make_responder()
        sig = _make_signal(metadata={"process": "wmic.exe"})
        assert r._is_lolbin_signal(sig) is True

    def test_regular_process_is_not_lolbin(self):
        r = _make_responder()
        sig = _make_signal(metadata={"process": "notepad.exe"})
        assert r._is_lolbin_signal(sig) is False

    def test_empty_process_metadata_is_not_lolbin(self):
        r = _make_responder()
        sig = _make_signal(metadata={})
        assert r._is_lolbin_signal(sig) is False

    def test_lolbin_check_is_case_insensitive(self):
        r = _make_responder()
        sig = _make_signal(metadata={"process": "VSSADMIN.EXE"})
        assert r._is_lolbin_signal(sig) is True


# ---------------------------------------------------------------------------
# _extract_pid and _extract_parent_pid
# ---------------------------------------------------------------------------

class TestExtractPid:
    def _r(self):
        return _make_responder()

    def test_extract_pid_from_pid_key(self):
        r = self._r()
        sig = _make_signal(metadata={"pid": 42})
        assert r._extract_pid(sig) == 42

    def test_extract_pid_from_ProcessId_key(self):
        r = self._r()
        sig = _make_signal(metadata={"ProcessId": 99})
        assert r._extract_pid(sig) == 99

    def test_extract_pid_from_child_pid_key(self):
        r = self._r()
        sig = _make_signal(metadata={"child_pid": 77})
        assert r._extract_pid(sig) == 77

    def test_extract_pid_returns_none_when_missing(self):
        r = self._r()
        sig = _make_signal(metadata={})
        assert r._extract_pid(sig) is None

    def test_extract_pid_ignores_zero(self):
        r = self._r()
        sig = _make_signal(metadata={"pid": 0})
        assert r._extract_pid(sig) is None

    def test_extract_pid_ignores_negative(self):
        r = self._r()
        sig = _make_signal(metadata={"pid": -1})
        assert r._extract_pid(sig) is None


class TestExtractParentPid:
    def _r(self):
        return _make_responder()

    def test_extract_parent_pid_from_ppid_key(self):
        r = self._r()
        sig = _make_signal(metadata={"ppid": 1000})
        assert r._extract_parent_pid(sig) == 1000

    def test_extract_parent_pid_from_parent_pid_key(self):
        r = self._r()
        sig = _make_signal(metadata={"parent_pid": 2000})
        assert r._extract_parent_pid(sig) == 2000

    def test_extract_parent_pid_from_ParentProcessId_key(self):
        r = self._r()
        sig = _make_signal(metadata={"ParentProcessId": 3000})
        assert r._extract_parent_pid(sig) == 3000

    def test_extract_parent_pid_returns_none_when_missing(self):
        r = self._r()
        sig = _make_signal(metadata={"pid": 100})
        assert r._extract_parent_pid(sig) is None


# ---------------------------------------------------------------------------
# actions() — history recording
# ---------------------------------------------------------------------------

class TestActionsHistory:
    def test_actions_returns_list_of_dicts(self):
        engine = _make_engine()
        r = _make_responder(engine=engine, mode=ResponderMode.OFF)
        r._lookup = lambda pid: ("notepad.exe", "notepad.exe", r"C:\Windows\notepad.exe")
        r._respond_to_pid(12345, "test_reason")
        actions = r.actions()
        assert isinstance(actions, list)
        assert len(actions) == 1
        assert isinstance(actions[0], dict)

    def test_actions_limit_parameter_caps_result(self):
        engine = _make_engine()
        r = _make_responder(engine=engine, mode=ResponderMode.OFF)
        r._lookup = lambda pid: ("app.exe", "app.exe", r"C:\app.exe")
        for i in range(10):
            r._respond_to_pid(i + 1000, "reason")
        assert len(r.actions(limit=3)) == 3


# ---------------------------------------------------------------------------
# Kill clears the killed PID's signals from the live scoring window
# (so the dashboard threat level returns to "safe" on its own — no manual reset)
# ---------------------------------------------------------------------------

class TestKillForgetsScoringSignals:
    def _kill_responder(self, engine):
        r = _make_responder(engine=engine, mode=ResponderMode.KILL)
        r._lookup = lambda pid: ("badapp.exe", "badapp.exe --encrypt",
                                 r"C:\Temp\badapp.exe")
        # Force a successful terminate without touching a real process.
        r._terminate = lambda pid: (True, None)
        return r

    def test_successful_kill_clears_that_pids_signals(self):
        engine = _make_engine()
        # A CRITICAL-weight signal attributed to the offending PID.
        engine.submit(Signal(detector="canary", name="canary_modified",
                             weight=200, severity=Severity.CRITICAL,
                             message="trip", metadata={"pid": 4242}))
        assert engine.current_level() == Severity.CRITICAL

        action = self._kill_responder(engine)._respond_to_pid(4242, "test")
        assert action.terminated is True
        # The killed PID's signals are gone → level decays to safe immediately.
        assert engine.current_level() == Severity.INFO
        assert engine.current_score() == 0

    def test_kill_leaves_other_pids_signals_intact(self):
        engine = _make_engine()
        engine.submit(Signal(detector="canary", name="canary_modified",
                             weight=200, severity=Severity.CRITICAL,
                             message="trip", metadata={"pid": 4242}))
        # A second, still-active attacker.
        engine.submit(Signal(detector="canary", name="canary_modified",
                             weight=200, severity=Severity.CRITICAL,
                             message="trip", metadata={"pid": 7777}))

        self._kill_responder(engine)._respond_to_pid(4242, "test")
        # Only the killed PID was forgotten; the live threat from 7777 stays.
        assert engine.current_level() == Severity.CRITICAL

    def test_failed_kill_does_not_clear_signals(self):
        engine = _make_engine()
        engine.submit(Signal(detector="canary", name="canary_modified",
                             weight=200, severity=Severity.CRITICAL,
                             message="trip", metadata={"pid": 4242}))
        r = _make_responder(engine=engine, mode=ResponderMode.KILL)
        r._lookup = lambda pid: ("badapp.exe", "badapp.exe --encrypt",
                                 r"C:\Temp\badapp.exe")
        r._terminate = lambda pid: (False, "terminate failed")

        action = r._respond_to_pid(4242, "test")
        assert action.terminated is False
        # Kill failed → the threat is NOT over, so signals must remain.
        assert engine.current_level() == Severity.CRITICAL


# ---------------------------------------------------------------------------
# ESCALATE_CHILD_NAMES set
# ---------------------------------------------------------------------------

class TestEscalateChildNames:
    def test_vssadmin_in_escalate_set(self):
        assert "vssadmin.exe" in ESCALATE_CHILD_NAMES

    def test_powershell_in_escalate_set(self):
        assert "powershell.exe" in ESCALATE_CHILD_NAMES

    def test_wbadmin_in_escalate_set(self):
        assert "wbadmin.exe" in ESCALATE_CHILD_NAMES

    def test_bcdedit_in_escalate_set(self):
        assert "bcdedit.exe" in ESCALATE_CHILD_NAMES


# ---------------------------------------------------------------------------
# PATH_VERIFIED set
# ---------------------------------------------------------------------------

class TestPathVerified:
    def test_svchost_in_path_verified(self):
        assert "svchost.exe" in PATH_VERIFIED

    def test_csrss_in_path_verified(self):
        assert "csrss.exe" in PATH_VERIFIED

    def test_lsass_in_path_verified(self):
        assert "lsass.exe" in PATH_VERIFIED

    def test_python_not_in_path_verified(self):
        """python.exe is in NEVER_KILL but not PATH_VERIFIED → no path check needed."""
        assert "python.exe" not in PATH_VERIFIED


# ---------------------------------------------------------------------------
# Windows-only kill tests (psutil required)
# ---------------------------------------------------------------------------

@pytest.mark.windows
class TestKillWithPsutil:
    def test_kill_nonexistent_pid_does_not_raise(self):
        psutil = pytest.importorskip("psutil")
        engine = _make_engine()
        r = ProcessResponder(engine, mode=ResponderMode.KILL)
        # PID 999999 almost certainly does not exist
        action = r._respond_to_pid(999999, "test")
        # Should record an action (error or not) without raising
        assert action is not None


# ---------------------------------------------------------------------------
# Action-time forensic context capture (보고서 자기모순 방지 — RustyStealer PDF)
# ---------------------------------------------------------------------------

class FakeMinifilter:
    def quarantine_pid(self, pid):
        return True


class TestActionTimeContext:
    def test_killaction_new_fields_have_defaults(self):
        from responder import KillAction
        a = KillAction(1.0, 2, "x.exe", "x.exe", "r", "kill",
                       quarantined=False, terminated=True)
        d = a.to_dict()
        assert d["exe_sha256"] == ""
        assert d["score_at_action"] is None
        assert d["trigger_signal"] is None

    def test_hash_exe_handles_missing_path(self):
        from responder import _hash_exe
        assert _hash_exe("") == ""
        assert _hash_exe("/nonexistent/zzz") == ""

    def test_dispatch_captures_trigger_score_level(self):
        engine = _make_engine()
        actions = []
        resp = ProcessResponder(engine, mode=ResponderMode.QUARANTINE,
                                minifilter=FakeMinifilter(),
                                on_action=actions.append)
        resp.attach()
        # corroborated precise-kill 정책: 단독 HIGH 는 관찰만 하므로,
        # 독립적인 암호화 정황(pid 없음)을 먼저 깔아 행동을 성립시킨다.
        engine.submit(_make_signal("magic_bytes_lost",
                                   metadata={"path": "a.docx"}))
        sig = _make_signal("kernel_rename_burst", metadata={"pid": 99999})
        engine.submit(sig)
        assert actions, "quarantine action should have been reported"
        a = actions[0]
        assert a.trigger_signal is not None
        assert a.trigger_signal["name"] == "kernel_rename_burst"
        assert a.detect_ts == sig.timestamp
        assert a.score_at_action == 20      # corroboration 10 + trigger 10
        assert a.level_at_action == "INFO"

    def test_forget_pid_after_terminated_kill(self):
        """44ca918 의 자동 회복(1ee4263 에서 회귀)이 다시 동작해야 한다."""
        engine = _make_engine()
        resp = ProcessResponder(engine, mode=ResponderMode.KILL,
                                minifilter=FakeMinifilter())
        resp.attach()
        # corroboration (pid 없음 → forget_pid 대상 아님)
        engine.submit(_make_signal("magic_bytes_lost",
                                   metadata={"path": "a.docx"}))
        # 존재하지 않는 pid → psutil.NoSuchProcess → terminated=True 처리
        engine.submit(_make_signal("kernel_rename_burst",
                                   metadata={"pid": 99999}))
        remaining = [s for s in engine.recent_signals(limit=50)
                     if (s.metadata or {}).get("pid") == 99999]
        assert remaining == [], "killed pid's signals must leave the window"


# ---------------------------------------------------------------------------
# Corroborated precise-kill policy (보고서 5-2)
#
# Regression guard: this policy was introduced in ab743d1 and accidentally
# reverted in 1ee4263 (the score-wide sweep came back).  These tests pin the
# intended behaviour so a refactor can't silently undo it again:
#   - CRITICAL signal naming a PID  → act immediately
#   - HIGH signal                   → act only with corroboration
#       (encryption activity in the window, or a 2nd distinct detector
#        naming the same PID); otherwise record "observed only"
#   - no score-wide sweep: aggregate CRITICAL alone kills nobody
# ---------------------------------------------------------------------------

class TestCorroboratedKillPolicy:
    def _armed_responder(self, engine, killed):
        r = _make_responder(engine=engine, mode=ResponderMode.KILL)
        r._lookup = lambda pid: ("badapp.exe", "badapp.exe --encrypt",
                                 r"C:\Temp\badapp.exe")

        def fake_terminate(pid):
            killed.append(pid)
            return (True, None)

        r._terminate = fake_terminate
        return r

    def test_uncorroborated_high_is_observed_only(self):
        engine = _make_engine()
        killed = []
        r = self._armed_responder(engine, killed)
        sig = Signal(detector="process_watcher", name="process_masquerade",
                     weight=60, severity=Severity.HIGH, message="m",
                     metadata={"pid": 4242})
        engine.submit(sig)
        r._dispatch(sig, engine.current_score(), engine.current_level())

        assert killed == []
        last = r.actions(limit=1)[-1]
        assert last["terminated"] is False
        assert "observed only" in (last["error"] or "")

    def test_critical_signal_acts_alone(self):
        engine = _make_engine()
        killed = []
        r = self._armed_responder(engine, killed)
        sig = Signal(detector="process_cmdline", name="vssadmin_delete_shadows",
                     weight=70, severity=Severity.CRITICAL, message="m",
                     metadata={"pid": 4242})
        engine.submit(sig)
        r._dispatch(sig, engine.current_score(), engine.current_level())
        assert 4242 in killed

    def test_high_with_encryption_activity_acts(self):
        engine = _make_engine()
        killed = []
        r = self._armed_responder(engine, killed)
        # Independent ground-truth encryption evidence in the window.
        engine.submit(Signal(detector="mass_io", name="magic_bytes_lost",
                             weight=12, severity=Severity.HIGH, message="m",
                             metadata={"path": "a.docx"}))
        sig = Signal(detector="process_watcher", name="process_masquerade",
                     weight=60, severity=Severity.HIGH, message="m",
                     metadata={"pid": 4242})
        engine.submit(sig)
        r._dispatch(sig, engine.current_score(), engine.current_level())
        assert 4242 in killed

    def test_high_with_second_detector_acts(self):
        engine = _make_engine()
        killed = []
        r = self._armed_responder(engine, killed)
        # Two distinct detectors independently name the same PID.
        engine.submit(Signal(detector="process_watcher", name="child_fanout",
                             weight=40, severity=Severity.HIGH, message="m",
                             metadata={"pid": 4242}))
        sig = Signal(detector="minifilter", name="kernel_rename_burst",
                     weight=40, severity=Severity.HIGH, message="m",
                     metadata={"pid": 4242})
        engine.submit(sig)
        r._dispatch(sig, engine.current_score(), engine.current_level())
        assert 4242 in killed

    def test_no_score_wide_sweep(self):
        """Aggregate CRITICAL score must not kill PIDs that only emitted
        low-severity signals (the old sweep did exactly that)."""
        engine = _make_engine()
        killed = []
        r = self._armed_responder(engine, killed)
        # Pump the aggregate score over the CRITICAL threshold with
        # non-encryption sabotage signals from one PID...
        for _ in range(3):
            engine.submit(Signal(detector="registry_kernel",
                                 name="defender_service_tamper",
                                 weight=70, severity=Severity.CRITICAL,
                                 message="m", metadata={"pid": 1111}))
        # ...then a bystander PID emits a harmless LOW signal.
        low = Signal(detector="minifilter", name="file_delete",
                     weight=3, severity=Severity.LOW, message="m",
                     metadata={"pid": 2222})
        engine.submit(low)
        r._dispatch(low, engine.current_score(), engine.current_level())
        assert 2222 not in killed

    def test_dispatch_without_pid_does_nothing(self):
        engine = _make_engine()
        killed = []
        r = self._armed_responder(engine, killed)
        sig = Signal(detector="canary", name="canary_modified",
                     weight=80, severity=Severity.CRITICAL, message="m",
                     metadata={})   # no pid → nothing to act on
        engine.submit(sig)
        r._dispatch(sig, engine.current_score(), engine.current_level())
        assert killed == []
        assert r.actions(limit=5) == []
