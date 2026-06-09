"""
Tests for system-binary masquerade detection (process_watcher)
--------------------------------------------------------------
Ransomware copies itself to %TEMP%\\svchost.exe to inherit never-kill immunity
and trust (T1036.005).  We flag a core system-binary NAME running from outside
System32/SysWOW64.  Paths are derived from the module's own constants so the
test is correct on both Windows and Linux CI.
"""

import os

from detectors import process_watcher as pw
from detectors.process_watcher import ProcessWatcher, ProcSnapshot, is_masquerading
from scoring import ScoringEngine, Severity


# A path guaranteed to be outside System32/SysWOW64 on any platform.
IMPOSTOR_PATH = os.path.normcase("/opt/evil/svchost.exe")
LEGIT_PATH = os.path.join(pw._SYSTEM_DIRS[0], "svchost.exe")


class TestIsMasquerading:
    def test_system_name_outside_system_dir_is_masquerade(self):
        assert is_masquerading("svchost.exe", IMPOSTOR_PATH) is True

    def test_system_name_inside_system_dir_is_clean(self):
        assert is_masquerading("svchost.exe", LEGIT_PATH) is False

    def test_unknown_path_is_not_flagged(self):
        # No image path → fail-safe to clean (never strip trust on a guess).
        assert is_masquerading("svchost.exe", "") is False

    def test_non_system_name_is_not_flagged(self):
        assert is_masquerading("notepad.exe", IMPOSTOR_PATH) is False

    def test_case_insensitive_name(self):
        assert is_masquerading("SVCHOST.EXE", IMPOSTOR_PATH) is True


class TestEmitsMasqueradeSignal:
    def _snap(self, name, exe):
        return ProcSnapshot(pid=4321, ppid=1, name=name, cmdline=f"{name}",
                            user="u", started_at=0.0, exe=exe)

    def test_emits_process_masquerade(self):
        engine = ScoringEngine()
        received = []
        engine.subscribe(lambda s, sc, lv: received.append(s))
        watcher = ProcessWatcher(engine)
        watcher._on_new_process(self._snap("svchost.exe", IMPOSTOR_PATH))
        masq = [s for s in received if s.name == "process_masquerade"]
        assert masq
        assert masq[0].severity == Severity.HIGH
        assert masq[0].metadata["pid"] == 4321

    def test_no_signal_for_legit_system_binary(self):
        engine = ScoringEngine()
        received = []
        engine.subscribe(lambda s, sc, lv: received.append(s))
        watcher = ProcessWatcher(engine)
        watcher._on_new_process(self._snap("svchost.exe", LEGIT_PATH))
        assert not any(s.name == "process_masquerade" for s in received)
