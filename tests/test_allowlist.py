"""
Tests for allowlist.Allowlist
------------------------------
Uses tmp_path; autoload=False throughout so no disk state bleeds across tests.
psutil-dependent paths are guarded with @pytest.mark.windows.
"""

import json
import os

import pytest

from allowlist import (
    Allowlist,
    AllowEntry,
    _normalize,
    _NEVER_EXEMPT_SIGNALS,
    combine_trust,
)
from scoring import Signal, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_allowlist(tmp_path, entries=None):
    path = str(tmp_path / "allowlist.json")
    al = Allowlist(path=path, autoload=False)
    if entries:
        for value, kind in entries:
            al.add(value, kind=kind)
    return al


def _make_signal(name="high_entropy_write", pid=None):
    meta = {}
    if pid is not None:
        meta["pid"] = pid
    return Signal(
        detector="test", name=name, weight=10,
        severity=Severity.HIGH, message="test", metadata=meta,
    )


# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------

class TestNormalize:
    def test_backslash_path_becomes_path_kind(self):
        entry = _normalize("", r"C:\Program Files\Veeam\agent.exe")
        assert entry.kind == "path"

    def test_c_colon_prefix_becomes_path_kind(self):
        entry = _normalize("", r"C:\Backup\backup.exe")
        assert entry.kind == "path"

    def test_forward_slash_path_becomes_path_kind(self):
        entry = _normalize("", "/usr/bin/backup")
        assert entry.kind == "path"

    def test_path_value_is_normcase(self):
        raw = r"C:\Program Files\VEEAM\Agent.exe"
        entry = _normalize("", raw)
        assert entry.value == os.path.normcase(raw)

    def test_bare_name_becomes_name_kind(self):
        entry = _normalize("", "veeamagent.exe")
        assert entry.kind == "name"

    def test_bare_name_value_is_lowercased(self):
        entry = _normalize("", "VeeamAgent.EXE")
        assert entry.value == "veeamagent.exe"

    def test_bare_name_basename_only(self):
        # When kind is explicitly "name", strip directory part
        entry = _normalize("name", "agent.exe")
        assert entry.value == "agent.exe"

    def test_explicit_kind_path_forces_path(self):
        entry = _normalize("path", "veeamagent.exe")
        assert entry.kind == "path"

    def test_empty_value_raises_valueerror(self):
        with pytest.raises(ValueError):
            _normalize("", "")

    def test_whitespace_only_value_raises_valueerror(self):
        with pytest.raises(ValueError):
            _normalize("", "   ")


# ---------------------------------------------------------------------------
# AllowEntry.matches
# ---------------------------------------------------------------------------

class TestAllowEntryMatches:
    def test_name_entry_matches_exact_lowercase_name(self):
        e = AllowEntry(kind="name", value="veeamagent.exe")
        assert e.matches("veeamagent.exe", "") is True

    def test_name_entry_does_not_match_different_name(self):
        e = AllowEntry(kind="name", value="backup.exe")
        assert e.matches("other.exe", "") is False

    def test_path_entry_matches_path_with_prefix(self):
        prefix = os.path.normcase(r"C:\Program Files\Veeam\\")
        e = AllowEntry(kind="path", value=prefix)
        path_lower = os.path.normcase(r"C:\Program Files\Veeam\agent.exe")
        assert e.matches("", path_lower) is True

    def test_path_entry_does_not_match_different_prefix(self):
        e = AllowEntry(kind="path", value=os.path.normcase(r"C:\Trusted\\"))
        path_lower = os.path.normcase(r"C:\Temp\evil.exe")
        assert e.matches("", path_lower) is False

    def test_name_entry_with_empty_name_does_not_match(self):
        e = AllowEntry(kind="name", value="backup.exe")
        assert e.matches("", "") is False


# ---------------------------------------------------------------------------
# Allowlist CRUD — add / remove / clear / dedupe
# ---------------------------------------------------------------------------

class TestAllowlistCrud:
    def test_add_entry_appears_in_entries(self, tmp_path):
        al = _make_allowlist(tmp_path)
        al.add("veeamagent.exe")
        entries = al.entries()
        assert any(e["value"] == "veeamagent.exe" for e in entries)

    def test_duplicate_add_is_ignored(self, tmp_path):
        al = _make_allowlist(tmp_path)
        al.add("veeamagent.exe")
        al.add("veeamagent.exe")
        assert len(al.entries()) == 1

    def test_remove_existing_entry_returns_true(self, tmp_path):
        al = _make_allowlist(tmp_path)
        al.add("veeamagent.exe")
        result = al.remove("veeamagent.exe")
        assert result is True
        assert len(al.entries()) == 0

    def test_remove_nonexistent_entry_returns_false(self, tmp_path):
        al = _make_allowlist(tmp_path)
        assert al.remove("nothere.exe") is False

    def test_clear_removes_all_entries(self, tmp_path):
        al = _make_allowlist(tmp_path)
        al.add("app1.exe")
        al.add("app2.exe")
        al.clear()
        assert al.entries() == []


# ---------------------------------------------------------------------------
# JSON persistence
# ---------------------------------------------------------------------------

class TestJsonPersistence:
    def test_saved_entries_reload_correctly(self, tmp_path):
        path = str(tmp_path / "al.json")
        al1 = Allowlist(path=path, autoload=False)
        al1.add("veeamagent.exe", note="test note")
        al1.add(r"C:\Program Files\Backup\\", kind="path")

        al2 = Allowlist(path=path, autoload=True)
        entries = al2.entries()
        values = [e["value"] for e in entries]
        assert "veeamagent.exe" in values
        assert any("program files" in v.lower() for v in values)

    def test_saved_entries_preserve_kind(self, tmp_path):
        path = str(tmp_path / "al.json")
        al1 = Allowlist(path=path, autoload=False)
        al1.add(r"C:\Backup\\", kind="path")
        al2 = Allowlist(path=path, autoload=True)
        entry = al2.entries()[0]
        assert entry["kind"] == "path"

    def test_load_from_missing_file_is_silent(self, tmp_path):
        path = str(tmp_path / "nonexistent.json")
        al = Allowlist(path=path, autoload=True)
        assert al.entries() == []

    def test_load_from_corrupt_json_is_silent(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("NOT JSON {{{{", encoding="utf-8")
        al = Allowlist(path=str(path), autoload=True)
        assert al.entries() == []


# ---------------------------------------------------------------------------
# matches (name and path matching without psutil)
# ---------------------------------------------------------------------------

class TestMatches:
    def test_matches_by_name(self, tmp_path):
        al = _make_allowlist(tmp_path)
        al.add("backup.exe")
        assert al.matches("backup.exe", "") is True

    def test_matches_is_case_insensitive_for_name(self, tmp_path):
        al = _make_allowlist(tmp_path)
        al.add("backup.exe")
        assert al.matches("BACKUP.EXE", "") is True

    def test_does_not_match_different_name(self, tmp_path):
        al = _make_allowlist(tmp_path)
        al.add("backup.exe")
        assert al.matches("evil.exe", "") is False

    def test_path_entry_matches_path_prefix(self, tmp_path):
        al = _make_allowlist(tmp_path)
        al.add(r"C:\Program Files\Veeam\\", kind="path")
        # Provide the full path as exe_path
        exe = r"C:\Program Files\Veeam\agent.exe"
        assert al.matches("agent.exe", exe) is True

    def test_path_entry_defeats_name_spoof(self, tmp_path):
        """A path-prefix entry will NOT match a name-alike from a different path."""
        al = _make_allowlist(tmp_path)
        al.add(r"C:\Program Files\Veeam\\", kind="path")
        # Same name but different (untrusted) path
        assert al.matches("agent.exe", r"C:\Temp\agent.exe") is False

    def test_empty_allowlist_never_matches(self, tmp_path):
        al = _make_allowlist(tmp_path)
        assert al.matches("anything.exe", r"C:\foo\anything.exe") is False


# ---------------------------------------------------------------------------
# signal_exempt — never-exempt signals are always False
# ---------------------------------------------------------------------------

class TestSignalExempt:
    def test_canary_modified_is_in_never_exempt_set(self):
        assert "canary_modified" in _NEVER_EXEMPT_SIGNALS

    def test_canary_deleted_is_in_never_exempt_set(self):
        assert "canary_deleted" in _NEVER_EXEMPT_SIGNALS

    def test_ransom_note_spread_is_in_never_exempt_set(self):
        assert "ransom_note_spread" in _NEVER_EXEMPT_SIGNALS

    def test_signal_named_canary_modified_returns_false_regardless_of_pid(self, tmp_path):
        """canary_modified is never exempted — even before psutil is checked."""
        al = _make_allowlist(tmp_path)
        # Add a name entry that would normally allow any process
        al.add("someprocess.exe")
        sig = _make_signal(name="canary_modified", pid=None)
        # Signal name gate fires before pid lookup; must return False
        assert al.signal_exempt(sig) is False

    def test_non_never_exempt_signal_without_pid_returns_false(self, tmp_path):
        """Without a valid pid, pid_allowed → False → signal not exempt."""
        al = _make_allowlist(tmp_path)
        al.add("someprocess.exe")
        sig = _make_signal(name="high_entropy_write", pid=None)
        # No pid means pid_allowed returns False → signal_exempt is False
        assert al.signal_exempt(sig) is False

    @pytest.mark.windows
    def test_signal_exempt_with_pid_requires_psutil(self, tmp_path):
        """pid_allowed with a real pid only works on Windows with psutil."""
        pytest.importorskip("psutil")
        al = _make_allowlist(tmp_path)
        sig = _make_signal(name="high_entropy_write", pid=1)
        # Just verify it doesn't crash; result depends on running process
        result = al.signal_exempt(sig)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# combine_trust — OR semantics, exception swallowing
# ---------------------------------------------------------------------------

class TestCombineTrust:
    def _make_sig(self):
        return _make_signal()

    def test_both_false_returns_false(self):
        combined = combine_trust(lambda s: False, lambda s: False)
        assert combined(self._make_sig()) is False

    def test_first_true_returns_true(self):
        combined = combine_trust(lambda s: True, lambda s: False)
        assert combined(self._make_sig()) is True

    def test_second_true_returns_true(self):
        combined = combine_trust(lambda s: False, lambda s: True)
        assert combined(self._make_sig()) is True

    def test_both_true_returns_true(self):
        combined = combine_trust(lambda s: True, lambda s: True)
        assert combined(self._make_sig()) is True

    def test_exception_in_classifier_is_swallowed(self):
        def exploding(sig):
            raise RuntimeError("boom")

        combined = combine_trust(exploding, lambda s: False)
        # Must not propagate; should return False
        assert combined(self._make_sig()) is False

    def test_exception_in_first_does_not_prevent_second_from_running(self):
        def exploding(sig):
            raise RuntimeError("boom")

        combined = combine_trust(exploding, lambda s: True)
        # Second classifier returns True despite first exploding
        assert combined(self._make_sig()) is True

    def test_none_classifiers_are_filtered_out(self):
        combined = combine_trust(None, lambda s: True)
        assert combined(self._make_sig()) is True

    def test_all_none_classifiers_returns_false(self):
        combined = combine_trust(None, None)
        assert combined(self._make_sig()) is False

    def test_single_classifier_works(self):
        combined = combine_trust(lambda s: True)
        assert combined(self._make_sig()) is True
