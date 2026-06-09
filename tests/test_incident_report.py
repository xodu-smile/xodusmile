"""
Tests for pure helper functions in incident_report.
------------------------------------------------------
No Flask, no psutil, no watchdog required.
Tests: summarize_damage, _attack_lines, _signame_from_reason,
       is_ransom_note (via is_ransom_note_name from ransom_note),
       _HIGH_ENTROPY_SKIP_EXTS, and supporting helpers.
"""

import pytest

from scoring import Signal, Severity
import incident_report
from incident_report import (
    _HIGH_ENTROPY_SKIP_EXTS,
    _attack_lines,
    _signame_from_reason,
    summarize_damage,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig(name, weight=10, severity=Severity.HIGH, metadata=None):
    return Signal(
        detector="test", name=name, weight=weight,
        severity=severity, message="test signal",
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# _signame_from_reason
# ---------------------------------------------------------------------------

class TestSigNameFromReason:
    def test_extracts_signal_name_from_detector_slash_signal(self):
        result = _signame_from_reason(
            "process_cmdline/vssadmin_delete_shadows [correlated]"
        )
        assert result == "vssadmin_delete_shadows"

    def test_extracts_signal_name_without_correlated_suffix(self):
        result = _signame_from_reason("mass_io/high_entropy_write")
        assert result == "high_entropy_write"

    def test_returns_empty_string_for_none(self):
        assert _signame_from_reason(None) == ""

    def test_returns_empty_string_for_empty_string(self):
        assert _signame_from_reason("") == ""

    def test_reason_without_slash_returns_whole_first_token(self):
        # No slash → parts[0] is the whole string (or first token)
        result = _signame_from_reason("score_critical_sweep")
        assert result == "score_critical_sweep"

    def test_multiple_brackets_only_first_token_returned(self):
        result = _signame_from_reason(
            "minifilter/kernel_write_burst [correlated] [extra]"
        )
        assert result == "kernel_write_burst"

    def test_parent_of_pid_reason_extracts_signal_name(self):
        result = _signame_from_reason(
            "process_cmdline/vssadmin_delete_shadows (parent of pid=1234)"
        )
        assert result == "vssadmin_delete_shadows"


# ---------------------------------------------------------------------------
# _HIGH_ENTROPY_SKIP_EXTS
# ---------------------------------------------------------------------------

class TestHighEntropySkipExts:
    def test_zip_in_skip_exts(self):
        assert ".zip" in _HIGH_ENTROPY_SKIP_EXTS

    def test_mp4_in_skip_exts(self):
        assert ".mp4" in _HIGH_ENTROPY_SKIP_EXTS

    def test_jpg_in_skip_exts(self):
        assert ".jpg" in _HIGH_ENTROPY_SKIP_EXTS

    def test_mp3_in_skip_exts(self):
        assert ".mp3" in _HIGH_ENTROPY_SKIP_EXTS

    def test_docx_in_skip_exts(self):
        assert ".docx" in _HIGH_ENTROPY_SKIP_EXTS

    def test_txt_not_in_skip_exts(self):
        assert ".txt" not in _HIGH_ENTROPY_SKIP_EXTS

    def test_exe_not_in_skip_exts(self):
        assert ".exe" not in _HIGH_ENTROPY_SKIP_EXTS


# ---------------------------------------------------------------------------
# summarize_damage
# ---------------------------------------------------------------------------

class TestSummarizeDamage:
    def test_empty_signals_returns_zero_counts(self):
        result = summarize_damage([])
        assert result["distinct_total"] == 0
        assert len(result["encrypted"]) == 0
        assert len(result["renamed"]) == 0
        assert len(result["deleted"]) == 0

    def test_high_entropy_write_counted_as_encrypted(self):
        sig = _sig("high_entropy_write", metadata={"path": r"C:\docs\report.docx"})
        result = summarize_damage([sig])
        assert r"C:\docs\report.docx" in result["encrypted"]

    def test_magic_bytes_lost_counted_as_encrypted(self):
        sig = _sig("magic_bytes_lost", metadata={"path": r"C:\docs\photo.jpg"})
        result = summarize_damage([sig])
        assert r"C:\docs\photo.jpg" in result["encrypted"]

    def test_suspicious_extension_counted_as_renamed(self):
        sig = _sig(
            "suspicious_extension",
            metadata={"dest": r"C:\docs\file.encrypted"}
        )
        result = summarize_damage([sig])
        assert r"C:\docs\file.encrypted" in result["renamed"]

    def test_file_delete_counted_as_deleted(self):
        sig = _sig("file_delete", metadata={"path": r"C:\docs\original.txt"})
        result = summarize_damage([sig])
        assert r"C:\docs\original.txt" in result["deleted"]

    def test_canary_modified_sets_canary_flag(self):
        sig = _sig("canary_modified", metadata={"path": r"C:\canary\decoy.txt"})
        result = summarize_damage([sig])
        assert result["canary"] is True

    def test_canary_deleted_sets_canary_flag(self):
        sig = _sig("canary_deleted", metadata={"path": r"C:\canary\decoy.txt"})
        result = summarize_damage([sig])
        assert result["canary"] is True

    def test_no_canary_signals_leaves_flag_false(self):
        sig = _sig("high_entropy_write", metadata={"path": r"C:\docs\doc.txt"})
        result = summarize_damage([sig])
        assert result["canary"] is False

    def test_distinct_total_counts_unique_paths(self):
        sigs = [
            _sig("high_entropy_write", metadata={"path": r"C:\a.txt"}),
            _sig("suspicious_extension", metadata={"dest": r"C:\b.txt"}),
            _sig("file_delete", metadata={"path": r"C:\c.txt"}),
        ]
        result = summarize_damage(sigs)
        assert result["distinct_total"] == 3

    def test_same_path_in_multiple_signals_counted_once(self):
        path = r"C:\docs\same_file.txt"
        sigs = [
            _sig("high_entropy_write", metadata={"path": path}),
            _sig("magic_bytes_lost", metadata={"path": path}),
        ]
        result = summarize_damage(sigs)
        # Both refer to same path; distinct_total should be 1
        assert result["distinct_total"] == 1

    def test_modify_burst_updates_max_modify_burst(self):
        sig = _sig("modify_burst", metadata={"count": 42, "path": r"C:\x"})
        result = summarize_damage([sig])
        assert result["max_modify_burst"] == 42

    def test_unrelated_signal_ignored(self):
        sig = _sig("vssadmin_delete_shadows", metadata={"path": r"C:\x"})
        result = summarize_damage([sig])
        assert result["distinct_total"] == 0


# ---------------------------------------------------------------------------
# _attack_lines
# ---------------------------------------------------------------------------

class TestAttackLines:
    def test_returns_list_of_strings(self):
        lines = _attack_lines("process_cmdline/vssadmin_delete_shadows", [])
        assert isinstance(lines, list)
        assert all(isinstance(l, str) for l in lines)

    def test_contains_mitre_attack_heading(self):
        lines = _attack_lines("process_cmdline/vssadmin_delete_shadows", [])
        combined = "\n".join(lines)
        assert "MITRE ATT&CK" in combined

    def test_contains_T1490_for_vss_reason(self):
        lines = _attack_lines("process_cmdline/vssadmin_delete_shadows", [])
        combined = "\n".join(lines)
        assert "T1490" in combined

    def test_contains_table_row_for_technique(self):
        lines = _attack_lines("process_cmdline/vssadmin_delete_shadows", [])
        # Table rows start with |
        table_rows = [l for l in lines if l.startswith("|") and "T1490" in l]
        assert table_rows, "Expected a table row containing T1490"

    def test_pid_signals_contribute_extra_techniques(self):
        pid_sigs = [_sig("high_entropy_write")]
        lines = _attack_lines("process_cmdline/vssadmin_delete_shadows", pid_sigs)
        combined = "\n".join(lines)
        # high_entropy_write -> T1486
        assert "T1486" in combined

    def test_no_mapping_produces_fallback_message(self):
        lines = _attack_lines("detector/unknown_signal_xyz", [])
        combined = "\n".join(lines)
        # Should contain some fallback text, not crash
        assert lines  # non-empty

    def test_none_reason_does_not_crash(self):
        lines = _attack_lines(None, [])
        assert isinstance(lines, list)


# ---------------------------------------------------------------------------
# is_ransom_note name check (via ransom_note.is_ransom_note_name)
# These are imported through the ransom_note module — incident_report itself
# does not export is_ransom_note_name but the concept is central to detection.
# ---------------------------------------------------------------------------

class TestIsRansomNoteName:
    """Verify the function referenced in incident_report context works correctly."""

    def test_how_to_decrypt_is_ransom_note(self):
        from detectors.ransom_note import is_ransom_note_name
        assert is_ransom_note_name("HOW_TO_DECRYPT.txt") is True

    def test_readme_md_is_not_ransom_note(self):
        from detectors.ransom_note import is_ransom_note_name
        assert is_ransom_note_name("readme.md") is False


# ---------------------------------------------------------------------------
# Helper internals exposed via module
# ---------------------------------------------------------------------------

class TestModuleHelpers:
    def test_ko_detector_returns_korean_for_known_detector(self):
        result = incident_report._ko_detector("canary")
        assert result == "미끼 파일 감시"

    def test_ko_detector_returns_raw_name_for_unknown(self):
        result = incident_report._ko_detector("unknown_detector")
        assert result == "unknown_detector"

    def test_detector_from_reason_extracts_detector_part(self):
        result = incident_report._detector_from_reason(
            "process_cmdline/vssadmin_delete_shadows"
        )
        assert result == "process_cmdline"

    def test_detector_from_reason_returns_empty_for_no_slash(self):
        result = incident_report._detector_from_reason("no_slash_here")
        assert result == ""

    def test_explain_reason_returns_tuple_of_two_strings(self):
        what, why = incident_report._explain_reason(
            "process_cmdline/vssadmin_delete_shadows"
        )
        assert isinstance(what, str)
        assert isinstance(why, str)
        assert what  # non-empty

    def test_damage_headline_returns_string(self):
        damage = {
            "encrypted": {r"C:\a.txt"},
            "renamed": set(),
            "deleted": set(),
            "distinct_total": 1,
            "max_modify_burst": 0,
            "max_rename_burst": 0,
            "max_write_bytes": 0,
            "canary": False,
        }
        headline = incident_report._damage_headline(damage)
        assert isinstance(headline, str)
        assert "1" in headline
