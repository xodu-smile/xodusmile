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


# ---------------------------------------------------------------------------
# 행동 시점 컨텍스트 — RustyStealer PDF 자기모순 회귀 테스트
# (엔진 윈도우에서 신호가 퇴거된 뒤에도 보고서는 차단 근거를 보여야 한다)
# ---------------------------------------------------------------------------

import json as _json
import time as _time

from scoring import ScoringEngine
from responder import KillAction
from incident_report import IncidentReporter, _damage_floors, _damage_headline


def _evicted_action(ts=None):
    ts = ts or _time.time()
    trig = Signal(
        detector="minifilter", name="kernel_rename_burst", weight=40,
        severity=Severity.HIGH,
        message="pid=10652 performed 12 renames in 10s",
        metadata={"pid": 10652, "count": 12,
                  "last_path": r"C:\u\doc.txt.locked"},
        timestamp=ts - 130,  # 점수 윈도우(120초) 밖
    )
    return KillAction(
        timestamp=ts, pid=10652, process_name="mal.exe",
        cmdline=r"C:\sample\mal.exe",
        reason="minifilter/kernel_rename_burst", mode="kill",
        quarantined=True, terminated=True,
        exe_path=r"C:\sample\mal.exe", exe_sha256="ab" * 32,
        username="HOST\\victim", ppid=4321, parent_name="explorer.exe",
        score_at_action=40, level_at_action="LOW",
        trigger_signal=trig.to_dict(), detect_ts=trig.timestamp,
    )


class TestActionTimeReport:
    def _build(self, tmp_path):
        engine = ScoringEngine()  # 비어 있음 = 신호 전부 퇴거된 상황
        rep = IncidentReporter(engine, reports_dir=str(tmp_path), notify=False)
        try:
            action = _evicted_action()
            md = rep._build_markdown(action)
            return rep, action, md
        finally:
            rep.close()

    def test_trigger_signal_survives_eviction(self, tmp_path):
        _, _, md = self._build(tmp_path)
        assert "kernel_rename_burst" in md
        assert "이 프로세스(PID 10652)에 대한 탐지 신호" in md

    def test_score_and_level_from_action_time(self, tmp_path):
        _, _, md = self._build(tmp_path)
        assert "차단 시점 위험 점수(최근 120초 누적):** 40" in md
        assert "(LOW)" in md

    def test_block_basis_explains_single_signal_kill(self, tmp_path):
        _, _, md = self._build(tmp_path)
        assert "즉시 차단" in md

    def test_forensics_fields_rendered(self, tmp_path):
        _, _, md = self._build(tmp_path)
        assert "ab" * 32 in md            # sha256
        assert "explorer.exe" in md       # 부모
        assert "HOST\\victim" in md       # 계정
        assert "탐지→대응 지연" in md

    def test_ioc_block_present(self, tmp_path):
        _, _, md = self._build(tmp_path)
        assert "침해 지표 (IOC)" in md
        assert f"sha256: {'ab' * 32}" in md
        assert "mitre_attack: T1486" in md

    def test_damage_floor_uses_burst_count(self, tmp_path):
        _, _, md = self._build(tmp_path)
        assert "최소 12개" in md

    def test_json_sidecar_written_with_schema(self, tmp_path):
        engine = ScoringEngine()
        rep = IncidentReporter(engine, reports_dir=str(tmp_path), notify=False)
        try:
            rep.on_action(_evicted_action())
        finally:
            rep.close()
        sidecars = list(tmp_path.glob("incident_*.json"))
        assert len(sidecars) == 1
        doc = _json.loads(sidecars[0].read_text(encoding="utf-8"))
        assert doc["schema"] == "ransomguard.incident.v1"
        assert doc["action"]["exe_sha256"] == "ab" * 32
        assert doc["damage"]["max_rename_burst"] == 12
        assert [t["id"] for t in doc["attack"]] == ["T1486"]
        assert doc["pid_signals"][0]["name"] == "kernel_rename_burst"

    def test_signal_table_has_pid_column_and_marker(self, tmp_path):
        _, _, md = self._build(tmp_path)
        assert "| 시각 | PID |" in md
        assert "**10652** ◀" in md

    def test_legacy_action_without_context_still_renders(self, tmp_path):
        """구버전 KillAction(컨텍스트 없음)도 보고서 생성이 가능해야 한다."""
        engine = ScoringEngine()
        rep = IncidentReporter(engine, reports_dir=str(tmp_path), notify=False)
        try:
            a = KillAction(_time.time(), 1, "x.exe", "x", "minifilter/file_delete",
                           "kill", quarantined=True, terminated=True)
            md = rep._build_markdown(a)
        finally:
            rep.close()
        assert "보고서 생성 시점 위험 점수" in md


class TestDamageFloors:
    def test_floor_when_burst_exceeds_paths(self):
        d = summarize_damage([_sig("kernel_rename_burst",
                                   metadata={"count": 12,
                                             "last_path": r"C:\a.locked"})])
        enc_min, ren_min = _damage_floors(d)
        assert ren_min == 12
        assert "최소 12개" in _damage_headline(d)

    def test_no_floor_when_paths_dominate(self):
        sigs = [_sig("suspicious_extension", metadata={"dest": f"C:\\f{i}.enc"})
                for i in range(3)]
        d = summarize_damage(sigs)
        _, ren_min = _damage_floors(d)
        assert ren_min == 3
        assert "최소" not in _damage_headline(d)
