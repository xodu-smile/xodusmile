"""
Tests for attack_map module.
-------------------------------
Pure data + lookup functions — no external dependencies.
"""

import pytest

import attack_map
from attack_map import (
    Technique,
    annotate_signal_dict,
    label_for,
    primary_technique,
    technique_dicts_for,
    techniques_for,
)


# ---------------------------------------------------------------------------
# primary_technique
# ---------------------------------------------------------------------------

class TestPrimaryTechnique:
    def test_vssadmin_delete_shadows_maps_to_T1490(self):
        t = primary_technique("vssadmin_delete_shadows")
        assert t is not None
        assert t.tid == "T1490"

    def test_high_entropy_write_maps_to_T1486(self):
        t = primary_technique("high_entropy_write")
        assert t is not None
        assert t.tid == "T1486"

    def test_unknown_signal_returns_none(self):
        assert primary_technique("totally_unknown_signal_xyz") is None

    def test_none_input_returns_none(self):
        assert primary_technique(None) is None

    def test_empty_string_returns_none(self):
        assert primary_technique("") is None


# ---------------------------------------------------------------------------
# techniques_for
# ---------------------------------------------------------------------------

class TestTechniquesFor:
    def test_high_entropy_write_contains_T1486(self):
        techs = techniques_for("high_entropy_write")
        tids = [t.tid for t in techs]
        assert "T1486" in tids

    def test_canary_deleted_maps_to_two_techniques(self):
        # canary_deleted -> [_DATA_ENCRYPTED, _DATA_DESTRUCTION]
        techs = techniques_for("canary_deleted")
        assert len(techs) >= 2

    def test_unknown_signal_returns_empty_list(self):
        assert techniques_for("not_a_real_signal") == []

    def test_none_input_returns_empty_list(self):
        assert techniques_for(None) == []

    def test_returns_list_of_technique_objects(self):
        techs = techniques_for("vssadmin_delete_shadows")
        for t in techs:
            assert isinstance(t, Technique)


# ---------------------------------------------------------------------------
# label_for
# ---------------------------------------------------------------------------

class TestLabelFor:
    def test_single_technique_label_has_no_plus_count(self):
        label = label_for("vssadmin_delete_shadows")
        assert "T1490" in label
        assert "(+" not in label

    def test_multi_technique_label_includes_plus_count(self):
        # canary_deleted has 2 techniques
        label = label_for("canary_deleted")
        assert "(+" in label

    def test_unknown_signal_returns_empty_string(self):
        assert label_for("unknown_xyz") == ""

    def test_none_returns_empty_string(self):
        assert label_for(None) == ""

    def test_label_starts_with_tid(self):
        label = label_for("high_entropy_write")
        assert label.startswith("T1486")


# ---------------------------------------------------------------------------
# technique_dicts_for
# ---------------------------------------------------------------------------

class TestTechniqueDictsFor:
    def test_returns_list_of_dicts(self):
        dicts = technique_dicts_for("vssadmin_delete_shadows")
        assert isinstance(dicts, list)
        assert len(dicts) >= 1
        assert isinstance(dicts[0], dict)

    def test_dict_has_required_keys(self):
        dicts = technique_dicts_for("high_entropy_write")
        keys = {"id", "name", "tactic", "tactic_ko", "url"}
        for d in dicts:
            assert keys.issubset(d.keys())

    def test_unknown_signal_returns_empty_list(self):
        assert technique_dicts_for("no_such_signal") == []


# ---------------------------------------------------------------------------
# annotate_signal_dict
# ---------------------------------------------------------------------------

class TestAnnotateSignalDict:
    def test_adds_attack_key(self):
        sig_dict = {"name": "vssadmin_delete_shadows", "weight": 30}
        annotated = annotate_signal_dict(sig_dict)
        assert "attack" in annotated

    def test_does_not_mutate_original(self):
        sig_dict = {"name": "high_entropy_write", "weight": 8}
        original_keys = set(sig_dict.keys())
        annotate_signal_dict(sig_dict)
        assert set(sig_dict.keys()) == original_keys

    def test_attack_key_is_a_list(self):
        sig_dict = {"name": "vssadmin_delete_shadows", "weight": 30}
        annotated = annotate_signal_dict(sig_dict)
        assert isinstance(annotated["attack"], list)

    def test_attack_list_contains_correct_technique(self):
        sig_dict = {"name": "vssadmin_delete_shadows", "weight": 30}
        annotated = annotate_signal_dict(sig_dict)
        tids = [t["id"] for t in annotated["attack"]]
        assert "T1490" in tids

    def test_unknown_signal_attack_key_is_empty_list(self):
        sig_dict = {"name": "unknown_xyz", "weight": 5}
        annotated = annotate_signal_dict(sig_dict)
        assert annotated["attack"] == []

    def test_other_fields_preserved(self):
        sig_dict = {"name": "high_entropy_write", "weight": 8, "severity": "MEDIUM"}
        annotated = annotate_signal_dict(sig_dict)
        assert annotated["weight"] == 8
        assert annotated["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Every Technique has a valid URL containing the tid path
# ---------------------------------------------------------------------------

class TestTechniqueUrls:
    def test_every_technique_has_url_with_tid_path(self):
        """All techniques in the signal map have a URL containing their tid."""
        checked = set()
        for signal_name in (
            "vssadmin_delete_shadows", "high_entropy_write", "canary_modified",
            "defender_disable_realtime", "powershell_obfuscated_exec",
            "schtasks_persistence", "process_masquerade", "canary_deleted",
            "wbadmin_delete_catalog", "bcdedit_recovery_disabled",
        ):
            techs = techniques_for(signal_name)
            for t in techs:
                if t.tid in checked:
                    continue
                checked.add(t.tid)
                # Sub-technique T1562.001 -> URL path T1562/001
                expected_path = t.tid.replace(".", "/")
                assert expected_path in t.url, (
                    f"URL {t.url!r} does not contain path {expected_path!r} for {t.tid}"
                )
                assert t.url.startswith("https://attack.mitre.org/techniques/")

    def test_technique_url_is_https(self):
        t = primary_technique("vssadmin_delete_shadows")
        assert t.url.startswith("https://")

    def test_subtechnique_url_uses_slash_separator(self):
        # T1562.001 -> https://attack.mitre.org/techniques/T1562/001/
        techs = techniques_for("defender_disable_realtime")
        sub = next((t for t in techs if "." in t.tid), None)
        if sub is not None:
            expected = sub.tid.replace(".", "/")
            assert expected in sub.url


# ---------------------------------------------------------------------------
# Technique dataclass is frozen (immutable)
# ---------------------------------------------------------------------------

class TestTechniqueImmutability:
    def test_technique_is_frozen(self):
        t = primary_technique("vssadmin_delete_shadows")
        with pytest.raises((AttributeError, TypeError)):
            t.tid = "X9999"  # type: ignore[misc]
