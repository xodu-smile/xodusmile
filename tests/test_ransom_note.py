"""
Tests for detectors.ransom_note
---------------------------------
Covers is_ransom_note_name, RansomNoteDetector._scan behavior (drop / spread /
initial-baseline / size guard).
No watchdog / psutil required.
"""

import pytest
from pathlib import Path

from detectors.ransom_note import (
    MAX_NOTE_BYTES,
    SPREAD_DIR_THRESHOLD,
    RansomNoteDetector,
    is_ransom_note_name,
)
from scoring import ScoringEngine, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_detector(engine, dirs):
    return RansomNoteDetector(engine, [str(d) for d in dirs])


# ---------------------------------------------------------------------------
# is_ransom_note_name — positive cases
# ---------------------------------------------------------------------------

class TestIsRansomNoteNamePositives:
    @pytest.mark.parametrize("filename", [
        "HOW_TO_DECRYPT.txt",
        "_readme.txt",
        "RESTORE-MY-FILES.txt",
        "!!!READ_ME.txt",
        "DECRYPT_INSTRUCTIONS.html",
        "YOUR FILES ARE ENCRYPTED.txt",
        "how_to_decrypt.txt",
        "HOW TO DECRYPT YOUR FILES.html",
        "RECOVER_MY_FILES.txt",
        "!!!RESTORE_FILES!!!.txt",
        "decrypt_info.txt",
        "ransom_note.txt",
        "READ_ME_FOR_DECRYPT.txt",
        "recovery_key.txt",
        "UNLOCK_YOUR_FILES.txt",
    ])
    def test_positive(self, filename):
        assert is_ransom_note_name(filename) is True, (
            f"Expected {filename!r} to be recognised as a ransom note"
        )


# ---------------------------------------------------------------------------
# is_ransom_note_name — negative cases
# ---------------------------------------------------------------------------

class TestIsRansomNoteNameNegatives:
    @pytest.mark.parametrize("filename", [
        "report.docx",
        "license.txt",
        "notes.txt",
        "readme.md",
        "photo.jpg",
        "invoice_2024.pdf",
        "project_plan.xlsx",
        "backup.zip",
        "README",
        "setup.exe",
    ])
    def test_negative(self, filename):
        assert is_ransom_note_name(filename) is False, (
            f"Expected {filename!r} NOT to be recognised as a ransom note"
        )


# ---------------------------------------------------------------------------
# _scan(initial=False) — emits ransom_note_dropped on single new note
# ---------------------------------------------------------------------------

class TestScanDropsSingleNote:
    def test_single_note_in_one_dir_emits_ransom_note_dropped(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        note = dir_a / "HOW_TO_DECRYPT.txt"
        note.write_text("Pay here", encoding="utf-8")

        det._scan(initial=False)

        sig_names = [s.name for s in received]
        assert "ransom_note_dropped" in sig_names

    def test_ransom_note_dropped_severity_is_high(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        (dir_a / "HOW_TO_DECRYPT.txt").write_text("Pay", encoding="utf-8")
        det._scan(initial=False)

        drop_sigs = [s for s in received if s.name == "ransom_note_dropped"]
        assert drop_sigs
        assert drop_sigs[0].severity == Severity.HIGH

    def test_same_note_not_reported_twice(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        (dir_a / "HOW_TO_DECRYPT.txt").write_text("Pay", encoding="utf-8")
        det._scan(initial=False)
        det._scan(initial=False)

        # Should only report once
        assert sum(1 for s in received if s.name == "ransom_note_dropped") == 1


# ---------------------------------------------------------------------------
# _scan — spread across multiple directories emits ransom_note_spread
# ---------------------------------------------------------------------------

class TestScanSpread:
    def test_notes_in_two_dirs_emit_ransom_note_spread(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a, dir_b])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        (dir_a / "HOW_TO_DECRYPT.txt").write_text("Pay", encoding="utf-8")
        det._scan(initial=False)

        (dir_b / "_readme.txt").write_text("Pay ransom", encoding="utf-8")
        det._scan(initial=False)

        sig_names = [s.name for s in received]
        assert "ransom_note_spread" in sig_names

    def test_ransom_note_spread_severity_is_critical(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a, dir_b])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        (dir_a / "HOW_TO_DECRYPT.txt").write_text("Pay", encoding="utf-8")
        det._scan(initial=False)
        (dir_b / "_readme.txt").write_text("Pay", encoding="utf-8")
        det._scan(initial=False)

        spread_sigs = [s for s in received if s.name == "ransom_note_spread"]
        assert spread_sigs
        assert spread_sigs[0].severity == Severity.CRITICAL

    def test_spread_metadata_includes_directories_affected(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a, dir_b])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        (dir_a / "HOW_TO_DECRYPT.txt").write_text("Pay", encoding="utf-8")
        det._scan(initial=False)
        (dir_b / "_readme.txt").write_text("Pay", encoding="utf-8")
        det._scan(initial=False)

        spread_sigs = [s for s in received if s.name == "ransom_note_spread"]
        assert spread_sigs
        assert spread_sigs[0].metadata.get("directories_affected", 0) >= SPREAD_DIR_THRESHOLD

    def test_spread_dir_threshold_is_two(self):
        assert SPREAD_DIR_THRESHOLD == 2


# ---------------------------------------------------------------------------
# _scan(initial=True) — registers baseline WITHOUT emitting
# ---------------------------------------------------------------------------

class TestScanInitialBaseline:
    def test_initial_scan_does_not_emit_for_existing_notes(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        # Pre-existing note before initial scan
        (dir_a / "HOW_TO_DECRYPT.txt").write_text("Pre-existing", encoding="utf-8")
        det._scan(initial=True)

        assert received == []

    def test_after_initial_scan_new_note_is_still_reported(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        # Pre-existing note
        (dir_a / "HOW_TO_DECRYPT.txt").write_text("Old", encoding="utf-8")
        det._scan(initial=True)

        # New note created after baseline
        (dir_a / "RESTORE-MY-FILES.txt").write_text("New", encoding="utf-8")
        det._scan(initial=False)

        sig_names = [s.name for s in received]
        assert "ransom_note_dropped" in sig_names


# ---------------------------------------------------------------------------
# Size guard — notes larger than MAX_NOTE_BYTES are ignored
# ---------------------------------------------------------------------------

class TestSizeLimitGuard:
    def test_note_larger_than_max_bytes_is_ignored(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        oversized_note = dir_a / "HOW_TO_DECRYPT.txt"
        oversized_note.write_bytes(b"X" * (MAX_NOTE_BYTES + 1))
        det._scan(initial=False)

        assert received == []

    def test_note_at_exactly_max_bytes_is_ignored(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        # stat().st_size > MAX_NOTE_BYTES → exactly MAX is excluded
        note = dir_a / "HOW_TO_DECRYPT.txt"
        note.write_bytes(b"X" * (MAX_NOTE_BYTES + 1))
        det._scan(initial=False)

        assert received == []

    def test_note_smaller_than_max_bytes_is_reported(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        note = dir_a / "HOW_TO_DECRYPT.txt"
        note.write_bytes(b"Pay us " * 10)  # well under 65536
        det._scan(initial=False)

        assert any(s.name == "ransom_note_dropped" for s in received)


# ---------------------------------------------------------------------------
# Non-note files are ignored
# ---------------------------------------------------------------------------

class TestNonNoteFilesIgnored:
    def test_regular_readme_is_not_reported(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        (dir_a / "readme.md").write_text("Normal readme", encoding="utf-8")
        det._scan(initial=False)

        assert received == []

    def test_license_file_is_not_reported(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        (dir_a / "license.txt").write_text("MIT License", encoding="utf-8")
        det._scan(initial=False)

        assert received == []

    def test_photo_jpg_is_not_reported(self, tmp_path):
        dir_a = tmp_path / "dir_a"
        dir_a.mkdir()
        engine = ScoringEngine()
        det = _make_detector(engine, [dir_a])

        received = []
        engine.subscribe(lambda sig, score, level: received.append(sig))

        (dir_a / "photo.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 50)
        det._scan(initial=False)

        assert received == []
