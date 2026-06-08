"""
Tests for detectors.ransom_note (content-aware redesign)
--------------------------------------------------------
Covers:
  - is_ransom_note_name (filename patterns)
  - analyze_note_content (content-based detection — the new capability)
  - RansomNoteDetector: single confirmed / name-only / content-only / spread
    (content-confirmed AND corroborated paths) / baseline / size guard.
No watchdog / psutil required.
"""

import pytest

from detectors.ransom_note import (
    MAX_NOTE_BYTES,
    SPREAD_DIR_THRESHOLD,
    RansomNoteDetector,
    is_ransom_note_name,
    analyze_note_content,
)
from scoring import ScoringEngine, Signal, Severity


# A realistic ransom note body: crypto address + onion + extortion phrase +
# payment + contact + threat → strongly content-confirmed.
RANSOM_BODY = (
    "All your files have been encrypted!\n"
    "To recover your files send 0.5 bitcoin to "
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n"
    "Then contact us at decrypt-help@protonmail.com\n"
    "Or visit http://abcdef1234567klmnopqrstuvwxyz234567abcdefghij234567ab.onion\n"
    "Do not rename or modify the files or you will lose them permanently.\n"
)


def _make_detector(engine, dirs):
    return RansomNoteDetector(engine, [str(d) for d in dirs])


def _collect(engine):
    received = []
    engine.subscribe(lambda sig, score, level: received.append(sig))
    return received


# ---------------------------------------------------------------------------
# is_ransom_note_name
# ---------------------------------------------------------------------------

class TestIsRansomNoteName:
    @pytest.mark.parametrize("filename", [
        "HOW_TO_DECRYPT.txt", "_readme.txt", "RESTORE-MY-FILES.txt",
        "!!!READ_ME.txt", "DECRYPT_INSTRUCTIONS.html",
        "YOUR FILES ARE ENCRYPTED.txt", "RECOVER_MY_FILES.txt",
        "decrypt_info.txt", "ransom_note.txt", "recovery_key.txt",
        "UNLOCK_YOUR_FILES.txt",
    ])
    def test_positive(self, filename):
        assert is_ransom_note_name(filename) is True

    @pytest.mark.parametrize("filename", [
        "report.docx", "license.txt", "notes.txt", "readme.md",
        "photo.jpg", "invoice_2024.pdf", "backup.zip", "README", "setup.exe",
    ])
    def test_negative(self, filename):
        assert is_ransom_note_name(filename) is False


# ---------------------------------------------------------------------------
# analyze_note_content — the new content-based capability (widened scope)
# ---------------------------------------------------------------------------

class TestAnalyzeContent:
    def test_full_ransom_body_is_confirmed(self):
        v = analyze_note_content(RANSOM_BODY)
        assert v.confirmed is True
        assert "crypto_address" in v.indicators
        assert "encryption_phrase" in v.indicators

    def test_btc_plus_phrase_is_confirmed(self):
        body = ("Your files are encrypted. Pay bitcoin to "
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 to decrypt your files.")
        assert analyze_note_content(body).confirmed is True

    def test_benign_license_not_confirmed(self):
        body = ("MIT License\n\nPermission is hereby granted, free of charge, "
                "to any person obtaining a copy of this software.")
        assert analyze_note_content(body).confirmed is False

    def test_benign_readme_not_confirmed(self):
        assert analyze_note_content("Build with make; run with ./app").confirmed is False

    def test_security_doc_without_crypto_not_confirmed(self):
        """An IR/security doc full of encryption words but NO crypto/onion
        address must NOT be content-confirmed (false-positive guard)."""
        body = ("Incident response: if your files are encrypted, do not rename "
                "them. Contact soc@corp.com to decrypt. All data is encrypted "
                "at rest. Ransom payment is never advised.")
        assert analyze_note_content(body).confirmed is False

    def test_lone_btc_address_not_confirmed(self):
        """A wallet address alone (e.g. a crypto backup file) isn't a note."""
        v = analyze_note_content("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        assert v.confirmed is False  # strong indicator present but score < 3

    def test_empty_not_confirmed(self):
        assert analyze_note_content("").confirmed is False


# ---------------------------------------------------------------------------
# Single note classification
# ---------------------------------------------------------------------------

class TestSingleNote:
    def test_content_confirmed_note_is_high(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "HOW_TO_DECRYPT.txt").write_text(RANSOM_BODY, encoding="utf-8")
        det._scan(initial=False)
        sigs = [s for s in received if s.name == "ransom_note_dropped"]
        assert sigs and sigs[0].severity == Severity.HIGH
        assert sigs[0].metadata["content_confirmed"] is True

    def test_content_only_random_name_is_detected(self, tmp_path):
        """The headline fix: a note with an arbitrary name is caught by content."""
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "A7F3C9.txt").write_text(RANSOM_BODY, encoding="utf-8")
        det._scan(initial=False)
        assert any(s.name == "ransom_note_dropped" for s in received)

    def test_name_only_weak_content_is_medium(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "HOW_TO_DECRYPT.txt").write_text("hello", encoding="utf-8")
        det._scan(initial=False)
        sigs = [s for s in received if s.name == "ransom_note_dropped"]
        assert sigs and sigs[0].severity == Severity.MEDIUM
        assert sigs[0].metadata["content_confirmed"] is False

    def test_same_note_not_reported_twice(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "HOW_TO_DECRYPT.txt").write_text(RANSOM_BODY, encoding="utf-8")
        det._scan(initial=False)
        det._scan(initial=False)
        assert sum(1 for s in received if s.name == "ransom_note_dropped") == 1


# ---------------------------------------------------------------------------
# Spread — now requires content confirmation OR corroboration, and >= 3 dirs
# ---------------------------------------------------------------------------

class TestSpread:
    def test_threshold_is_three(self):
        assert SPREAD_DIR_THRESHOLD == 3

    def test_content_confirmed_across_three_dirs_is_critical(self, tmp_path):
        dirs = [tmp_path / x for x in ("a", "b", "c")]
        for d in dirs:
            d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, dirs)
        received = _collect(engine)
        for d in dirs:
            (d / "HOW_TO_DECRYPT.txt").write_text(RANSOM_BODY, encoding="utf-8")
            det._scan(initial=False)
        spread = [s for s in received if s.name == "ransom_note_spread"]
        assert spread and spread[0].severity == Severity.CRITICAL
        assert spread[0].metadata["directories_confirmed"] >= SPREAD_DIR_THRESHOLD

    def test_two_confirmed_dirs_is_not_spread(self, tmp_path):
        dirs = [tmp_path / x for x in ("a", "b")]
        for d in dirs:
            d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, dirs)
        received = _collect(engine)
        for d in dirs:
            (d / "HOW_TO_DECRYPT.txt").write_text(RANSOM_BODY, encoding="utf-8")
            det._scan(initial=False)
        assert not any(s.name == "ransom_note_spread" for s in received)

    def test_name_only_spread_without_encryption_is_not_critical(self, tmp_path):
        """The leniency fix: name-only notes across many dirs no longer auto-CRITICAL."""
        dirs = [tmp_path / x for x in ("a", "b", "c", "d")]
        for d in dirs:
            d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, dirs)
        received = _collect(engine)
        for d in dirs:
            (d / "HOW_TO_DECRYPT.txt").write_text("please pay", encoding="utf-8")
            det._scan(initial=False)
        assert not any(s.name == "ransom_note_spread" for s in received)

    def test_name_only_spread_with_encryption_activity_is_critical(self, tmp_path):
        """Name-only spread DOES escalate when corroborated by real encryption."""
        dirs = [tmp_path / x for x in ("a", "b", "c")]
        for d in dirs:
            d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, dirs)
        received = _collect(engine)
        # Inject a non-canary encryption signal (no boost) to corroborate.
        engine.submit(Signal(detector="mass_io", name="magic_bytes_lost",
                             weight=12, severity=Severity.HIGH,
                             message="x", metadata={"path": "x"}))
        for d in dirs:
            (d / "HOW_TO_DECRYPT.txt").write_text("please pay", encoding="utf-8")
            det._scan(initial=False)
        spread = [s for s in received if s.name == "ransom_note_spread"]
        assert spread and spread[0].metadata["trigger"] == "correlated"


# ---------------------------------------------------------------------------
# Baseline + size guard + non-note files
# ---------------------------------------------------------------------------

class TestBaselineAndGuards:
    def test_initial_scan_does_not_emit(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "HOW_TO_DECRYPT.txt").write_text(RANSOM_BODY, encoding="utf-8")
        det._scan(initial=True)
        assert received == []

    def test_new_note_after_baseline_is_reported(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "HOW_TO_DECRYPT.txt").write_text(RANSOM_BODY, encoding="utf-8")
        det._scan(initial=True)
        (d / "RESTORE-MY-FILES.txt").write_text(RANSOM_BODY, encoding="utf-8")
        det._scan(initial=False)
        assert any(s.name == "ransom_note_dropped" for s in received)

    def test_oversized_note_ignored(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "HOW_TO_DECRYPT.txt").write_bytes(b"X" * (MAX_NOTE_BYTES + 1))
        det._scan(initial=False)
        assert received == []

    def test_regular_readme_not_reported(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "readme.md").write_text("Normal readme", encoding="utf-8")
        det._scan(initial=False)
        assert received == []

    def test_license_not_reported(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "license.txt").write_text("MIT License", encoding="utf-8")
        det._scan(initial=False)
        assert received == []

    def test_photo_not_reported(self, tmp_path):
        d = tmp_path / "a"; d.mkdir()
        engine = ScoringEngine(); det = _make_detector(engine, [d])
        received = _collect(engine)
        (d / "photo.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 50)
        det._scan(initial=False)
        assert received == []
