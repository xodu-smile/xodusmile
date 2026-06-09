"""
Tests for detectors.mass_io
-----------------------------
Tests shannon_entropy, detect_magic, the FP fix (NATIVE_HIGH_ENTROPY_EXTS),
on_moved suspicious extension, and _is_noise.
Does NOT start the watchdog observer thread.
"""

import os
from pathlib import Path

import pytest

from detectors.mass_io import (
    NATIVE_HIGH_ENTROPY_EXTS,
    NOISE_EXTENSIONS,
    NOISE_PATH_FRAGMENTS,
    TARGET_EXTENSIONS,
    MassIODetector,
    detect_magic,
    shannon_entropy,
)
from scoring import ScoringEngine


# ---------------------------------------------------------------------------
# Fake engine to capture emitted signals without heavy deps
# ---------------------------------------------------------------------------

class FakeEngine:
    """Minimal ScoringEngine replacement that records submitted signals."""

    def __init__(self):
        self.submitted = []

    def submit(self, signal):
        self.submitted.append(signal)

    def subscribe(self, listener):
        # MassIODetector calls engine.subscribe in __init__; accept silently.
        pass

    def signal_names(self):
        return [s.name for s in self.submitted]


# ---------------------------------------------------------------------------
# shannon_entropy
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_bytes_returns_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte_repeated_has_entropy_zero(self):
        data = b"\x00" * 1024
        assert shannon_entropy(data) == pytest.approx(0.0)

    def test_all_same_byte_is_zero(self):
        for byte_val in (0x00, 0xFF, 0x41):
            assert shannon_entropy(bytes([byte_val] * 256)) == pytest.approx(0.0)

    def test_random_like_data_has_high_entropy(self):
        # os.urandom produces near-uniform distribution → entropy close to 8.0
        data = os.urandom(4096)
        assert shannon_entropy(data) > 7.5

    def test_low_entropy_text_is_below_threshold(self):
        # Repetitive ASCII text has low entropy
        data = b"hello world " * 300
        assert shannon_entropy(data) < 7.5

    def test_two_byte_alternating_is_exactly_one_bit(self):
        data = bytes([0x00, 0xFF] * 512)
        assert shannon_entropy(data) == pytest.approx(1.0)

    def test_uniform_256_byte_values_is_max_entropy(self):
        data = bytes(range(256))
        assert shannon_entropy(data) == pytest.approx(8.0)


# ---------------------------------------------------------------------------
# detect_magic
# ---------------------------------------------------------------------------

class TestDetectMagic:
    def test_pe_header_detected(self):
        assert detect_magic(b"\x4d\x5a" + b"\x00" * 100) == "PE"

    def test_pdf_header_detected(self):
        assert detect_magic(b"\x25\x50\x44\x46" + b"\x00" * 50) == "PDF"

    def test_zip_office_header_detected(self):
        assert detect_magic(b"\x50\x4b\x03\x04" + b"\x00" * 50) == "ZIP/Office"

    def test_jpeg_header_detected(self):
        assert detect_magic(b"\xff\xd8\xff" + b"\x00" * 50) == "JPEG"

    def test_png_header_detected(self):
        assert detect_magic(b"\x89\x50\x4e\x47" + b"\x00" * 50) == "PNG"

    def test_random_bytes_returns_none(self):
        # High-entropy data with no known magic prefix
        assert detect_magic(os.urandom(256)) is None

    def test_empty_bytes_returns_none(self):
        assert detect_magic(b"") is None

    def test_unknown_header_returns_none(self):
        assert detect_magic(b"\x00\x01\x02\x03\x04") is None


# ---------------------------------------------------------------------------
# NATIVE_HIGH_ENTROPY_EXTS membership
# ---------------------------------------------------------------------------

class TestNativeHighEntropyExts:
    def test_zip_is_in_native_high_entropy_exts(self):
        assert ".zip" in NATIVE_HIGH_ENTROPY_EXTS

    def test_mp4_is_in_native_high_entropy_exts(self):
        assert ".mp4" in NATIVE_HIGH_ENTROPY_EXTS

    def test_mp3_is_in_native_high_entropy_exts(self):
        assert ".mp3" in NATIVE_HIGH_ENTROPY_EXTS

    def test_jpg_is_in_native_high_entropy_exts(self):
        assert ".jpg" in NATIVE_HIGH_ENTROPY_EXTS

    def test_txt_is_not_in_native_high_entropy_exts(self):
        assert ".txt" not in NATIVE_HIGH_ENTROPY_EXTS

    def test_docx_is_not_a_native_high_entropy_ext_for_detection(self):
        # .docx IS in TARGET_EXTENSIONS but NOT in NATIVE_HIGH_ENTROPY_EXTS
        # (it has a known magic so magic_bytes_lost covers it)
        assert ".docx" not in NATIVE_HIGH_ENTROPY_EXTS


# ---------------------------------------------------------------------------
# MassIODetector — FP fix: native high-entropy extensions skipped
# ---------------------------------------------------------------------------

class TestMassIODetectorFPFix:
    """
    Critical false-positive regression tests.
    All write / move calls are made directly (no watchdog thread started).
    """

    def _make_detector(self, tmp_path):
        engine = FakeEngine()
        det = MassIODetector(engine, [str(tmp_path)])
        return det, engine

    def test_high_entropy_mp4_does_not_emit_high_entropy_write(self, tmp_path):
        """An .mp4 file is in NATIVE_HIGH_ENTROPY_EXTS → no high_entropy_write."""
        det, engine = self._make_detector(tmp_path)
        p = tmp_path / "video.mp4"
        # Write high-entropy content with no magic prefix
        p.write_bytes(os.urandom(4096))
        det.on_modified(p)
        assert "high_entropy_write" not in engine.signal_names()

    def test_high_entropy_zip_does_not_emit_high_entropy_write(self, tmp_path):
        """An .zip file (native high entropy) skips entropy-only signal."""
        det, engine = self._make_detector(tmp_path)
        p = tmp_path / "archive.zip"
        p.write_bytes(os.urandom(4096))
        det.on_modified(p)
        assert "high_entropy_write" not in engine.signal_names()

    def test_high_entropy_mp3_does_not_emit_high_entropy_write(self, tmp_path):
        det, engine = self._make_detector(tmp_path)
        p = tmp_path / "audio.mp3"
        p.write_bytes(os.urandom(4096))
        det.on_modified(p)
        assert "high_entropy_write" not in engine.signal_names()

    def test_high_entropy_txt_emits_high_entropy_write(self, tmp_path):
        """.txt is a target extension and NOT native-high-entropy → signal emitted."""
        det, engine = self._make_detector(tmp_path)
        p = tmp_path / "document.txt"
        # No magic bytes + high entropy + .txt is in TARGET_EXTENSIONS
        p.write_bytes(os.urandom(4096))
        det.on_modified(p)
        assert "high_entropy_write" in engine.signal_names()

    def test_high_entropy_docx_with_magic_does_not_emit_entropy_signal(self, tmp_path):
        """A .docx file with valid PK magic → detect_magic returns something → no entropy signal."""
        det, engine = self._make_detector(tmp_path)
        p = tmp_path / "report.docx"
        # PK magic prefix (ZIP/Office)
        p.write_bytes(b"\x50\x4b\x03\x04" + os.urandom(4092))
        det.on_modified(p)
        assert "high_entropy_write" not in engine.signal_names()

    def test_non_target_extension_does_not_emit_high_entropy_write(self, tmp_path):
        """Files with extensions not in TARGET_EXTENSIONS are ignored."""
        det, engine = self._make_detector(tmp_path)
        p = tmp_path / "data.xyz_unknown"
        p.write_bytes(os.urandom(4096))
        det.on_modified(p)
        assert "high_entropy_write" not in engine.signal_names()


# ---------------------------------------------------------------------------
# on_moved — suspicious extension
# ---------------------------------------------------------------------------

class TestOnMoved:
    def _make_detector(self, tmp_path):
        engine = FakeEngine()
        det = MassIODetector(engine, [str(tmp_path)])
        return det, engine

    def test_rename_to_encrypted_emits_suspicious_extension(self, tmp_path):
        det, engine = self._make_detector(tmp_path)
        src = tmp_path / "document.docx"
        dest = tmp_path / "document.docx.encrypted"
        src.write_bytes(b"content")
        dest.write_bytes(b"content")
        det.on_moved(src, dest)
        assert "suspicious_extension" in engine.signal_names()

    def test_rename_to_enc_emits_suspicious_extension(self, tmp_path):
        det, engine = self._make_detector(tmp_path)
        src = tmp_path / "photo.jpg"
        dest = tmp_path / "photo.jpg.enc"
        src.write_bytes(b"content")
        dest.write_bytes(b"content")
        det.on_moved(src, dest)
        assert "suspicious_extension" in engine.signal_names()

    def test_rename_to_locked_emits_suspicious_extension(self, tmp_path):
        det, engine = self._make_detector(tmp_path)
        src = tmp_path / "data.txt"
        dest = tmp_path / "data.txt.locked"
        src.write_bytes(b"content")
        dest.write_bytes(b"content")
        det.on_moved(src, dest)
        assert "suspicious_extension" in engine.signal_names()

    def test_normal_rename_does_not_emit_suspicious_extension(self, tmp_path):
        det, engine = self._make_detector(tmp_path)
        src = tmp_path / "old_name.txt"
        dest = tmp_path / "new_name.txt"
        src.write_bytes(b"content")
        dest.write_bytes(b"content")
        det.on_moved(src, dest)
        assert "suspicious_extension" not in engine.signal_names()


# ---------------------------------------------------------------------------
# _is_noise
# ---------------------------------------------------------------------------

class TestIsNoise:
    def test_appdata_packages_path_is_noise(self):
        p = Path(r"C:\Users\user\AppData\Local\Packages\Microsoft.Store\cache.dat")
        assert MassIODetector._is_noise(p) is True

    def test_tmp_extension_is_noise(self):
        p = Path(r"C:\Users\user\Downloads\some_file.tmp")
        assert MassIODetector._is_noise(p) is True

    def test_temp_extension_is_noise(self):
        p = Path(r"C:\Users\user\doc.temp")
        assert MassIODetector._is_noise(p) is True

    def test_log_extension_is_noise(self):
        p = Path(r"C:\app\debug.log")
        assert MassIODetector._is_noise(p) is True

    def test_normal_docx_is_not_noise(self):
        p = Path(r"C:\Users\user\Documents\report.docx")
        assert MassIODetector._is_noise(p) is False

    def test_normal_txt_is_not_noise(self):
        p = Path(r"C:\Users\user\Desktop\notes.txt")
        assert MassIODetector._is_noise(p) is False

    def test_appdata_local_microsoft_is_noise(self):
        p = Path(r"C:\Users\user\AppData\Local\Microsoft\Windows\cache")
        assert MassIODetector._is_noise(p) is True

    def test_recycle_bin_is_noise(self):
        p = Path(r"C:\$Recycle.Bin\S-1-5-21\somefile.txt")
        assert MassIODetector._is_noise(p) is True


# ---------------------------------------------------------------------------
# on_modified with a noise path emits no signal
# ---------------------------------------------------------------------------

class TestOnModifiedNoisePath:
    def test_noise_path_emits_no_signal(self, tmp_path):
        engine = FakeEngine()
        det = MassIODetector(engine, [str(tmp_path)])
        # Create a path that looks like noise via .tmp extension
        p = tmp_path / "tempfile.tmp"
        p.write_bytes(os.urandom(4096))
        det.on_modified(p)
        assert engine.submitted == []

    def test_nonexistent_file_emits_no_signal(self, tmp_path):
        engine = FakeEngine()
        det = MassIODetector(engine, [str(tmp_path)])
        p = tmp_path / "ghost_file.txt"
        # File does not exist; on_modified should return early
        det.on_modified(p)
        assert engine.submitted == []


# ---------------------------------------------------------------------------
# MassIODetector construction does not require watchdog
# ---------------------------------------------------------------------------

class TestMassIODetectorConstruction:
    def test_constructor_succeeds_without_watchdog(self, tmp_path):
        """MassIODetector can be instantiated even when watchdog is absent."""
        engine = FakeEngine()
        det = MassIODetector(engine, [str(tmp_path)])
        assert det is not None

    def test_watch_dirs_stored_as_paths(self, tmp_path):
        engine = FakeEngine()
        det = MassIODetector(engine, [str(tmp_path)])
        assert all(isinstance(d, Path) for d in det.watch_dirs)
