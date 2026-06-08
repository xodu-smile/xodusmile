"""
Tests for scoring.ScoringEngine
--------------------------------
Covers: weight accumulation, threshold levels, Severity enum mapping,
window eviction, correlation gating, trusted-actor stamping, and helpers.
No psutil/flask/watchdog required.
"""

import time

import pytest

from scoring import (
    CORRELATION_GATED_NAMES,
    ENCRYPTION_SIGNAL_NAMES,
    THRESHOLD_CRITICAL,
    THRESHOLD_HIGH,
    THRESHOLD_LOW,
    THRESHOLD_MEDIUM,
    Severity,
    Signal,
    ScoringEngine,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig(name="canary_modified", weight=10, severity=Severity.HIGH,
         metadata=None, timestamp=None):
    """Build a minimal Signal for testing."""
    kwargs = dict(
        detector="test",
        name=name,
        weight=weight,
        severity=severity,
        message="test signal",
        metadata=metadata or {},
    )
    if timestamp is not None:
        kwargs["timestamp"] = timestamp
    return Signal(**kwargs)


# ---------------------------------------------------------------------------
# Threshold constants are sane values
# ---------------------------------------------------------------------------

class TestThresholdConstants:
    def test_low_threshold_is_30(self):
        assert THRESHOLD_LOW == 30

    def test_medium_threshold_is_60(self):
        assert THRESHOLD_MEDIUM == 60

    def test_high_threshold_is_100(self):
        assert THRESHOLD_HIGH == 100

    def test_critical_threshold_is_150(self):
        assert THRESHOLD_CRITICAL == 150

    def test_thresholds_are_strictly_increasing(self):
        assert THRESHOLD_LOW < THRESHOLD_MEDIUM < THRESHOLD_HIGH < THRESHOLD_CRITICAL


# ---------------------------------------------------------------------------
# Severity enum mapping via _level_for_score
# ---------------------------------------------------------------------------

class TestLevelForScore:
    def test_score_below_low_is_info(self):
        assert ScoringEngine._level_for_score(0) == Severity.INFO
        assert ScoringEngine._level_for_score(THRESHOLD_LOW - 1) == Severity.INFO

    def test_score_at_low_threshold_is_low(self):
        assert ScoringEngine._level_for_score(THRESHOLD_LOW) == Severity.LOW

    def test_score_between_low_and_medium_is_low(self):
        assert ScoringEngine._level_for_score(THRESHOLD_LOW + 1) == Severity.LOW
        assert ScoringEngine._level_for_score(THRESHOLD_MEDIUM - 1) == Severity.LOW

    def test_score_at_medium_threshold_is_medium(self):
        assert ScoringEngine._level_for_score(THRESHOLD_MEDIUM) == Severity.MEDIUM

    def test_score_at_high_threshold_is_high(self):
        assert ScoringEngine._level_for_score(THRESHOLD_HIGH) == Severity.HIGH

    def test_score_at_critical_threshold_is_critical(self):
        assert ScoringEngine._level_for_score(THRESHOLD_CRITICAL) == Severity.CRITICAL

    def test_score_above_critical_is_still_critical(self):
        assert ScoringEngine._level_for_score(THRESHOLD_CRITICAL + 500) == Severity.CRITICAL


# ---------------------------------------------------------------------------
# current_score and current_level reflect submitted signals
# ---------------------------------------------------------------------------

class TestCurrentScoreAndLevel:
    def test_empty_engine_has_score_zero(self):
        engine = ScoringEngine()
        assert engine.current_score() == 0

    def test_empty_engine_level_is_info(self):
        engine = ScoringEngine()
        assert engine.current_level() == Severity.INFO

    def test_single_signal_weight_contributes_to_score(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="high_entropy_write", weight=40))
        assert engine.current_score() == 40

    def test_multiple_signals_weights_sum(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="high_entropy_write", weight=40))
        engine.submit(_sig(name="magic_bytes_lost", weight=30))
        assert engine.current_score() == 70

    def test_score_reaches_medium_level(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="high_entropy_write", weight=THRESHOLD_MEDIUM))
        assert engine.current_level() == Severity.MEDIUM

    def test_score_reaches_high_level(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="high_entropy_write", weight=THRESHOLD_HIGH))
        assert engine.current_level() == Severity.HIGH

    def test_score_reaches_critical_level(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="canary_modified", weight=THRESHOLD_CRITICAL))
        assert engine.current_level() == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Window eviction — old signals are removed
# ---------------------------------------------------------------------------

class TestWindowEviction:
    def test_signal_outside_window_does_not_contribute(self):
        """A signal with a timestamp before the window boundary contributes 0."""
        engine = ScoringEngine(window_seconds=10)
        old_ts = time.time() - 20  # 20 seconds ago, outside 10s window
        engine.submit(_sig(name="canary_modified", weight=50, timestamp=old_ts))
        assert engine.current_score() == 0

    def test_signal_inside_window_contributes(self):
        engine = ScoringEngine(window_seconds=10)
        recent_ts = time.time() - 5
        engine.submit(_sig(name="canary_modified", weight=50, timestamp=recent_ts))
        assert engine.current_score() == 50

    def test_mix_of_old_and_new_signals(self):
        engine = ScoringEngine(window_seconds=10)
        old_ts = time.time() - 20
        recent_ts = time.time() - 1
        engine.submit(_sig(name="canary_modified", weight=50, timestamp=old_ts))
        engine.submit(_sig(name="high_entropy_write", weight=30, timestamp=recent_ts))
        # Only the recent signal should score
        assert engine.current_score() == 30


# ---------------------------------------------------------------------------
# Correlation gating — file_delete only counts when same PID has enc activity
# ---------------------------------------------------------------------------

class TestCorrelationGating:
    def test_file_delete_name_is_in_gated_set(self):
        assert "file_delete" in CORRELATION_GATED_NAMES

    def test_isolated_file_delete_contributes_zero(self):
        """A lone file_delete signal (no PID encryption activity) scores 0."""
        engine = ScoringEngine()
        sig = _sig(name="file_delete", weight=15, metadata={"pid": 999})
        engine.submit(sig)
        assert engine.current_score() == 0

    def test_file_delete_with_corroborating_enc_signal_same_pid_counts(self):
        """file_delete contributes weight when same PID also emitted enc signal."""
        engine = ScoringEngine()
        pid = 100
        # First emit an encryption signal for pid=100
        enc_sig = _sig(
            name="high_entropy_write", weight=20,
            metadata={"pid": pid}
        )
        del_sig = _sig(
            name="file_delete", weight=15,
            metadata={"pid": pid}
        )
        engine.submit(enc_sig)
        engine.submit(del_sig)
        # Both signals should contribute: 20 + 15 = 35
        assert engine.current_score() == 35

    def test_file_delete_different_pid_from_enc_does_not_count(self):
        """file_delete from pid=200 when only pid=100 has enc activity scores 0 for delete."""
        engine = ScoringEngine()
        enc_sig = _sig(name="high_entropy_write", weight=20, metadata={"pid": 100})
        del_sig = _sig(name="file_delete", weight=15, metadata={"pid": 200})
        engine.submit(enc_sig)
        engine.submit(del_sig)
        # Only enc_sig counts; del_sig pid=200 has no enc corroboration
        assert engine.current_score() == 20

    def test_file_delete_without_pid_does_not_count(self):
        """file_delete with no PID metadata never correlates."""
        engine = ScoringEngine()
        del_sig = _sig(name="file_delete", weight=15)
        engine.submit(del_sig)
        assert engine.current_score() == 0


# ---------------------------------------------------------------------------
# Trusted actor classifier — signals marked trusted are excluded from score
# ---------------------------------------------------------------------------

class TestTrustedActorClassifier:
    def test_trusted_signal_is_stamped_actor_trusted_true(self):
        """The classifier result is written to metadata['actor_trusted']."""
        trusted_name = "high_entropy_write"

        def always_trust(sig):
            return sig.name == trusted_name

        engine = ScoringEngine(is_trusted_actor=always_trust)
        sig = _sig(name=trusted_name, weight=50)
        engine.submit(sig)
        assert sig.metadata.get("actor_trusted") is True

    def test_trusted_signal_excluded_from_score(self):
        """A trusted signal contributes 0 to the score."""
        def always_trust(sig):
            return True

        engine = ScoringEngine(is_trusted_actor=always_trust)
        engine.submit(_sig(name="canary_modified", weight=50))
        assert engine.current_score() == 0

    def test_untrusted_signal_not_stamped_as_trusted(self):
        def never_trust(sig):
            return False

        engine = ScoringEngine(is_trusted_actor=never_trust)
        sig = _sig(name="canary_modified", weight=50)
        engine.submit(sig)
        assert sig.metadata.get("actor_trusted") is False

    def test_untrusted_signal_contributes_full_weight(self):
        def never_trust(sig):
            return False

        engine = ScoringEngine(is_trusted_actor=never_trust)
        engine.submit(_sig(name="canary_modified", weight=50))
        assert engine.current_score() == 50

    def test_classifier_exception_is_swallowed_and_signal_not_trusted(self):
        """An exception in the classifier is caught; signal is NOT trusted."""
        def exploding_classifier(sig):
            raise RuntimeError("classifier boom")

        engine = ScoringEngine(is_trusted_actor=exploding_classifier)
        sig = _sig(name="canary_modified", weight=50)
        engine.submit(sig)
        # Should not propagate; signal treated as untrusted
        assert sig.metadata.get("actor_trusted") is False
        assert engine.current_score() == 50

    def test_pre_stamped_actor_trusted_is_not_overwritten(self):
        """If actor_trusted is already in metadata, classifier is skipped."""
        call_count = []

        def counting_classifier(sig):
            call_count.append(1)
            return False

        engine = ScoringEngine(is_trusted_actor=counting_classifier)
        sig = _sig(name="canary_modified", weight=50,
                   metadata={"actor_trusted": True})
        engine.submit(sig)
        assert len(call_count) == 0  # classifier never called
        assert engine.current_score() == 0  # pre-stamped trusted → excluded


# ---------------------------------------------------------------------------
# has_encryption_activity
# ---------------------------------------------------------------------------

class TestHasEncryptionActivity:
    def test_returns_false_when_no_signals(self):
        engine = ScoringEngine()
        assert engine.has_encryption_activity() is False

    def test_returns_true_when_enc_signal_present(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="canary_modified", weight=10))
        assert engine.has_encryption_activity() is True

    def test_non_enc_signal_does_not_count(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="vssadmin_delete_shadows", weight=10))
        # vssadmin is not in ENCRYPTION_SIGNAL_NAMES
        assert "vssadmin_delete_shadows" not in ENCRYPTION_SIGNAL_NAMES
        assert engine.has_encryption_activity() is False

    def test_exclude_parameter_excludes_the_signal_itself(self):
        """With exclude=sig, a lone enc signal does not corroborate itself."""
        engine = ScoringEngine()
        sig = _sig(name="canary_modified", weight=10)
        engine.submit(sig)
        assert engine.has_encryption_activity(exclude=sig) is False

    def test_trusted_signal_does_not_count_as_encryption_activity(self):
        def always_trust(sig):
            return True

        engine = ScoringEngine(is_trusted_actor=always_trust)
        engine.submit(_sig(name="canary_modified", weight=10))
        assert engine.has_encryption_activity() is False


# ---------------------------------------------------------------------------
# forget_pid
# ---------------------------------------------------------------------------

class TestForgetPid:
    def test_forget_pid_removes_signals_with_that_pid(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="high_entropy_write", weight=20, metadata={"pid": 42}))
        engine.submit(_sig(name="canary_modified", weight=30, metadata={"pid": 99}))
        removed = engine.forget_pid(42)
        assert removed == 1
        # Only pid=99 signal remains
        assert engine.current_score() == 30

    def test_forget_pid_returns_count_of_removed_signals(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="high_entropy_write", weight=20, metadata={"pid": 7}))
        engine.submit(_sig(name="magic_bytes_lost", weight=15, metadata={"pid": 7}))
        engine.submit(_sig(name="canary_modified", weight=10))
        removed = engine.forget_pid(7)
        assert removed == 2

    def test_forget_nonexistent_pid_removes_nothing(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="canary_modified", weight=10))
        removed = engine.forget_pid(9999)
        assert removed == 0

    def test_signals_without_pid_are_retained_after_forget(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="canary_modified", weight=30))  # no pid
        engine.submit(_sig(name="high_entropy_write", weight=20, metadata={"pid": 5}))
        engine.forget_pid(5)
        assert engine.current_score() == 30


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

class TestReset:
    def test_reset_clears_all_signals(self):
        engine = ScoringEngine()
        engine.submit(_sig(name="canary_modified", weight=50))
        engine.reset()
        assert engine.current_score() == 0
        assert engine.recent_signals() == []


# ---------------------------------------------------------------------------
# recent_signals
# ---------------------------------------------------------------------------

class TestRecentSignals:
    def test_returns_empty_list_when_no_signals(self):
        engine = ScoringEngine()
        assert engine.recent_signals() == []

    def test_returns_submitted_signals(self):
        engine = ScoringEngine()
        sig = _sig(name="canary_modified", weight=10)
        engine.submit(sig)
        assert sig in engine.recent_signals()

    def test_limit_parameter_caps_result(self):
        engine = ScoringEngine()
        for i in range(10):
            engine.submit(_sig(name="canary_modified", weight=1))
        assert len(engine.recent_signals(limit=3)) == 3


# ---------------------------------------------------------------------------
# Subscriber / listener
# ---------------------------------------------------------------------------

class TestSubscriber:
    def test_listener_called_on_submit(self):
        received = []
        engine = ScoringEngine()
        engine.subscribe(lambda sig, score, level: received.append((sig, score, level)))
        sig = _sig(name="canary_modified", weight=10)
        engine.submit(sig)
        assert len(received) == 1
        assert received[0][0] is sig

    def test_listener_exception_does_not_crash_engine(self):
        def bad_listener(sig, score, level):
            raise RuntimeError("listener boom")

        engine = ScoringEngine()
        engine.subscribe(bad_listener)
        # Should not raise
        engine.submit(_sig(name="canary_modified", weight=10))
        assert engine.current_score() == 10
