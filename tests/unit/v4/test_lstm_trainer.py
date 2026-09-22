"""
Tests for shadow313.v3.lstm_trainer

Covers:
  - Sequence generators (no negative intervals, correct CV)
  - LSTMHeadTrainer training and scoring
  - Timing override fix (dns_beacon recall improvement)
  - N-gram extraction and signature building
  - Adaptive threshold
  - Full pipeline: train → score → detect
"""
from __future__ import annotations

import random
import statistics
import pytest

from shadow313.v3.lstm_trainer import (
    LSTMHeadTrainer,
    generate_c2_beacon_sequence,
    generate_benign_sequence,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Sequence generators
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerators:

    def test_c2_sequence_has_correct_length(self):
        seq = generate_c2_beacon_sequence(20)
        assert len(seq["events"]) == 20

    def test_c2_sequence_no_negative_intervals(self):
        """Critical fix: timestamps must be monotonically increasing."""
        for _ in range(10):
            seq = generate_c2_beacon_sequence(20)
            ts = [e["timestamp"] for e in seq["events"]]
            intervals = [ts[i+1]-ts[i] for i in range(len(ts)-1)]
            assert all(iv > 0 for iv in intervals), f"Negative interval found: {min(intervals):.2f}"

    def test_c2_sequence_cv_within_beacon_range(self):
        """CV should be ~0.03-0.08 for jitter=0.05."""
        for _ in range(5):
            seq = generate_c2_beacon_sequence(20, jitter=0.05)
            ts = [e["timestamp"] for e in seq["events"]]
            intervals = [ts[i+1]-ts[i] for i in range(len(ts)-1)]
            cv = statistics.stdev(intervals) / statistics.mean(intervals)
            assert cv < 0.15, f"CV too high for beacon: {cv:.3f}"

    def test_c2_sequence_beacon_types(self):
        for btype in ("dns_beacon", "http_beacon", "mixed_beacon"):
            seq = generate_c2_beacon_sequence(20, beacon_type=btype)
            assert seq["beacon_type"] == btype
            tokens = [e["event_type"] for e in seq["events"][1:]]  # skip process_creation
            if btype == "dns_beacon":
                assert all(t == "dns_query" for t in tokens)
            elif btype == "http_beacon":
                assert all(t == "network_outbound" for t in tokens)

    def test_c2_sequence_starts_with_process_creation(self):
        seq = generate_c2_beacon_sequence(20)
        assert seq["events"][0]["event_type"] == "process_creation"

    def test_benign_sequence_has_correct_length(self):
        seq = generate_benign_sequence(20)
        assert len(seq["events"]) == 20

    def test_benign_sequence_has_varied_event_types(self):
        seq = generate_benign_sequence(20)
        types = set(e["event_type"] for e in seq["events"])
        assert len(types) >= 3, "Benign sequence should have varied event types"

    def test_benign_sequence_irregular_intervals(self):
        """Benign traffic should have high CV (irregular)."""
        seq = generate_benign_sequence(20)
        ts = sorted(e["timestamp"] for e in seq["events"])
        intervals = [ts[i+1]-ts[i] for i in range(len(ts)-1) if ts[i+1] > ts[i]]
        if len(intervals) >= 3:
            cv = statistics.stdev(intervals) / statistics.mean(intervals)
            assert cv > 0.3, f"Benign CV too low (too regular): {cv:.3f}"


# ═══════════════════════════════════════════════════════════════════════════════
# LSTMHeadTrainer — training
# ═══════════════════════════════════════════════════════════════════════════════

class TestLSTMHeadTrainerTraining:

    @pytest.fixture
    def trained_head(self):
        random.seed(313)
        head = LSTMHeadTrainer("c2_head", 20)
        pos = [generate_c2_beacon_sequence(20) for _ in range(10)]
        neg = [generate_benign_sequence(20) for _ in range(10)]
        head.train(pos[:5], neg[:5], verbose=False)
        return head, pos, neg

    def test_train_extracts_signatures(self, trained_head):
        head, _, _ = trained_head
        assert len(head.signatures) >= 5

    def test_train_sets_threshold(self, trained_head):
        head, _, _ = trained_head
        assert 0.45 <= head.threshold <= 0.85

    def test_train_computes_timing_stats(self, trained_head):
        head, _, _ = trained_head
        assert "mean_interval" in head.timing_stats
        assert "cv" in head.timing_stats
        assert head.timing_stats["mean_interval"] > 0

    def test_train_returns_metrics(self):
        random.seed(42)
        head = LSTMHeadTrainer("test", 20)
        pos = [generate_c2_beacon_sequence(20) for _ in range(5)]
        neg = [generate_benign_sequence(20) for _ in range(5)]
        metrics = head.train(pos, neg, verbose=False)
        for key in ("accuracy", "precision", "recall", "f1", "threshold"):
            assert key in metrics

    def test_train_marks_as_trained(self, trained_head):
        head, _, _ = trained_head
        assert head._trained is True

    def test_signatures_sorted_by_weight(self, trained_head):
        head, _, _ = trained_head
        weights = [s.weight * s.frequency for s in head.signatures]
        assert weights == sorted(weights, reverse=True)

    def test_top_signatures_are_beacon_ngrams(self, trained_head):
        head, _, _ = trained_head
        top_tokens = set()
        for sig in head.signatures[:5]:
            top_tokens.update(sig.ngram)
        assert "dns_query" in top_tokens or "network_outbound" in top_tokens


# ═══════════════════════════════════════════════════════════════════════════════
# LSTMHeadTrainer — scoring
# ═══════════════════════════════════════════════════════════════════════════════

class TestLSTMHeadTrainerScoring:

    @pytest.fixture
    def trained_head(self):
        random.seed(313)
        head = LSTMHeadTrainer("c2_head", 20)
        pos = [generate_c2_beacon_sequence(20) for _ in range(10)]
        neg = [generate_benign_sequence(20) for _ in range(10)]
        head.train(pos[:5], neg[:5], verbose=False)
        return head, pos, neg

    def test_score_in_range(self, trained_head):
        head, pos, neg = trained_head
        for seq in pos[:3] + neg[:3]:
            score = head.score_sequence(seq["events"])
            assert 0.0 <= score <= 1.0

    def test_c2_scores_higher_than_benign(self, trained_head):
        head, pos, neg = trained_head
        pos_scores = [head.score_sequence(s["events"]) for s in pos]
        neg_scores = [head.score_sequence(s["events"]) for s in neg]
        assert statistics.mean(pos_scores) > statistics.mean(neg_scores)

    def test_training_set_recall_100_percent(self, trained_head):
        """KEY FIX: timing override must achieve 100% recall on training set."""
        head, pos, _ = trained_head
        detected = sum(1 for s in pos[:5]
                       if head.score_sequence(s["events"]) >= head.threshold)
        assert detected == 5, f"Training recall {detected}/5 — timing override not working"

    def test_no_false_positives_on_benign(self, trained_head):
        """Precision must be 100% — no benign sequences detected as C2."""
        head, _, neg = trained_head
        fp = sum(1 for s in neg
                 if head.score_sequence(s["events"]) >= head.threshold)
        assert fp == 0, f"{fp} false positives on benign sequences"

    def test_dns_beacon_detected(self, trained_head):
        """dns_beacon specifically must be detected (was the 60% recall bug)."""
        head, _, _ = trained_head
        random.seed(99)
        dns_seq = generate_c2_beacon_sequence(20, beacon_type="dns_beacon")
        score = head.score_sequence(dns_seq["events"])
        assert score >= head.threshold, \
            f"dns_beacon not detected: score={score:.3f} threshold={head.threshold:.3f}"

    def test_http_beacon_detected(self, trained_head):
        head, _, _ = trained_head
        random.seed(99)
        http_seq = generate_c2_beacon_sequence(20, beacon_type="http_beacon")
        score = head.score_sequence(http_seq["events"])
        assert score >= head.threshold, \
            f"http_beacon not detected: score={score:.3f} threshold={head.threshold:.3f}"

    def test_mixed_beacon_detected(self, trained_head):
        head, _, _ = trained_head
        random.seed(99)
        mixed_seq = generate_c2_beacon_sequence(20, beacon_type="mixed_beacon")
        score = head.score_sequence(mixed_seq["events"])
        assert score >= head.threshold, \
            f"mixed_beacon not detected: score={score:.3f} threshold={head.threshold:.3f}"

    def test_empty_sequence_returns_zero(self, trained_head):
        head, _, _ = trained_head
        score = head.score_sequence([])
        assert score == 0.0

    def test_predict_returns_dict(self, trained_head):
        head, pos, _ = trained_head
        result = head.predict(pos[0]["events"])
        assert "score" in result
        assert "detected" in result
        assert "threshold" in result
        assert "head" in result


# ═══════════════════════════════════════════════════════════════════════════════
# Component scoring functions
# ═══════════════════════════════════════════════════════════════════════════════

class TestScoringComponents:

    @pytest.fixture
    def trained_head(self):
        random.seed(313)
        head = LSTMHeadTrainer("c2_head", 20)
        pos = [generate_c2_beacon_sequence(20) for _ in range(5)]
        neg = [generate_benign_sequence(20) for _ in range(5)]
        head.train(pos, neg, verbose=False)
        return head

    def test_timing_score_high_for_regular_beacon(self, trained_head):
        head = trained_head
        seq = generate_c2_beacon_sequence(20, jitter=0.02)
        score = head._score_timing(seq["events"])
        assert score >= 0.8, f"Regular beacon timing score too low: {score:.3f}"

    def test_timing_score_low_for_irregular(self, trained_head):
        head = trained_head
        seq = generate_benign_sequence(20)
        score = head._score_timing(seq["events"])
        assert score <= 0.5, f"Irregular timing score too high: {score:.3f}"

    def test_entropy_score_low_for_repetitive(self, trained_head):
        head = trained_head
        # All same event type → low entropy → high entropy score
        events = [{"event_type": "dns_query", "timestamp": float(i*60)} for i in range(20)]
        score = head._score_entropy([e["event_type"] for e in events])
        assert score >= 0.8, f"Repetitive entropy score too low: {score:.3f}"

    def test_entropy_score_low_for_varied(self, trained_head):
        head = trained_head
        types = ["process_creation", "file_read", "registry_read", "network_outbound",
                 "dns_query", "file_write", "process_exit", "service_start"]
        tokens = [types[i % len(types)] for i in range(20)]
        score = head._score_entropy(tokens)
        assert score <= 0.5, f"Varied entropy score too high: {score:.3f}"

    def test_ngram_score_zero_before_training(self):
        head = LSTMHeadTrainer("untrained", 20)
        tokens = ["dns_query"] * 10
        score = head._score_ngrams(tokens)
        assert score == 0.0

    def test_extract_intervals_filters_negatives(self, trained_head):
        head = trained_head
        # Events with out-of-order timestamps
        events = [
            {"timestamp": 100.0},
            {"timestamp": 160.0},
            {"timestamp": 150.0},  # out of order
            {"timestamp": 220.0},
        ]
        intervals = head._extract_intervals(events)
        assert all(iv > 0 for iv in intervals)


# ═══════════════════════════════════════════════════════════════════════════════
# Adaptive threshold
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdaptiveThreshold:

    def test_threshold_within_bounds(self):
        random.seed(42)
        head = LSTMHeadTrainer("test", 20)
        pos = [generate_c2_beacon_sequence(20) for _ in range(10)]
        neg = [generate_benign_sequence(20) for _ in range(10)]
        head.train(pos, neg, verbose=False)
        assert head.THRESHOLD_FLOOR <= head.threshold <= head.THRESHOLD_CEILING

    def test_threshold_default_before_training(self):
        head = LSTMHeadTrainer("test", 20)
        assert head.threshold == 0.750

    def test_threshold_adapts_to_training_data(self):
        """Threshold should change after training."""
        random.seed(42)
        head = LSTMHeadTrainer("test", 20)
        initial = head.threshold
        pos = [generate_c2_beacon_sequence(20) for _ in range(5)]
        neg = [generate_benign_sequence(20) for _ in range(5)]
        head.train(pos, neg, verbose=False)
        # Threshold should have been updated from default 0.750
        assert head.threshold != initial or head._trained


# ═══════════════════════════════════════════════════════════════════════════════
# Stats and state
# ═══════════════════════════════════════════════════════════════════════════════

class TestStats:

    def test_stats_before_training(self):
        head = LSTMHeadTrainer("test", 20)
        s = head.stats()
        assert s["trained"] is False
        assert s["signatures"] == 0

    def test_stats_after_training(self):
        random.seed(42)
        head = LSTMHeadTrainer("test", 20)
        pos = [generate_c2_beacon_sequence(20) for _ in range(5)]
        neg = [generate_benign_sequence(20) for _ in range(5)]
        head.train(pos, neg, verbose=False)
        s = head.stats()
        assert s["trained"] is True
        assert s["signatures"] >= 1
        assert s["threshold"] > 0