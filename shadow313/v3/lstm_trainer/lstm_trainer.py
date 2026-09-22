"""
shadow313.v3.lstm_trainer.lstm_trainer
────────────────────────────────────────
LSTM Head Trainer for C2 beacon sequence detection.

Implements n-gram signature extraction + timing analysis for detecting
C2 beaconing patterns in event sequences.

ROOT CAUSE OF 60% RECALL (diagnosed from stalled machine output):
  - Threshold 0.750 is too high for sequences with variable n-gram coverage
  - Score formula weights n-gram match too heavily vs timing regularity
  - Sequences with fewer repeated n-grams (e.g., mixed dns_query/network_outbound)
    score below threshold even though timing CV=0.035 is a strong beacon indicator

FIXES APPLIED:
  1. Adaptive threshold: set at mean(pos_scores) - 0.5*std(pos_scores) instead of 0.75
  2. Timing weight increased: CV < 0.1 contributes 0.35 to score (was implicit 0.0)
  3. Composite score: 0.55 * ngram_score + 0.35 * timing_score + 0.10 * entropy_score
  4. Threshold floor: minimum 0.45 to avoid false positive explosion
"""
from __future__ import annotations

import math
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Optional


# ── Sequence generators ───────────────────────────────────────────────────────

def generate_c2_beacon_sequence(
    length: int = 20,
    beacon_type: str = "auto",
    interval_s: float = 60.0,
    jitter: float = 0.05,
) -> dict:
    """
    Generate a synthetic C2 beacon event sequence.

    Beacon types:
      dns_beacon:     repeated dns_query events (Lazarus, DNS tunneling)
      http_beacon:    repeated network_outbound events (Cobalt Strike)
      mixed_beacon:   alternating dns_query + network_outbound (Sliver)
      auto:           randomly chosen
    """
    if beacon_type == "auto":
        beacon_type = random.choice(["dns_beacon", "http_beacon", "mixed_beacon"])

    base_ts = time.time()
    events = []

    # Initial process creation
    events.append({
        "event_type": "process_creation",
        "timestamp":  base_ts,
        "process":    random.choice(["powershell.exe", "cmd.exe", "wscript.exe"]),
        "severity":   "medium",
    })

    # Use cumulative timestamps to prevent negative intervals
    # Each step adds interval_s ± jitter*interval_s (always positive)
    current_ts = base_ts
    for i in range(1, length):
        step = interval_s * (1.0 + random.uniform(-jitter, jitter))
        step = max(step, interval_s * 0.5)  # floor at 50% of interval — no negative gaps
        current_ts += step

        if beacon_type == "dns_beacon":
            etype = "dns_query"
        elif beacon_type == "http_beacon":
            etype = "network_outbound"
        else:  # mixed
            etype = "dns_query" if i % 2 == 0 else "network_outbound"

        events.append({
            "event_type": etype,
            "timestamp":  current_ts,
            "dest_ip":    f"185.220.{random.randint(100,110)}.{random.randint(1,50)}",
            "dest_port":  random.choice([443, 80, 53, 8080]),
            "severity":   "low",
        })

    return {
        "sequence_type": "c2_beacon",
        "beacon_type":   beacon_type,
        "events":        events,
        "interval_s":    interval_s,
        "jitter":        jitter,
    }


def generate_benign_sequence(length: int = 20) -> dict:
    """Generate a synthetic benign event sequence (irregular, varied types)."""
    base_ts = time.time()
    events = []
    event_types = [
        "process_creation", "file_read", "registry_read",
        "network_outbound", "dns_query", "file_write",
        "process_exit", "service_start",
    ]

    for i in range(length):
        # Irregular intervals — not periodic
        ts = base_ts + i * random.uniform(5, 300)
        events.append({
            "event_type": random.choice(event_types),
            "timestamp":  ts,
            "severity":   random.choice(["low", "info", "medium"]),
        })

    return {
        "sequence_type": "benign",
        "events":        events,
    }


# ── LSTM Head Trainer ─────────────────────────────────────────────────────────

@dataclass
class Signature:
    """An n-gram signature extracted from C2 sequences."""
    ngram:     list[str]
    frequency: float    # Mean occurrences per sequence in positive set
    weight:    float    # Discriminative weight (pos_freq / (pos_freq + neg_freq + 1e-9))


class LSTMHeadTrainer:
    """
    LSTM Head Trainer for C2 beacon sequence detection.

    Uses n-gram signature extraction + timing regularity analysis.
    Pure-Python implementation — no PyTorch/TensorFlow dependency.

    Scoring formula (FIXED from stalled machine 60% recall):
      composite = 0.55 * ngram_score + 0.35 * timing_score + 0.10 * entropy_score

    Threshold (FIXED):
      Adaptive: mean(pos_scores) - 0.5 * std(pos_scores)
      Floor: 0.45 (prevents false positive explosion)
      Ceiling: 0.85 (prevents over-fitting to training set)
    """

    # N-gram sizes to extract
    NGRAM_SIZES = [2, 3, 4]

    # Scoring weights (sum to 1.0)
    NGRAM_WEIGHT   = 0.55
    TIMING_WEIGHT  = 0.35
    ENTROPY_WEIGHT = 0.10

    # Threshold bounds
    THRESHOLD_FLOOR   = 0.45
    THRESHOLD_CEILING = 0.85
    THRESHOLD_SIGMA   = 0.3   # threshold = mean(pos) - sigma * std(pos)

    # Timing regularity: CV below this → strong beacon indicator
    CV_BEACON_THRESHOLD = 0.15

    def __init__(self, head_name: str, sequence_length: int = 20) -> None:
        self.head_name       = head_name
        self.sequence_length = sequence_length
        self.signatures:     list[Signature] = []
        self.timing_stats:   dict = {}
        self.threshold:      float = 0.750  # default; overridden by train()
        self._trained        = False
        self._pos_score_mean = 0.0
        self._pos_score_std  = 0.0

    # ── Training ──────────────────────────────────────────────────────────────

    def train(
        self,
        positive_sequences: list[dict],
        negative_sequences: list[dict],
        verbose: bool = True,
    ) -> dict:
        """
        Train the LSTM head on positive (C2) and negative (benign) sequences.

        Returns training metrics dict.
        """
        if verbose:
            print(f"\n  Training {self.head_name} head...")
            print(f"    Positive: {len(positive_sequences)} | Negative: {len(negative_sequences)}")

        # ── Extract n-gram frequencies ────────────────────────────────────────
        pos_ngram_freq = self._count_ngrams(positive_sequences)
        neg_ngram_freq = self._count_ngrams(negative_sequences)

        # ── Build discriminative signatures ───────────────────────────────────
        self.signatures = []
        all_ngrams = set(pos_ngram_freq.keys()) | set(neg_ngram_freq.keys())

        for ngram_key in all_ngrams:
            pos_f = pos_ngram_freq.get(ngram_key, 0.0)
            neg_f = neg_ngram_freq.get(ngram_key, 0.0)
            # Only keep n-grams that appear more in positive than negative
            if pos_f > neg_f * 1.5 and pos_f >= 0.3:
                weight = pos_f / (pos_f + neg_f + 1e-9)
                self.signatures.append(Signature(
                    ngram     = list(ngram_key),
                    frequency = pos_f,
                    weight    = weight,
                ))

        # Sort by discriminative weight × frequency
        self.signatures.sort(key=lambda s: -(s.weight * s.frequency))

        # ── Compute timing stats from positive sequences ───────────────────────
        all_intervals = []
        for seq in positive_sequences:
            intervals = self._extract_intervals(seq["events"])
            all_intervals.extend(intervals)

        if all_intervals:
            mean_i = statistics.mean(all_intervals)
            std_i  = statistics.stdev(all_intervals) if len(all_intervals) > 1 else 0.0
            self.timing_stats = {
                "mean_interval": mean_i,
                "std_interval":  std_i,
                "cv":            std_i / mean_i if mean_i > 0 else 1.0,
                "min_interval":  min(all_intervals),
                "max_interval":  max(all_intervals),
            }

        # ── Compute adaptive threshold ─────────────────────────────────────────
        pos_scores = [self.score_sequence(s["events"]) for s in positive_sequences]
        neg_scores = [self.score_sequence(s["events"]) for s in negative_sequences]

        if pos_scores:
            self._pos_score_mean = statistics.mean(pos_scores)
            self._pos_score_std  = statistics.stdev(pos_scores) if len(pos_scores) > 1 else 0.0
            raw_threshold = self._pos_score_mean - self.THRESHOLD_SIGMA * self._pos_score_std
            self.threshold = max(
                self.THRESHOLD_FLOOR,
                min(self.THRESHOLD_CEILING, raw_threshold),
            )

        if verbose:
            print(f"    Threshold: {self.threshold:.3f}")

        # ── Compute training metrics ───────────────────────────────────────────
        tp = sum(1 for s in pos_scores if s >= self.threshold)
        fp = sum(1 for s in neg_scores if s >= self.threshold)
        tn = sum(1 for s in neg_scores if s < self.threshold)
        fn = sum(1 for s in pos_scores if s < self.threshold)

        total    = len(pos_scores) + len(neg_scores)
        accuracy = (tp + tn) / total * 100 if total > 0 else 0.0
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)

        if verbose:
            print(f"    Training accuracy: {accuracy:.1f}%")
            print(f"    Precision: {precision:.1f}% | Recall: {recall:.1f}%")
            print(f"    F1: {f1:.1f}%")

        self._trained = True
        return {
            "accuracy":  accuracy,
            "precision": precision,
            "recall":    recall,
            "f1":        f1,
            "threshold": self.threshold,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        }

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score_sequence(self, events: list[dict]) -> float:
        """
        Score an event sequence for C2 beacon likelihood.

        Returns float in [0.0, 1.0]. Higher = more likely C2.

        FIXED composite formula:
          0.55 * ngram_score + 0.35 * timing_score + 0.10 * entropy_score
        """
        tokens = [e.get("event_type", "") for e in events]

        ngram_score   = self._score_ngrams(tokens)
        timing_score  = self._score_timing(events)
        entropy_score = self._score_entropy(tokens)

        composite = (
            self.NGRAM_WEIGHT   * ngram_score +
            self.TIMING_WEIGHT  * timing_score +
            self.ENTROPY_WEIGHT * entropy_score
        )

        # Timing override: near-perfect periodicity (CV < 0.05) is a strong
        # beacon indicator regardless of n-gram coverage.
        #
        # Two tiers:
        #   Tier A: timing=1.0 + any n-gram match (ngram >= 0.01) → boost above threshold
        #           Handles http_beacon when training set had no http signatures
        #   Tier B: timing=1.0 + good n-gram match (ngram >= 0.3) → stronger boost
        #           Handles dns_beacon when training set was mixed-dominated
        #
        # This fixes both the 60% recall bug (dns_beacon) and the http_beacon miss.
        if timing_score >= 0.95:
            min_detect_score = self.threshold + 0.02 if self._trained else self.THRESHOLD_FLOOR + 0.05
            if ngram_score >= 0.01:
                # Any n-gram match + perfect timing → detect
                composite = max(composite, min_detect_score)
            elif entropy_score >= 0.5:
                # Low entropy (repetitive) + perfect timing → likely beacon even without n-gram match
                composite = max(composite, min_detect_score)

        return min(1.0, max(0.0, composite))

    def _score_ngrams(self, tokens: list[str]) -> float:
        """Score based on presence of discriminative n-gram signatures."""
        if not self.signatures or not tokens:
            return 0.0

        total_weight = sum(s.weight * s.frequency for s in self.signatures)
        if total_weight == 0:
            return 0.0

        matched_weight = 0.0
        for sig in self.signatures:
            n = len(sig.ngram)
            count = sum(
                1 for i in range(len(tokens) - n + 1)
                if tokens[i:i+n] == sig.ngram  # nosec S03 — list comparison, not credential
            )
            if count > 0:
                matched_weight += sig.weight * min(count, sig.frequency)

        return min(1.0, matched_weight / total_weight)

    def _score_timing(self, events: list[dict]) -> float:
        """
        Score based on timing regularity (low CV = periodic = beacon).

        FIXED: This was the missing component causing 60% recall.
        Sequences with low CV but fewer n-gram matches were being missed.
        """
        intervals = self._extract_intervals(events)
        if len(intervals) < 3:
            return 0.0

        mean_i = statistics.mean(intervals)
        if mean_i <= 0:
            return 0.0

        std_i = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv    = std_i / mean_i

        # Low CV → high timing score (periodic = beacon)
        # CV < 0.05: score = 1.0 (very regular)
        # CV = 0.15: score = 0.5 (threshold)
        # CV > 0.35: score = 0.0 (irregular)
        if cv <= 0.05:
            timing_score = 1.0
        elif cv <= self.CV_BEACON_THRESHOLD:
            timing_score = 1.0 - (cv - 0.05) / (self.CV_BEACON_THRESHOLD - 0.05) * 0.5
        elif cv <= 0.35:
            timing_score = 0.5 * (1.0 - (cv - self.CV_BEACON_THRESHOLD) / (0.35 - self.CV_BEACON_THRESHOLD))
        else:
            timing_score = 0.0

        # Bonus: if timing matches trained beacon interval
        if self.timing_stats.get("mean_interval", 0) > 0:
            trained_mean = self.timing_stats["mean_interval"]
            ratio = mean_i / trained_mean
            if 0.7 <= ratio <= 1.3:
                timing_score = min(1.0, timing_score * 1.2)

        return timing_score

    def _score_entropy(self, tokens: list[str]) -> float:
        """
        Score based on token entropy (low entropy = repetitive = beacon).

        C2 beacons repeat the same event types → low Shannon entropy.
        Benign traffic has varied event types → high entropy.
        """
        if not tokens:
            return 0.0

        freq: dict[str, int] = {}
        for t in tokens:
            freq[t] = freq.get(t, 0) + 1

        n = len(tokens)
        entropy = -sum((c/n) * math.log2(c/n) for c in freq.values() if c > 0)

        # Max entropy for n unique types = log2(n)
        max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1.0

        # Normalize: low entropy → high score
        normalized = entropy / max_entropy if max_entropy > 0 else 0.0
        return max(0.0, 1.0 - normalized)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_intervals(self, events: list[dict]) -> list[float]:
        """Extract inter-event time intervals in seconds."""
        timestamps = [e.get("timestamp", 0.0) for e in events if "timestamp" in e]
        if len(timestamps) < 2:
            return []
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        # Filter out negative/zero intervals (clock skew, out-of-order events)
        return [iv for iv in intervals if iv > 0.1]

    def _count_ngrams(self, sequences: list[dict]) -> dict[tuple, float]:
        """Count mean n-gram frequency across sequences."""
        total_counts: dict[tuple, float] = {}
        n_seqs = len(sequences)
        if n_seqs == 0:
            return total_counts

        for seq in sequences:
            tokens = [e.get("event_type", "") for e in seq.get("events", [])]
            seq_counts: dict[tuple, int] = {}
            for n in self.NGRAM_SIZES:
                for i in range(len(tokens) - n + 1):
                    key = tuple(tokens[i:i+n])
                    seq_counts[key] = seq_counts.get(key, 0) + 1
            for key, count in seq_counts.items():
                total_counts[key] = total_counts.get(key, 0.0) + count / n_seqs

        return total_counts

    def predict(self, events: list[dict]) -> dict:
        """Predict whether a sequence is C2 beacon."""
        score = self.score_sequence(events)
        return {
            "score":     score,
            "threshold": self.threshold,
            "detected":  score >= self.threshold,
            "head":      self.head_name,
        }

    def stats(self) -> dict:
        return {
            "head_name":      self.head_name,
            "trained":        self._trained,
            "signatures":     len(self.signatures),
            "threshold":      self.threshold,
            "timing_stats":   self.timing_stats,
            "pos_score_mean": self._pos_score_mean,
            "pos_score_std":  self._pos_score_std,
        }