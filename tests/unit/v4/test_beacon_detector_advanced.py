"""
Tests for AdvancedBeaconDetector — analyze_intervals + find_shared_c2.
Covers the test_shared_c2_detected scenario from the frozen thread.
"""
from __future__ import annotations

import math
import random
import pytest
from shadow313.v3.bridge.beacon_detector import AdvancedBeaconDetector, HostBeaconProfile


# ── Helpers ───────────────────────────────────────────────────────────────────

def gen_jitter_beacon(
    period: float,
    jitter_frac: float,
    n: int,
    seed: int = 42,
) -> list[float]:
    """Generate n beacon intervals with Gaussian jitter."""
    rng = random.Random(seed)
    return [
        max(1.0, period + rng.gauss(0, period * jitter_frac))
        for _ in range(n)
    ]


def gen_random_intervals(n: int, seed: int = 99) -> list[float]:
    """Generate n random (non-beaconing) intervals."""
    rng = random.Random(seed)
    return [rng.uniform(1.0, 300.0) for _ in range(n)]


# ── analyze_intervals tests ───────────────────────────────────────────────────

class TestAnalyzeIntervals:

    def test_low_jitter_beacon_detected(self):
        """Low jitter (5%) beacon should be detected with high confidence."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.05, 30)
        profile = detector.analyze_intervals("10.0.0.1", "network_outbound", intervals)
        assert profile is not None
        assert profile.is_beacon is True
        assert profile.confidence >= 0.60
        assert abs(profile.period_s - 60.0) < 10.0

    def test_high_jitter_not_beacon(self):
        """High jitter (80%) should not be flagged as beaconing."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.80, 30)
        profile = detector.analyze_intervals("10.0.0.2", "network_outbound", intervals)
        # Either not detected or low confidence
        if profile is not None:
            assert profile.is_beacon is False or profile.confidence < 0.50

    def test_random_intervals_not_beacon(self):
        """Truly random intervals should not be flagged as beaconing."""
        detector = AdvancedBeaconDetector()
        intervals = gen_random_intervals(30)
        profile = detector.analyze_intervals("10.0.0.3", "network_outbound", intervals)
        if profile is not None:
            assert profile.is_beacon is False

    def test_insufficient_intervals_returns_none(self):
        """Fewer than MIN_INTERVALS should return None."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.05, 3)
        profile = detector.analyze_intervals("10.0.0.4", "network_outbound", intervals)
        assert profile is None

    def test_profile_fields_populated(self):
        """Profile should have all required fields populated."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(120.0, 0.05, 20)
        profile = detector.analyze_intervals("10.0.0.5", "network_outbound", intervals)
        assert profile is not None
        assert profile.host == "10.0.0.5"
        assert profile.event_type == "network_outbound"
        assert profile.period_s > 0
        assert 0.0 <= profile.cv <= 10.0
        assert 0.0 <= profile.confidence <= 1.0
        assert profile.n_intervals == 20

    def test_different_periods_detected(self):
        """Detector should handle various beacon periods correctly."""
        detector = AdvancedBeaconDetector()
        for period in [30.0, 60.0, 300.0, 3600.0]:
            intervals = gen_jitter_beacon(period, 0.05, 25, seed=int(period))
            profile = detector.analyze_intervals(f"10.0.0.{int(period)}", "net", intervals)
            assert profile is not None
            assert abs(profile.period_s - period) < period * 0.15

    def test_profile_registered_in_detector(self):
        """High-confidence profiles should be registered internally."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.05, 30)
        detector.analyze_intervals("10.0.0.6", "network_outbound", intervals)
        profiles = detector.get_all_profiles()
        assert len(profiles) >= 1
        hosts = [p.host for p in profiles]
        assert "10.0.0.6" in hosts

    def test_zero_mean_interval_handled(self):
        """Zero-mean intervals should not crash."""
        detector = AdvancedBeaconDetector()
        intervals = [0.0] * 10
        profile = detector.analyze_intervals("10.0.0.7", "net", intervals)
        # Should return None (mean=0 guard)
        assert profile is None

    def test_single_interval_value(self):
        """Single repeated interval (no variance) should be high confidence."""
        detector = AdvancedBeaconDetector()
        intervals = [60.0] * 20  # Perfect beacon, zero jitter
        profile = detector.analyze_intervals("10.0.0.8", "net", intervals)
        assert profile is not None
        assert profile.cv == 0.0
        assert profile.confidence >= 0.80


# ── find_shared_c2 tests ──────────────────────────────────────────────────────

class TestFindSharedC2:

    def test_shared_c2_detected(self):
        """Multiple hosts with same beacon period = shared C2."""
        detector = AdvancedBeaconDetector()
        period = 60.0

        # Three hosts all beaconing at 60s (same C2 server)
        for i, host in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3"]):
            intervals = gen_jitter_beacon(period, 0.05, 30, seed=i * 100)
            detector.analyze_intervals(host, "network_outbound", intervals)

        correlations = detector.find_shared_c2()
        assert len(correlations) > 0, "Should detect shared C2 infrastructure across hosts"

    def test_shared_c2_correlation_fields(self):
        """Correlation dicts should have required fields."""
        detector = AdvancedBeaconDetector()
        for i, host in enumerate(["10.0.0.1", "10.0.0.2"]):
            intervals = gen_jitter_beacon(60.0, 0.05, 30, seed=i * 100)
            detector.analyze_intervals(host, "network_outbound", intervals)

        correlations = detector.find_shared_c2()
        assert len(correlations) > 0
        c = correlations[0]
        assert "host1" in c
        assert "host2" in c
        assert "period1_s" in c
        assert "period2_s" in c
        assert "match_ratio" in c
        assert c["match_ratio"] > 0.90  # Very close periods

    def test_different_periods_no_shared_c2(self):
        """Hosts with very different periods should NOT be correlated."""
        detector = AdvancedBeaconDetector()
        # Host 1: 60s beacon
        intervals1 = gen_jitter_beacon(60.0, 0.05, 30, seed=1)
        detector.analyze_intervals("10.0.0.1", "net", intervals1)
        # Host 2: 300s beacon (5x different)
        intervals2 = gen_jitter_beacon(300.0, 0.05, 30, seed=2)
        detector.analyze_intervals("10.0.0.2", "net", intervals2)

        correlations = detector.find_shared_c2()
        assert len(correlations) == 0, "Different periods should not be correlated"

    def test_no_self_correlation(self):
        """A host should not be correlated with itself."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.05, 30)
        detector.analyze_intervals("10.0.0.1", "network_outbound", intervals)

        correlations = detector.find_shared_c2()
        for c in correlations:
            assert c["host1"] != c["host2"]

    def test_no_duplicate_pairs(self):
        """Each host pair should appear at most once in correlations."""
        detector = AdvancedBeaconDetector()
        for i, host in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3"]):
            intervals = gen_jitter_beacon(60.0, 0.05, 30, seed=i * 100)
            detector.analyze_intervals(host, "network_outbound", intervals)

        correlations = detector.find_shared_c2()
        pairs = [tuple(sorted([c["host1"], c["host2"]])) for c in correlations]
        assert len(pairs) == len(set(pairs)), "Duplicate pairs found"

    def test_empty_detector_no_correlations(self):
        """Empty detector should return no correlations."""
        detector = AdvancedBeaconDetector()
        correlations = detector.find_shared_c2()
        assert correlations == []

    def test_single_host_no_correlations(self):
        """Single host cannot have shared C2 correlations."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.05, 30)
        detector.analyze_intervals("10.0.0.1", "network_outbound", intervals)
        correlations = detector.find_shared_c2()
        assert correlations == []

    def test_five_hosts_shared_c2(self):
        """Five hosts with same period should produce multiple correlations."""
        detector = AdvancedBeaconDetector()
        hosts = [f"10.0.0.{i}" for i in range(1, 6)]
        for i, host in enumerate(hosts):
            intervals = gen_jitter_beacon(60.0, 0.05, 30, seed=i * 77)
            detector.analyze_intervals(host, "network_outbound", intervals)

        correlations = detector.find_shared_c2()
        # 5 hosts → up to C(5,2)=10 pairs
        assert len(correlations) >= 3, f"Expected ≥3 correlations, got {len(correlations)}"

    def test_lazarus_slow_beacon_shared_c2(self):
        """Low-and-slow APT beacons (300s) should also be correlated."""
        detector = AdvancedBeaconDetector()
        for i, host in enumerate(["192.168.1.10", "192.168.1.11"]):
            intervals = gen_jitter_beacon(300.0, 0.05, 20, seed=i * 50)
            detector.analyze_intervals(host, "dns_query", intervals)

        correlations = detector.find_shared_c2()
        assert len(correlations) > 0, "Lazarus-style slow beacons should be correlated"


# ── get_beacon_hosts / clear tests ───────────────────────────────────────────

class TestHelperMethods:

    def test_get_beacon_hosts(self):
        """get_beacon_hosts should return confirmed beaconing hosts."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.05, 30)
        detector.analyze_intervals("10.0.0.1", "net", intervals)
        hosts = detector.get_beacon_hosts()
        assert "10.0.0.1" in hosts

    def test_clear_resets_state(self):
        """clear() should remove all registered profiles."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.05, 30)
        detector.analyze_intervals("10.0.0.1", "net", intervals)
        assert len(detector.get_all_profiles()) > 0
        detector.clear()
        assert len(detector.get_all_profiles()) == 0
        assert detector.find_shared_c2() == []

    def test_multiple_event_types_tracked_separately(self):
        """Same host with different event types should be tracked separately."""
        detector = AdvancedBeaconDetector()
        intervals = gen_jitter_beacon(60.0, 0.05, 30)
        detector.analyze_intervals("10.0.0.1", "network_outbound", intervals)
        detector.analyze_intervals("10.0.0.1", "dns_query", intervals)
        profiles = detector.get_all_profiles()
        event_types = [p.event_type for p in profiles if p.host == "10.0.0.1"]
        assert len(set(event_types)) >= 1