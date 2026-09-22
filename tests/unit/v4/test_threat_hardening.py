"""
Tests for shadow313.v4.detection.threat_hardening

Verifies all 11 fixes for evaded attack vectors from nextgen_threat_analysis.py
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import random
import pytest

from shadow313.v4.detection.threat_hardening import (
    AggregateBeaconTracker, AtomicRegistryWriter, IOCResult,
    CrossHostBeaconDetector, IntegrityProtectedJSON, CircuitBreakerLock,
    RandomizedThresholdDetector, HardenedEnsembleDetector,
    CredibilityWeightedIOCStore, MultiSignalAPTDetector, HARDENING_FIXES,
)


class TestFix1AggregateBeaconTracker:
    """FIX-1: C5 rate-limit bypass via host rotation."""

    def test_detects_rotation_many_sources(self):
        tracker = AggregateBeaconTracker(aggregate_threshold=50)
        for i in range(100):
            for j in range(2):
                tracker.record_event(f"10.0.0.{i}", "185.220.101.47", 4444, time.time())
        result = tracker.detect_rotation("185.220.101.47", 4444)
        assert result["rotation_detected"] is True
        assert result["unique_sources"] >= 5

    def test_no_rotation_single_source(self):
        tracker = AggregateBeaconTracker(aggregate_threshold=50)
        for j in range(10):
            tracker.record_event("10.0.0.1", "185.220.101.47", 4444, time.time())
        result = tracker.detect_rotation("185.220.101.47", 4444)
        assert result["rotation_detected"] is False

    def test_prunes_old_events(self):
        tracker = AggregateBeaconTracker(window_s=1.0, aggregate_threshold=5)
        for i in range(10):
            tracker.record_event(f"10.0.0.{i}", "1.1.1.1", 443, time.time() - 2.0)
        result = tracker.detect_rotation("1.1.1.1", 443)
        assert result["aggregate_events"] == 0


class TestFix2AtomicRegistryWriter:
    """FIX-2: C1 TOCTOU race condition."""

    def test_atomic_write_and_read(self, tmp_path):
        writer = AtomicRegistryWriter(str(tmp_path / "registry.json"))
        data = {"alerts": {"ALERT-001": {"score": 0.9}}}
        assert writer.atomic_write(data) is True
        read_back = writer.safe_read()
        assert read_back == data

    def test_concurrent_writes_no_corruption(self, tmp_path):
        writer = AtomicRegistryWriter(str(tmp_path / "registry.json"))
        writer.atomic_write({"alerts": {}})
        errors = []

        def write_entry(i):
            try:
                data = writer.safe_read()
                data["alerts"][f"ALERT-{i}"] = {"score": 0.5}
                writer.atomic_write(data)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=write_entry, args=(i,)) for i in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert len(errors) == 0

    def test_safe_read_missing_file(self, tmp_path):
        writer = AtomicRegistryWriter(str(tmp_path / "nonexistent.json"))
        result = writer.safe_read()
        assert result == {"alerts": {}}


class TestFix3SchemaValidation:
    """FIX-3: C4 schema confusion."""

    def test_string_alerts_replaced_with_dict(self, tmp_path):
        path = str(tmp_path / "reg.json")
        with open(path, "w") as f:
            f.write('{"alerts": "not_a_dict"}')
        writer = AtomicRegistryWriter(path)
        result = writer.safe_read()
        assert isinstance(result["alerts"], dict)

    def test_list_alerts_replaced_with_dict(self, tmp_path):
        path = str(tmp_path / "reg.json")
        with open(path, "w") as f:
            f.write('{"alerts": [1, 2, 3]}')
        writer = AtomicRegistryWriter(path)
        result = writer.safe_read()
        assert isinstance(result["alerts"], dict)

    def test_null_alerts_replaced_with_dict(self, tmp_path):
        path = str(tmp_path / "reg.json")
        with open(path, "w") as f:
            f.write('{"alerts": null}')
        writer = AtomicRegistryWriter(path)
        result = writer.safe_read()
        assert isinstance(result["alerts"], dict)

    def test_valid_schema_preserved(self, tmp_path):
        path = str(tmp_path / "reg.json")
        data = {"alerts": {"A": {"score": 0.9}}}
        with open(path, "w") as f:
            json.dump(data, f)
        writer = AtomicRegistryWriter(path)
        result = writer.safe_read()
        assert result["alerts"]["A"]["score"] == 0.9


class TestFix4IOCResult:
    """FIX-4: C1/C6 empty-list ambiguity."""

    def test_failure_is_failure_empty(self):
        r = IOCResult.failure("feed", "timeout")
        assert r.is_failure_empty is True
        assert r.is_legit_empty is False
        assert bool(r) is False

    def test_legit_empty_is_legit_empty(self):
        r = IOCResult.success_empty("feed")
        assert r.is_legit_empty is True
        assert r.is_failure_empty is False
        assert bool(r) is False

    def test_success_with_iocs_is_truthy(self):
        r = IOCResult.success_with_iocs(["1.1.1.1"], "feed")
        assert bool(r) is True
        assert r.is_empty is False

    def test_failure_and_legit_empty_distinguishable(self):
        failure = IOCResult.failure("feed", "error")
        legit   = IOCResult.success_empty("feed")
        assert failure.is_failure_empty != legit.is_failure_empty
        assert failure.is_legit_empty != legit.is_legit_empty


class TestFix5CrossHostBeaconDetector:
    """FIX-5: Sub-threshold beacon rotation."""

    def test_detects_rotation(self):
        detector = CrossHostBeaconDetector()
        events = []
        for i in range(10):
            for j in range(12):
                events.append({"src_ip": f"10.0.0.{i}", "dst_ip": "185.220.101.47",
                                "dst_port": 4444, "timestamp": time.time() + j * 300})
        result = detector.analyze(events)
        assert result["rotation_detected"] is True

    def test_no_rotation_single_source(self):
        detector = CrossHostBeaconDetector()
        events = [{"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1",
                   "dst_port": 443, "timestamp": time.time() + i * 60}
                  for i in range(10)]
        result = detector.analyze(events)
        assert result["rotation_detected"] is False


class TestFix6IntegrityProtectedJSON:
    """FIX-6: json.loads monkey-patch."""

    def test_safe_loads_bypasses_monkeypatch(self):
        ipj = IntegrityProtectedJSON()
        original_loads = json.loads

        def malicious_loads(s, **kwargs):
            result = original_loads(s, **kwargs)
            if isinstance(result, dict):
                result["INJECTED"] = True
            return result

        json.loads = malicious_loads
        try:
            result = ipj.safe_loads('{"alerts": {"A": 1}}')
            assert "INJECTED" not in result
        finally:
            json.loads = original_loads

    def test_signed_loads_verifies_integrity(self):
        ipj = IntegrityProtectedJSON()
        data = {"alerts": {"A": 1}}
        s, sig = ipj.signed_dumps(data)
        result = ipj.signed_loads(s, sig)
        assert result == data

    def test_signed_loads_rejects_tampered(self):
        ipj = IntegrityProtectedJSON()
        data = {"alerts": {"A": 1}}
        s, sig = ipj.signed_dumps(data)
        result = ipj.signed_loads(s + " ", sig)  # tampered
        assert result is None


class TestFix7CircuitBreakerLock:
    """FIX-7: RLock starvation."""

    def test_circuit_breaker_opens_after_failures(self):
        cb = CircuitBreakerLock(timeout_ms=50, failure_threshold=3)

        def hold_lock():
            with cb._lock:
                time.sleep(0.5)

        holder = threading.Thread(target=hold_lock)
        holder.start()
        time.sleep(0.01)

        fails = sum(1 for _ in range(5) if not cb.acquire())
        holder.join()

        assert fails >= 3
        assert cb._circuit_open is True

    def test_circuit_breaker_resets(self):
        cb = CircuitBreakerLock(timeout_ms=50, failure_threshold=3)
        cb._circuit_open = True
        cb._circuit_open_at = time.time() - 10.0  # expired
        result = cb.acquire()
        if result:
            cb.release()
        assert cb._circuit_open is False

    def test_normal_acquisition_works(self):
        cb = CircuitBreakerLock(timeout_ms=100)
        assert cb.acquire() is True
        cb.release()


class TestFix8RandomizedThreshold:
    """FIX-8: Feature boundary probing."""

    def test_threshold_varies(self):
        import statistics
        rtd = RandomizedThresholdDetector(0.45, 0.05)
        thresholds = [rtd.get_threshold() for _ in range(100)]
        std = statistics.stdev(thresholds)
        assert std > 0.01

    def test_threshold_within_bounds(self):
        rtd = RandomizedThresholdDetector(0.45, 0.05)
        for _ in range(100):
            t = rtd.get_threshold()
            assert 0.1 <= t <= 0.9

    def test_high_score_detected(self):
        rtd = RandomizedThresholdDetector(0.45, 0.01)
        assert rtd.is_anomalous(0.99) is True

    def test_low_score_not_detected(self):
        rtd = RandomizedThresholdDetector(0.45, 0.01)
        assert rtd.is_anomalous(0.01) is False


class TestFix9HardenedEnsemble:
    """FIX-9: Adversarial perturbation."""

    def test_clearly_malicious_detected(self):
        hed = HardenedEnsembleDetector()
        features = [0.9] * 32
        result = hed.score(features)
        assert result["anomalous"] is True

    def test_clearly_benign_not_detected(self):
        hed = HardenedEnsembleDetector()
        features = [0.05] * 32
        result = hed.score(features)
        assert result["anomalous"] is False

    def test_invalid_features_replaced(self):
        hed = HardenedEnsembleDetector()
        features = [1.5, -0.1, "bad", None] + [0.5] * 28
        result = hed.score(features)
        assert "score" in result

    def test_adversarial_perturbation_resisted(self):
        hed = HardenedEnsembleDetector()
        malicious = [0.8] * 32
        for _ in range(200):
            candidate = [f + random.gauss(0, 0.05) for f in malicious]
            candidate = [max(0, min(1, f)) for f in candidate]
            result = hed.score(candidate)
            if not result["anomalous"]:
                malicious = candidate
        final = hed.score(malicious)
        assert final["anomalous"] is True


class TestFix10CredibilityWeightedIOC:
    """FIX-10: IOC data poisoning."""

    def test_high_credibility_sources_dominate(self):
        store = CredibilityWeightedIOCStore()
        store.ingest("185.220.101.42", 0.95, "MISP")
        store.ingest("185.220.101.42", 0.92, "AlienVault")
        for _ in range(10):
            store.ingest("185.220.101.42", 0.05, "VirusTotal_COMPROMISED")
        score = store.get_score("185.220.101.42")
        assert score >= 0.5

    def test_zero_credibility_source_rejected(self):
        store = CredibilityWeightedIOCStore()
        store.ingest("1.1.1.1", 0.05, "VirusTotal_COMPROMISED")
        score = store.get_score("1.1.1.1")
        assert score == 0.5  # unknown (rejected)

    def test_unknown_ioc_returns_neutral(self):
        store = CredibilityWeightedIOCStore()
        assert store.get_score("9.9.9.9") == 0.5

    def test_outlier_rejection(self):
        store = CredibilityWeightedIOCStore()
        store.ingest("2.2.2.2", 0.95, "MISP")
        store.ingest("2.2.2.2", 0.90, "AlienVault")
        for _ in range(20):
            store.ingest("2.2.2.2", 0.01, "VirusTotal")
        score = store.get_score("2.2.2.2")
        assert score >= 0.5


class TestFix11MultiSignalAPT:
    """FIX-11: APT kill chain evasion."""

    def test_any_signal_triggers_detection(self):
        apt = MultiSignalAPTDetector()
        apt.record_signal("Recon", "probe", 0.43, 0.45, False)
        apt.record_signal("Recon", "scan_rate", 0.8, 0.5, True)
        result = apt.evaluate_stage("Recon")
        assert result["detected"] is True

    def test_all_signals_below_threshold_not_detected(self):
        apt = MultiSignalAPTDetector()
        apt.record_signal("Recon", "probe", 0.3, 0.45, False)
        apt.record_signal("Recon", "scan_rate", 0.2, 0.5, False)
        result = apt.evaluate_stage("Recon")
        assert result["detected"] is False

    def test_kill_chain_active_if_any_stage_detected(self):
        apt = MultiSignalAPTDetector()
        apt.record_signal("Recon", "probe", 0.3, 0.45, False)
        apt.record_signal("Exfil", "volume", 0.9, 0.5, True)
        result = apt.is_kill_chain_active()
        assert result["kill_chain_active"] is True
        assert "Exfil" in result["detected_stages"]

    def test_no_signals_not_detected(self):
        apt = MultiSignalAPTDetector()
        result = apt.evaluate_stage("Recon")
        assert result["detected"] is False


class TestHardeningFixRegistry:
    def test_all_11_fixes_registered(self):
        assert len(HARDENING_FIXES) >= 11

    def test_fix_ids_sequential(self):
        ids = list(HARDENING_FIXES.keys())
        assert "FIX-1" in ids and "FIX-11" in ids