"""
Unit tests — shadow313.v4.detection (full suite for new modules)
Covers: file_access_monitor, hndl_prioritizer, quantum_threat_dna,
        swift_process_monitor, temporal_correlation, identity_controls
"""
from __future__ import annotations
import pytest
import time


# ── FILE ACCESS MONITOR ───────────────────────────────────────────────────────

class TestFileAccessMonitor:
    def test_importable(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        assert FileAccessMonitor is not None

    def test_sensitive_file_alert(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        m = FileAccessMonitor()
        result = m.monitor_access("/etc/shadow", "attacker", 1234)
        assert result["event"]["sensitive"] is True
        assert result["alert"]["severity"] == "HIGH"

    def test_traversal_critical_alert(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        m = FileAccessMonitor()
        result = m.monitor_access("../../etc/passwd", "user", 5678)
        assert result["event"]["traversal"] is True
        assert result["alert"]["severity"] == "CRITICAL"

    def test_normal_access_no_alert(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        m = FileAccessMonitor()
        result = m.monitor_access("/home/user/document.txt", "user", 1111)
        assert result["alert"] is None

    def test_repeated_access_alert(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        m = FileAccessMonitor(alert_threshold=3)
        for _ in range(4):
            m.monitor_access("/var/log/auth.log", "suspicious", 9999)
        alerts = m.get_alerts()
        assert len(alerts) > 0

    def test_get_alerts_by_severity(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        m = FileAccessMonitor()
        m.monitor_access("/etc/shadow", "u1", 1)
        m.monitor_access("../../etc/passwd", "u2", 2)
        critical = m.get_alerts("CRITICAL")
        high = m.get_alerts("HIGH")
        assert len(critical) >= 1
        assert len(high) >= 1

    def test_status(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        m = FileAccessMonitor()
        m.monitor_access("/tmp/test.txt", "user", 1)
        status = m.status()
        assert status["events_monitored"] == 1


# ── HNDL PRIORITIZER ─────────────────────────────────────────────────────────

class TestHNDLPrioritizer:
    def test_importable(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        assert HNDLPrioritizer is not None

    def test_rsa_scores_critical(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        p = HNDLPrioritizer()
        result = p.score_stream({"id": "s1", "algorithm": "RSA-2048", "sensitivity": 0.9, "retention_years": 10})
        assert result["risk_level"] in ["CRITICAL", "HIGH"]
        assert result["hndl_score"] > 0.5

    def test_pqc_scores_low(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        p = HNDLPrioritizer()
        result = p.score_stream({"id": "s2", "algorithm": "ML-KEM-768", "sensitivity": 0.5, "retention_years": 5})
        assert result["risk_level"] == "LOW"
        assert result["hndl_score"] < 0.1

    def test_prioritize_streams_sorted(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        p = HNDLPrioritizer()
        p.score_stream({"id": "s1", "algorithm": "RSA-2048", "sensitivity": 0.9, "retention_years": 10})
        p.score_stream({"id": "s2", "algorithm": "AES-256-GCM", "sensitivity": 0.3, "retention_years": 2})
        prioritized = p.prioritize_streams()
        assert prioritized[0]["hndl_score"] >= prioritized[-1]["hndl_score"]

    def test_recommendation_present(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        p = HNDLPrioritizer()
        result = p.score_stream({"id": "s3", "algorithm": "RSA-2048", "sensitivity": 0.9, "retention_years": 10})
        assert "recommendation" in result
        assert len(result["recommendation"]) > 0

    def test_status(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        p = HNDLPrioritizer()
        p.score_stream({"id": "s4", "algorithm": "TLS-1.2", "sensitivity": 0.5, "retention_years": 5})
        status = p.status()
        assert status["streams_analyzed"] == 1


# ── QUANTUM THREAT DNA ────────────────────────────────────────────────────────

class TestQuantumThreatDNA:
    def test_importable(self):
        from shadow313.v4.detection.quantum_threat_dna import QuantumThreatDNA
        assert QuantumThreatDNA is not None

    def test_known_pattern_match(self):
        from shadow313.v4.detection.quantum_threat_dna import QuantumThreatDNA
        dna = QuantumThreatDNA()
        result = dna.observe_pattern("bulk_tls_capture", {"source": "network_tap"})
        assert result["match"] is not None
        assert result["match"]["actor"] == "APT_CRQC_HARVESTER"
        assert result["match"]["risk"] == "CRITICAL"

    def test_unknown_pattern_no_match(self):
        from shadow313.v4.detection.quantum_threat_dna import QuantumThreatDNA
        dna = QuantumThreatDNA()
        result = dna.observe_pattern("normal_traffic_pattern", {})
        assert result["match"] is None

    def test_fingerprint_generation(self):
        from shadow313.v4.detection.quantum_threat_dna import QuantumThreatDNA
        dna = QuantumThreatDNA()
        fp = dna.generate_dna_fingerprint(["bulk_tls_capture", "rsa_key_extraction"])
        assert len(fp) == 16

    def test_fingerprint_deterministic(self):
        from shadow313.v4.detection.quantum_threat_dna import QuantumThreatDNA
        dna = QuantumThreatDNA()
        fp1 = dna.generate_dna_fingerprint(["a", "b"])
        fp2 = dna.generate_dna_fingerprint(["b", "a"])
        assert fp1 == fp2  # sorted, so order-independent

    def test_threat_summary(self):
        from shadow313.v4.detection.quantum_threat_dna import QuantumThreatDNA
        dna = QuantumThreatDNA()
        dna.observe_pattern("bulk_tls_capture", {})
        dna.observe_pattern("code_signing_abuse", {})
        summary = dna.get_threat_summary()
        assert summary["patterns_observed"] == 2
        assert summary["actor_matches"] == 2


# ── SWIFT PROCESS MONITOR ─────────────────────────────────────────────────────

class TestSWIFTProcessMonitor:
    def test_importable(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        assert SWIFTProcessMonitor is not None

    def test_fastcash_detected(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        m = SWIFTProcessMonitor()
        result = m.monitor_process({"name": "java", "cmdline": "FASTCash inject payload", "pid": 1234})
        assert result["event"]["suspicious"] is True
        assert result["alert"]["severity"] == "CRITICAL"
        assert result["alert"]["mitre_technique"] == "T1565.001"

    def test_normal_process_no_alert(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        m = SWIFTProcessMonitor()
        result = m.monitor_process({"name": "nginx", "cmdline": "nginx -g daemon off", "pid": 5678})
        assert result["alert"] is None

    def test_mt103_large_amount_suspicious(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        m = SWIFTProcessMonitor()
        msg = ":32A:260101USD5000000,00\n:57A:RCBCPHMMXXX"
        result = m.analyze_mt103(msg)
        assert result["suspicious"] is True

    def test_mt103_normal_not_suspicious(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        m = SWIFTProcessMonitor()
        msg = ":32A:260101USD1000,00\n:57A:DEUTDEDBXXX"
        result = m.analyze_mt103(msg)
        assert result["suspicious"] is False

    def test_status(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        m = SWIFTProcessMonitor()
        m.monitor_process({"name": "java", "cmdline": "normal", "pid": 1})
        status = m.status()
        assert status["processes_monitored"] == 1


# ── TEMPORAL CORRELATION ──────────────────────────────────────────────────────

class TestTemporalCorrelation:
    def test_importable(self):
        from shadow313.v4.detection.temporal_correlation import TemporalCorrelationEngine
        assert TemporalCorrelationEngine is not None

    def test_event_ingestion(self):
        from shadow313.v4.detection.temporal_correlation import TemporalCorrelationEngine
        engine = TemporalCorrelationEngine(window_seconds=3600)
        engine.ingest_event({"entity": "user1", "technique": "T1078", "severity_score": 0.7})
        assert engine.status()["events_stored"] == 1

    def test_correlation_with_multiple_events(self):
        from shadow313.v4.detection.temporal_correlation import TemporalCorrelationEngine
        engine = TemporalCorrelationEngine(window_seconds=3600)
        for i in range(5):
            engine.ingest_event({"entity": "attacker", "technique": f"T10{i:02d}", "severity_score": 0.8})
        result = engine.correlate("attacker")
        assert result["correlated"] is True
        assert result["event_count"] == 5

    def test_single_event_not_correlated(self):
        from shadow313.v4.detection.temporal_correlation import TemporalCorrelationEngine
        engine = TemporalCorrelationEngine()
        engine.ingest_event({"entity": "user2", "technique": "T1078", "severity_score": 0.5})
        result = engine.correlate("user2")
        assert result["correlated"] is False

    def test_status(self):
        from shadow313.v4.detection.temporal_correlation import TemporalCorrelationEngine
        engine = TemporalCorrelationEngine()
        engine.ingest_event({"entity": "e1", "technique": "T1", "severity_score": 0.5})
        status = engine.status()
        assert status["entities_tracked"] == 1
        assert status["events_stored"] == 1