"""Unit tests — new detection modules (FileAccessMonitor, HNDLPrioritizer, QuantumThreatDNA, etc.)"""
import pytest

class TestFileAccessMonitor:
    def test_importable(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        assert FileAccessMonitor is not None

    def test_sensitive_file_detection(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        monitor = FileAccessMonitor()
        result = monitor.monitor_access("/etc/shadow", "attacker", 1234)
        assert result["event"]["sensitive"] is True
        assert result["alert"] is not None
        assert result["alert"]["severity"] == "HIGH"

    def test_path_traversal_detection(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        monitor = FileAccessMonitor()
        result = monitor.monitor_access("../../etc/passwd", "user", 5678)
        assert result["event"]["traversal"] is True
        assert result["alert"]["severity"] == "CRITICAL"

    def test_normal_access_no_alert(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        monitor = FileAccessMonitor()
        result = monitor.monitor_access("/home/user/document.txt", "user", 1111)
        assert result["event"]["sensitive"] is False
        assert result["event"]["traversal"] is False

    def test_repeated_access_alert(self):
        from shadow313.v4.detection.file_access_monitor import FileAccessMonitor
        monitor = FileAccessMonitor(alert_threshold=3)
        for _ in range(4):
            monitor.monitor_access("/var/log/auth.log", "suspicious_user", 9999)
        alerts = monitor.get_alerts()
        assert len(alerts) > 0

class TestHNDLPrioritizer:
    def test_importable(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        assert HNDLPrioritizer is not None

    def test_rsa_high_risk(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        p = HNDLPrioritizer()
        result = p.score_stream({"id": "s1", "algorithm": "RSA-2048", "sensitivity": 0.9, "retention_years": 10})
        assert result["risk_level"] in ["CRITICAL", "HIGH"]
        assert result["hndl_score"] > 0.5

    def test_pqc_low_risk(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        p = HNDLPrioritizer()
        result = p.score_stream({"id": "s2", "algorithm": "ML-KEM-768", "sensitivity": 0.5, "retention_years": 5})
        assert result["risk_level"] == "LOW"
        assert result["hndl_score"] < 0.1

    def test_prioritization_order(self):
        from shadow313.v4.detection.hndl_prioritizer import HNDLPrioritizer
        p = HNDLPrioritizer()
        p.score_stream({"id": "s1", "algorithm": "RSA-2048", "sensitivity": 0.9, "retention_years": 10})
        p.score_stream({"id": "s2", "algorithm": "AES-256-GCM", "sensitivity": 0.3, "retention_years": 2})
        prioritized = p.prioritize_streams()
        assert prioritized[0]["hndl_score"] >= prioritized[-1]["hndl_score"]

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

class TestSWIFTProcessMonitor:
    def test_importable(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        assert SWIFTProcessMonitor is not None

    def test_suspicious_process_detection(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        monitor = SWIFTProcessMonitor()
        result = monitor.monitor_process({"name": "java", "cmdline": "FASTCash inject payload", "pid": 1234})
        assert result["event"]["suspicious"] is True
        assert result["alert"] is not None

    def test_normal_process_no_alert(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        monitor = SWIFTProcessMonitor()
        result = monitor.monitor_process({"name": "nginx", "cmdline": "nginx -g daemon off", "pid": 5678})
        assert result["alert"] is None

    def test_mt103_analysis(self):
        from shadow313.v4.detection.swift_process_monitor import SWIFTProcessMonitor
        monitor = SWIFTProcessMonitor()
        msg = ":32A:260101USD5000000,00\n:57A:RCBCPHMMXXX"
        result = monitor.analyze_mt103(msg)
        assert result["suspicious"] is True

class TestTemporalCorrelation:
    def test_importable(self):
        from shadow313.v4.detection.temporal_correlation import TemporalCorrelationEngine
        assert TemporalCorrelationEngine is not None

    def test_event_ingestion(self):
        from shadow313.v4.detection.temporal_correlation import TemporalCorrelationEngine
        engine = TemporalCorrelationEngine(window_seconds=3600)
        engine.ingest_event({"entity": "user1", "technique": "T1078", "severity_score": 0.7})
        assert engine.status()["events_stored"] == 1

    def test_correlation_detection(self):
        from shadow313.v4.detection.temporal_correlation import TemporalCorrelationEngine
        engine = TemporalCorrelationEngine(window_seconds=3600)
        for i in range(5):
            engine.ingest_event({"entity": "attacker", "technique": f"T10{i:02d}", "severity_score": 0.8})
        result = engine.correlate("attacker")
        assert result["correlated"] is True
        assert result["event_count"] == 5
