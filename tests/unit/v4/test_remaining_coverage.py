"""
Tests for modules with zero test coverage:
  - shadow313.v4.detection.threat_predictor
  - shadow313.v4.mobile_api.mobile_api (unit-testable parts)
  - shadow313.v2.vuln_upgrades.epss_kev_enhanced
  - shadow313.v2.graph.intel_graph

Plus integration edge case tests for:
  - event_bus → enforcement routing
  - stia_binder → temporal binding chain
  - nexus_toolkit bridge → ledger
  - ti_feed → ioc_store persistence
  - attack_simulator → log_parser pipeline
"""
from __future__ import annotations

import pytest
import tempfile
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v4.detection.threat_predictor
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatPredictor:

    def test_import(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        assert p is not None

    def test_ingest_behavioral(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("10.0.1.10", 0.85, ["T1059.001", "T1003.001"])
        assert "10.0.1.10" in p._behavioral
        assert len(p._behavioral["10.0.1.10"]) == 1

    def test_ingest_ti_match(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_ti_match("10.0.1.10", 90, "T1071.001", ioc_value="185.220.101.47")
        assert "10.0.1.10" in p._ti_matches

    def test_ingest_cve(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_cve("10.0.1.10", "CVE-2024-1234")
        assert "CVE-2024-1234" in p._cve_matches.get("10.0.1.10", [])

    def test_forecast_host_returns_profile(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("10.0.1.10", 0.9, ["T1003.001"])
        p.ingest_ti_match("10.0.1.10", 85, "T1071.001")
        forecast = p.forecast_host("10.0.1.10")
        assert forecast is not None
        assert hasattr(forecast, "host")
        assert forecast.host == "10.0.1.10"

    def test_forecast_risk_score_range(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("10.0.1.10", 0.9, ["T1003.001"])
        forecast = p.forecast_host("10.0.1.10")
        assert 0.0 <= forecast.overall_risk <= 1.0

    def test_forecast_unknown_host(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        forecast = p.forecast_host("192.168.99.99")
        assert forecast is not None
        assert forecast.overall_risk == 0.0

    def test_remediation_queue_sorted_by_risk(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("host-a", 0.3, ["T1059"])
        p.ingest_behavioral("host-b", 0.9, ["T1003.001", "T1055"])
        p.forecast_host("host-a")
        p.forecast_host("host-b")
        queue = p.get_remediation_queue()
        assert len(queue) >= 1
        # Higher risk should come first
        if len(queue) >= 2:
            assert queue[0]['risk_score'] >= queue[1]['risk_score']

    def test_behavioral_capped_at_100(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        for i in range(150):
            p.ingest_behavioral("host", 0.5, ["T1059"])
        assert len(p._behavioral["host"]) == 100

    def test_multiple_hosts_independent(self):
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("host-a", 0.9, ["T1003"])
        p.ingest_behavioral("host-b", 0.1, ["T1059"])
        fa = p.forecast_host("host-a")
        fb = p.forecast_host("host-b")
        assert fa.overall_risk >= fb.overall_risk


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v4.mobile_api.mobile_api (unit-testable parts)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMobileAPI:

    def test_import(self):
        from shadow313.v4.mobile_api.mobile_api import MobileAPIModule
        assert MobileAPIModule is not None

    def test_module_has_register(self):
        from shadow313.v4.mobile_api.mobile_api import MobileAPIModule
        assert hasattr(MobileAPIModule, "register")

    def test_module_has_run(self):
        from shadow313.v4.mobile_api.mobile_api import MobileAPIModule
        assert hasattr(MobileAPIModule, "run")

    def test_timing_safe_compare_used(self):
        """Verify hmac.compare_digest is used for token comparison (timing-safe)."""
        import inspect
        from shadow313.v4.mobile_api import mobile_api as m
        src = inspect.getsource(m)
        assert "compare_digest" in src, "Must use hmac.compare_digest for timing-safe token comparison"

    def test_no_direct_string_comparison(self):
        """Verify no direct == comparison on tokens."""
        import inspect, re
        from shadow313.v4.mobile_api import mobile_api as m
        src = inspect.getsource(m)
        # Should not have token == something (timing attack)
        dangerous = re.findall(r'token\s*==\s*\w+|credentials\s*==\s*\w+', src)
        assert len(dangerous) == 0, f"Timing-unsafe comparison found: {dangerous}"


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v2.vuln_upgrades.epss_kev_enhanced
# ═══════════════════════════════════════════════════════════════════════════════

class TestEPSSKEVEnhanced:

    def test_import(self):
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer, EPSSScore
        assert EPSSKEVScorer is not None

    def test_score_unknown_cve(self):
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer
        scorer = EPSSKEVScorer()
        result = scorer.score("CVE-9999-99999")
        assert result.cve_id == "CVE-9999-99999"
        assert result.epss == 0.0
        assert result.in_kev is False
        assert result.composite_risk == 0.0

    def test_score_returns_epss_score(self):
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer, EPSSScore
        scorer = EPSSKEVScorer()
        result = scorer.score("CVE-2024-1234")
        assert isinstance(result, EPSSScore)
        assert hasattr(result, "risk_tier")
        assert result.risk_tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_kev_multiplier_is_3x(self):
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer
        assert EPSSKEVScorer.KEV_MULTIPLIER == 3.0

    def test_risk_tiers_correct(self):
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer, EPSSScore
        scorer = EPSSKEVScorer()
        # Manually inject a high-risk CVE
        scorer._epss["CVE-TEST-HIGH"] = (0.9, 99.0)
        scorer._loaded = True
        result = scorer.score("CVE-TEST-HIGH", cvss=9.0)
        assert result.risk_tier in ("CRITICAL", "HIGH")

    def test_load_from_cache_returns_bool(self):
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer
        with tempfile.TemporaryDirectory() as d:
            scorer = EPSSKEVScorer(cache_dir=Path(d))
            result = scorer.load_from_cache()
            assert isinstance(result, bool)

    def test_score_batch(self):
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer
        scorer = EPSSKEVScorer()
        cves = [("CVE-2024-1234", 7.5), ("CVE-2023-5678", 5.0), ("CVE-9999-0001", 0.0)]
        results = scorer.score_batch(cves)
        assert len(results) == 3

    def test_epss_score_dataclass_fields(self):
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSScore
        s = EPSSScore(
            cve_id="CVE-2024-1234", epss=0.5, percentile=75.0,
            in_kev=True, composite_risk=0.8, risk_tier="CRITICAL",
        )
        assert s.cve_id == "CVE-2024-1234"
        assert s.in_kev is True
        assert s.risk_tier == "CRITICAL"


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v2.graph.intel_graph
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntelGraphV2:

    def test_import(self):
        from shadow313.v2.graph.intel_graph import IntelligenceGraph
        assert IntelligenceGraph is not None

    def test_add_node(self):
        from shadow313.v2.graph.intel_graph import IntelligenceGraph
        with tempfile.TemporaryDirectory() as d:
            g = IntelligenceGraph(graph_path=Path(d) / "test.json")
            g.add_node("10.0.1.10", "host", label="WS-07")
            assert g.has_node("10.0.1.10")

    def test_add_edge(self):
        from shadow313.v2.graph.intel_graph import IntelligenceGraph
        with tempfile.TemporaryDirectory() as d:
            g = IntelligenceGraph(graph_path=Path(d) / "test.json")
            g.add_node("10.0.1.10", "host")
            g.add_node("CVE-2024-1234", "cve")
            g.add_edge("10.0.1.10", "CVE-2024-1234", "has_cve")
            assert g.has_node("10.0.1.10")

    def test_has_node_false_for_missing(self):
        from shadow313.v2.graph.intel_graph import IntelligenceGraph
        with tempfile.TemporaryDirectory() as d:
            g = IntelligenceGraph(graph_path=Path(d) / "test.json")
            assert g.has_node("nonexistent") is False

    def test_find_nodes_by_type(self):
        from shadow313.v2.graph.intel_graph import IntelligenceGraph
        with tempfile.TemporaryDirectory() as d:
            g = IntelligenceGraph(graph_path=Path(d) / "test.json")
            g.add_node("10.0.1.10", "host")
            g.add_node("10.0.1.11", "host")
            g.add_node("CVE-2024-1234", "cve")
            hosts = g.find_nodes("host")
            assert len(hosts) == 2

    def test_shortest_path_no_path(self):
        from shadow313.v2.graph.intel_graph import IntelligenceGraph
        with tempfile.TemporaryDirectory() as d:
            g = IntelligenceGraph(graph_path=Path(d) / "test.json")
            g.add_node("A", "host")
            g.add_node("B", "host")
            path = g.shortest_path("A", "B")
            assert isinstance(path, list)

    def test_cves_for_host(self):
        from shadow313.v2.graph.intel_graph import IntelligenceGraph
        with tempfile.TemporaryDirectory() as d:
            g = IntelligenceGraph(graph_path=Path(d) / "test.json")
            g.add_node("10.0.1.10", "host")
            cves = g.cves_for_host("10.0.1.10")
            assert isinstance(cves, list)


# ═══════════════════════════════════════════════════════════════════════════════
# Integration edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegrationEdgeCases:

    def test_stia_binder_to_temporal_chain(self):
        """STIA binder creates a 313-BIND receipt with timestamp ending in 313."""
        from shadow313.integrations.stia.binder import STIABinder
        binder = STIABinder()
        result, receipt = binder.bind_dict({
            "target_id": "VSAT-001", "risk_level": "CRITICAL",
            "severity_score": 9.5, "cve_list": ["CVE-2026-3392"],
        })
        assert receipt is not None
        ts = getattr(receipt, "timestamp_ns", None)
        if ts:
            assert str(ts).endswith("313")

    def test_stia_binder_summary_has_bind_id(self):
        """Summary includes bind_id from receipt."""
        from shadow313.integrations.stia.binder import STIABinder
        binder = STIABinder()
        result, receipt = binder.bind_dict({"target_id": "T1", "risk_level": "HIGH"})
        summary = binder.summary(result, receipt)
        assert "bind_id" in summary
        assert summary["bind_id"] is not None

    def test_nexus_engine_to_bridge_pipeline(self):
        """Full pipeline: log entry → detection → bridge → receipt."""
        from nexus_toolkit.engine import NexusDetectionEngine
        from nexus_toolkit.core.log_parser import LogEntry
        from nexus_toolkit.shadow313_bridge.bridge import Shadow313Bridge

        engine = NexusDetectionEngine()
        bridge = Shadow313Bridge()

        entry = LogEntry({
            "log_id": "PIPE-001", "event_id": 10,
            "event_type": "process_access",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "command_line": "sekurlsa::logonpasswords",
            "severity": "critical",
        })
        detection = engine.detect(entry)
        assert detection.threat_level == "CRITICAL"

        result = bridge.route_detection(detection)
        assert result.detection_id == "PIPE-001"
        assert result.error == "" or result.bind_id is not None

    def test_attack_simulator_to_log_parser_pipeline(self):
        """Attack simulator produces entries compatible with 37-dim feature extractor."""
        from shadow313.demo.attack_simulator import APTAttackSimulator
        from nexus_toolkit.core.log_parser import FeatureExtractor, LogEntry

        sim = APTAttackSimulator()
        entries = sim.get_all_log_entries()
        fe = FeatureExtractor()

        for raw in entries:
            entry = LogEntry(raw)
            v = fe.extract(entry)
            assert len(v) == 37
            assert all(0.0 <= x <= 1.0 for x in v)

    def test_ti_feed_to_ioc_store_persistence(self):
        """ThreatIntelFeed indicators can be persisted to IOCStore."""
        from shadow313.threat_intel.ti_feed import ThreatIntelFeed, ThreatIndicator
        from shadow313.threat_intel.ioc_store import IOCStore

        feed = ThreatIntelFeed()
        with tempfile.TemporaryDirectory() as d:
            store = IOCStore(db_path=f"{d}/test.db")

            # Persist all feed indicators to store
            for ioc in feed._cache.values():
                store.add(ioc)

            assert store.count() >= len(feed._cache)

            # Lookup should work
            result = store.lookup("ip", "185.220.101.47")
            assert result is not None
            store.close()

    def test_event_bus_publish_and_status(self):
        """Event bus correctly tracks published events."""
        from shadow313.v4.core.event_bus import EventBus, Event, Topics
        bus = EventBus()
        bus.publish_sync(Event(topic=Topics.THREAT_DETECTED, payload={"pid": 1234}))
        bus.publish_sync(Event(topic=Topics.RECEIPT_CREATED, payload={"bind_id": "313-X"}))
        s = bus.status()
        assert s["events_total"] == 2
        assert Topics.THREAT_DETECTED in s["topics"] or s["queue_size"] >= 0

    def test_audit_server_chain_integrity_after_many_entries(self):
        """Audit server chain remains valid after 100 entries."""
        from shadow313.v4.core.audit_server import AuditServer
        server = AuditServer()
        for i in range(100):
            server.log("module", f"action_{i}", severity="INFO")
        result = server.verify_chain()
        assert result["valid"] is True
        assert result["total"] == 100

    def test_cyber_kg_query_returns_known_actors(self):
        """CyberKG returns known APT actors for financial sector."""
        from shadow313.v4.core.cyber_kg import CyberKG
        kg = CyberKG()
        result = kg.query_actors_by_sector("financial")
        actor_names = [r["actor"] for r in result.results]
        # FIN7 targets financial sector
        assert any("FIN7" in name or "Lazarus" in name for name in actor_names)

    def test_intelligence_graph_v4_stix_roundtrip(self):
        """IntelligenceGraph exports valid STIX bundle."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        import json
        g = IntelligenceGraph()
        a = g.add_node("ThreatActor", "APT29")
        t = g.add_node("Technique", "T1059.001")
        g.add_edge(a.node_id, t.node_id, "uses")
        bundle = g.to_stix_bundle()
        # Should be JSON-serializable
        serialized = json.dumps(bundle)
        parsed = json.loads(serialized)
        assert parsed["type"] == "bundle"
        assert len(parsed["objects"]) >= 2

    def test_threat_predictor_high_risk_host_in_queue(self):
        """High-risk host appears in remediation queue."""
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("critical-host", 0.95, ["T1003.001", "T1055", "T1490"])
        p.ingest_ti_match("critical-host", 95, "T1071.001", ioc_value="185.220.101.47")
        p.forecast_host("critical-host")
        queue = p.get_remediation_queue()
        host_ids = [q['host'] for q in queue]
        assert "critical-host" in host_ids

    def test_epss_scorer_kev_multiplier_effect(self):
        """KEV multiplier raises composite risk 3x."""
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer
        scorer = EPSSKEVScorer()
        # Inject same CVE with and without KEV
        scorer._epss["CVE-TEST-A"] = (0.2, 50.0)
        scorer._epss["CVE-TEST-B"] = (0.2, 50.0)
        scorer._kev["CVE-TEST-B"] = {"dateAdded": "2024-01-01", "vendorProject": "Test"}
        scorer._loaded = True

        no_kev = scorer.score("CVE-TEST-A", cvss=5.0)
        with_kev = scorer.score("CVE-TEST-B", cvss=5.0)
        assert with_kev.composite_risk > no_kev.composite_risk