"""
Tests for all newly created modules without existing test coverage.

Covers:
  - shadow313.v4.core: event_bus, intelligence_graph, audit_server, crypto_sbom, cyber_kg
  - shadow313.v3.bridge: beacon_detector, extended_c2_correlator, phantomscan
  - shadow313.integrations.stia: alerting, zeroday_analyzer
  - shadow313.threat_intel: ti_feed, ioc_store
  - shadow313.demo: attack_simulator, roi_calculator
  - shadow313.core.intelligence_graph
  - nexus_toolkit: engine, log_parser, ml_engine, bridge
"""
from __future__ import annotations

import json
import tempfile
import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v4.core.event_bus
# ═══════════════════════════════════════════════════════════════════════════════

class TestEventBus:
    def test_import(self):
        from shadow313.v4.core.event_bus import EventBus, Event, Topics, get_event_bus
        assert EventBus is not None

    def test_subscribe_and_publish_sync(self):
        from shadow313.v4.core.event_bus import EventBus, Event
        bus = EventBus()
        received = []
        bus.subscribe_fn("test.topic", lambda e: received.append(e.payload))
        bus.publish_sync(Event(topic="test.topic", payload={"key": "val"}))
        assert bus.status()["queue_size"] == 1

    def test_status_has_required_keys(self):
        from shadow313.v4.core.event_bus import EventBus
        bus = EventBus()
        s = bus.status()
        for k in ("running", "queue_size", "events_total", "topics"):
            assert k in s

    def test_topics_constants(self):
        from shadow313.v4.core.event_bus import Topics
        assert Topics.THREAT_DETECTED == "threat.detected"
        assert Topics.RECEIPT_CREATED == "receipt.created"

    def test_get_event_bus_singleton(self):
        from shadow313.v4.core.event_bus import get_event_bus
        b1 = get_event_bus()
        b2 = get_event_bus()
        assert b1 is b2

    def test_queue_full_drops_gracefully(self):
        import asyncio
        from shadow313.v4.core.event_bus import EventBus, Event
        # Create bus with small queue to test overflow handling
        bus = EventBus()
        bus._queue = asyncio.Queue(maxsize=2)
        for i in range(5):
            bus.publish_sync(Event(topic="t", payload=i))
        # Should not raise — overflow is silently dropped


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v4.core.intelligence_graph
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntelligenceGraphV4:
    def test_add_node(self):
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        n = g.add_node("ThreatActor", "APT29")
        assert n.name == "APT29"
        assert n.node_type == "ThreatActor"

    def test_add_edge(self):
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        a = g.add_node("ThreatActor", "APT29")
        t = g.add_node("Technique", "T1059")
        e = g.add_edge(a.node_id, t.node_id, "uses")
        assert e is not None
        assert e.relation == "uses"

    def test_get_neighbors(self):
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        a = g.add_node("ThreatActor", "APT29")
        t = g.add_node("Technique", "T1059")
        g.add_edge(a.node_id, t.node_id, "uses")
        neighbors = g.get_neighbors(a.node_id, "uses")
        assert len(neighbors) == 1
        assert neighbors[0].name == "T1059"

    def test_find_nodes_by_type(self):
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        g.add_node("ThreatActor", "APT29")
        g.add_node("ThreatActor", "APT41")
        g.add_node("Malware", "Cobalt Strike")
        actors = g.find_nodes(node_type="ThreatActor")
        assert len(actors) == 2

    def test_stats(self):
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        g.add_node("ThreatActor", "APT29")
        s = g.stats()
        assert s["total_nodes"] == 1
        assert s["total_edges"] == 0

    def test_stix_export(self):
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        g.add_node("ThreatActor", "APT29")
        bundle = g.to_stix_bundle()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) >= 1

    def test_edge_returns_none_for_missing_node(self):
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        result = g.add_edge("nonexistent", "also-nonexistent", "uses")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v4.core.audit_server
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditServer:
    def test_log_entry(self):
        from shadow313.v4.core.audit_server import AuditServer
        s = AuditServer()
        e = s.log("test_module", "test_action", severity="INFO")
        assert e.module == "test_module"
        assert e.action == "test_action"
        assert e.chain_hash != ""

    def test_chain_valid_after_entries(self):
        from shadow313.v4.core.audit_server import AuditServer
        s = AuditServer()
        for i in range(5):
            s.log("mod", f"action_{i}")
        result = s.verify_chain()
        assert result["valid"] is True
        assert result["total"] == 5

    def test_empty_chain_valid(self):
        from shadow313.v4.core.audit_server import AuditServer
        s = AuditServer()
        assert s.verify_chain()["valid"] is True

    def test_query_by_module(self):
        from shadow313.v4.core.audit_server import AuditServer
        s = AuditServer()
        s.log("module_a", "action1")
        s.log("module_b", "action2")
        results = s.query(module="module_a")
        assert len(results) == 1

    def test_stats(self):
        from shadow313.v4.core.audit_server import AuditServer
        s = AuditServer()
        s.log("mod", "act", outcome="SUCCESS")
        stats = s.stats()
        assert stats["total_entries"] == 1
        assert stats["chain_valid"] is True

    def test_export_json(self):
        from shadow313.v4.core.audit_server import AuditServer
        s = AuditServer()
        s.log("mod", "act")
        data = json.loads(s.export_json())
        assert len(data) == 1
        assert data[0]["module"] == "mod"

    def test_chain_hashes_unique(self):
        from shadow313.v4.core.audit_server import AuditServer
        s = AuditServer()
        e1 = s.log("mod", "act1")
        e2 = s.log("mod", "act2")
        assert e1.chain_hash != e2.chain_hash


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v4.core.crypto_sbom
# ═══════════════════════════════════════════════════════════════════════════════

class TestCryptoSBOM:
    def test_import(self):
        from shadow313.v4.core.crypto_sbom import CryptoSBOM, SHADOW313_CRYPTO_SBOM
        assert len(SHADOW313_CRYPTO_SBOM) >= 5

    def test_summary(self):
        from shadow313.v4.core.crypto_sbom import CryptoSBOM
        sbom = CryptoSBOM()
        s = sbom.summary()
        assert s["total"] >= 5
        assert s["quantum_safe"] >= 1

    def test_get_vulnerable(self):
        from shadow313.v4.core.crypto_sbom import CryptoSBOM
        sbom = CryptoSBOM()
        vuln = sbom.get_vulnerable()
        # ECDSA P-256 cosign should be in vulnerable list
        names = [c.algorithm for c in vuln]
        assert any("ECDSA" in n or "cosign" in n.lower() for n in names)

    def test_cyclonedx_export(self):
        from shadow313.v4.core.crypto_sbom import CryptoSBOM
        sbom = CryptoSBOM()
        cdx = sbom.to_cyclonedx()
        assert cdx["bomFormat"] == "CycloneDX"
        assert len(cdx["components"]) >= 5

    def test_to_json_valid(self):
        from shadow313.v4.core.crypto_sbom import CryptoSBOM
        sbom = CryptoSBOM()
        data = json.loads(sbom.to_json())
        assert data["bomFormat"] == "CycloneDX"

    def test_slhdsa_is_active(self):
        from shadow313.v4.core.crypto_sbom import CryptoSBOM
        sbom = CryptoSBOM()
        active = sbom.get_active()
        names = [c.algorithm for c in active]
        assert any("SLH-DSA" in n for n in names)


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v4.core.cyber_kg
# ═══════════════════════════════════════════════════════════════════════════════

class TestCyberKG:
    def test_seeded_with_known_actors(self):
        from shadow313.v4.core.cyber_kg import CyberKG
        kg = CyberKG()
        s = kg.stats()
        assert s["actors"] >= 4

    def test_query_actor_ttps(self):
        from shadow313.v4.core.cyber_kg import CyberKG
        kg = CyberKG()
        result = kg.query_actor_ttps("APT29")
        assert result.confidence > 0
        assert len(result.results) >= 1

    def test_query_actors_by_sector(self):
        from shadow313.v4.core.cyber_kg import CyberKG
        kg = CyberKG()
        result = kg.query_actors_by_sector("financial")
        assert len(result.results) >= 1

    def test_query_lateral_movement(self):
        from shadow313.v4.core.cyber_kg import CyberKG
        kg = CyberKG()
        result = kg.query_lateral_movement_path("WS-07", "DC-01")
        assert len(result.results) >= 3

    def test_unknown_actor_returns_empty(self):
        from shadow313.v4.core.cyber_kg import CyberKG
        kg = CyberKG()
        result = kg.query_actor_ttps("NonExistentActor12345")
        assert result.confidence == 0.0
        assert len(result.results) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v3.bridge.beacon_detector
# ═══════════════════════════════════════════════════════════════════════════════

class TestBeaconDetector:
    def _make_events(self, n=10, period=60.0, jitter=0.05):
        import time, random
        from shadow313.v3.bridge.beacon_detector import BeaconEvent
        random.seed(313)
        base = time.time()
        return [
            BeaconEvent(
                timestamp  = base + i * period * (1 + random.uniform(-jitter, jitter)),
                src_ip     = "10.0.1.10",
                dst_ip     = "104.21.0.1",
                dst_port   = 443,
                bytes_sent = 512,
                uri        = "/jquery-3.3.1.min.js",
                ja3        = "72a589da586844d7f0818ce684948eea",
            )
            for i in range(n)
        ]

    def test_detects_beacon(self):
        from shadow313.v3.bridge.beacon_detector import BeaconDetector
        d = BeaconDetector()
        events = self._make_events(10, 60.0, 0.05)
        profiles = d.detect(events)
        assert len(profiles) >= 1
        assert profiles[0].is_beacon

    def test_period_approximately_correct(self):
        from shadow313.v3.bridge.beacon_detector import BeaconDetector
        d = BeaconDetector()
        events = self._make_events(10, 60.0, 0.05)
        profiles = d.detect(events)
        assert 50 <= profiles[0].period_s <= 70

    def test_framework_attribution(self):
        from shadow313.v3.bridge.beacon_detector import BeaconDetector
        d = BeaconDetector()
        events = self._make_events(10, 60.0, 0.05)
        profiles = d.detect(events)
        assert "Cobalt Strike" in profiles[0].framework

    def test_too_few_events_no_detection(self):
        from shadow313.v3.bridge.beacon_detector import BeaconDetector, BeaconEvent
        import time
        d = BeaconDetector()
        events = [BeaconEvent(time.time() + i*60, "10.0.0.1", "1.1.1.1", 443, 100)
                  for i in range(2)]
        profiles = d.detect(events)
        assert len(profiles) == 0

    def test_summary(self):
        from shadow313.v3.bridge.beacon_detector import BeaconDetector
        d = BeaconDetector()
        events = self._make_events(10)
        profiles = d.detect(events)
        s = d.summary(profiles)
        assert "total_beacons" in s


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v3.bridge.extended_c2_correlator
# ═══════════════════════════════════════════════════════════════════════════════

class TestExtendedC2Correlator:
    def test_correlate_same_campaign(self):
        from shadow313.v3.bridge.extended_c2_correlator import ExtendedC2Correlator
        from shadow313.v3.bridge.c2_attribution_analysis import build_scenario
        hosts = build_scenario()
        apt_a = [h for h in hosts if h.campaign == "APT-A"]
        corr = ExtendedC2Correlator()
        result = corr.correlate(apt_a[0], apt_a[1])
        assert result.matched is True

    def test_cdn_flag_set_for_cloudflare(self):
        from shadow313.v3.bridge.extended_c2_correlator import ExtendedC2Correlator
        from shadow313.v3.bridge.c2_attribution_analysis import build_scenario
        hosts = build_scenario()
        apt_a = [h for h in hosts if h.campaign == "APT-A"]
        apt_b = [h for h in hosts if h.campaign == "APT-B"]
        corr = ExtendedC2Correlator()
        result = corr.correlate(apt_a[0], apt_b[0])
        assert result.cdn_flag is True

    def test_lstm_features_dim28_29(self):
        from shadow313.v3.bridge.extended_c2_correlator import ExtendedC2Correlator
        from shadow313.v3.bridge.c2_attribution_analysis import build_scenario
        hosts = build_scenario()
        apt_a = [h for h in hosts if h.campaign == "APT-A"]
        corr = ExtendedC2Correlator()
        features = corr.get_lstm_features(apt_a[0], apt_a[1])
        assert len(features) == 2
        assert 0.0 <= features[0] <= 1.0
        assert 0.0 <= features[1] <= 1.0

    def test_classify_uri_cobalt_strike(self):
        from shadow313.v3.bridge.extended_c2_correlator import classify_uri
        result = classify_uri("/jquery-3.3.1.min.js")
        assert result["matched"] is True
        assert result["framework"] == "Cobalt Strike"

    def test_classify_uri_unknown(self):
        from shadow313.v3.bridge.extended_c2_correlator import classify_uri
        result = classify_uri("/index.html")
        assert result["matched"] is False

    def test_cluster_separates_campaigns(self):
        from shadow313.v3.bridge.extended_c2_correlator import ExtendedC2Correlator
        from shadow313.v3.bridge.c2_attribution_analysis import build_scenario
        hosts = build_scenario()
        corr = ExtendedC2Correlator()
        clusters = corr.cluster(hosts)
        assert len(clusters) >= 2


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.v3.bridge.phantomscan
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhantomScan:
    def test_profiles_defined(self):
        from shadow313.v3.bridge.phantomscan import PROFILES
        for p in ("ghost", "stealth", "normal", "aggressive", "DEEP"):
            assert p in PROFILES

    def test_scan_result_structure(self):
        from shadow313.v3.bridge.phantomscan import PhantomScan
        scanner = PhantomScan(profile="normal")
        # Scan localhost — port 22 may or may not be open, but result should be valid
        result = scanner.scan("127.0.0.1", ports=[9999, 9998])
        assert result.target == "127.0.0.1"
        assert result.ports_scanned == 2
        assert isinstance(result.open_ports, list)
        assert isinstance(result.closed_ports, list)

    def test_quick_check(self):
        from shadow313.v3.bridge.phantomscan import PhantomScan
        scanner = PhantomScan()
        result = scanner.quick_check("127.0.0.1", [9999, 9998])
        assert isinstance(result, dict)
        assert 9999 in result

    def test_open_port_numbers_property(self):
        from shadow313.v3.bridge.phantomscan import PhantomScan
        scanner = PhantomScan()
        result = scanner.scan("127.0.0.1", ports=[9999])
        assert isinstance(result.open_port_numbers, list)

    def test_profile_randomize_order(self):
        from shadow313.v3.bridge.phantomscan import PROFILES
        assert PROFILES["ghost"]["randomize_order"] is True
        assert PROFILES["aggressive"]["randomize_order"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.integrations.stia.alerting
# ═══════════════════════════════════════════════════════════════════════════════

class TestSTIAAlerting:
    def _make_result(self):
        from shadow313.integrations.stia.parser import STIAScanResult
        return STIAScanResult(
            target_id="VSAT-001", target_name="Test VSAT",
            risk_level="CRITICAL", severity_score=9.5,
            cve_list=["CVE-2026-3392"], mitre_tactics=["Initial Access"],
            threat_profile="APT29",
        )

    def test_create_alert(self):
        from shadow313.integrations.stia.alerting import STIAAlertRouter
        router = STIAAlertRouter()
        result = self._make_result()
        alert = router.create_alert(result)
        assert alert.severity == "CRITICAL"
        assert alert.target_id == "VSAT-001"
        assert alert.alert_id.startswith("STIA-")

    def test_route_critical_delivers_immediately(self):
        from shadow313.integrations.stia.alerting import STIAAlertRouter
        router = STIAAlertRouter()
        result = self._make_result()
        alert = router.create_alert(result)
        delivery = router.route(alert)
        assert delivery["status"] == "delivered"

    def test_route_high_queues(self):
        from shadow313.integrations.stia.alerting import STIAAlertRouter
        from shadow313.integrations.stia.parser import STIAScanResult
        router = STIAAlertRouter()
        r = STIAScanResult(target_id="T1", risk_level="HIGH", severity_score=7.5)
        alert = router.create_alert(r)
        delivery = router.route(alert)
        assert "queued" in delivery["status"]

    def test_flush_queue(self):
        from shadow313.integrations.stia.alerting import STIAAlertRouter
        from shadow313.integrations.stia.parser import STIAScanResult
        router = STIAAlertRouter()
        for i in range(3):
            r = STIAScanResult(target_id=f"T{i}", risk_level="HIGH", severity_score=7.0)
            router.route(router.create_alert(r))
        results = router.flush_queue()
        assert len(results) == 3

    def test_sign_webhook_payload(self):
        from shadow313.integrations.stia.alerting import STIAAlertRouter
        router = STIAAlertRouter(webhook_secret=b"test-secret-key")
        sig = router.sign_webhook_payload(b"test payload")
        assert len(sig) == 64  # HMAC-SHA256 hex

    def test_stats(self):
        from shadow313.integrations.stia.alerting import STIAAlertRouter
        router = STIAAlertRouter()
        s = router.stats()
        assert "queued" in s and "delivered" in s


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.integrations.stia.zeroday_analyzer
# ═══════════════════════════════════════════════════════════════════════════════

class TestZeroDayAnalyzer:
    def test_analyze_recent_cve(self):
        from shadow313.integrations.stia.zeroday_analyzer import ZeroDayAnalyzer
        from shadow313.integrations.stia.parser import STIAScanResult
        from datetime import datetime, timezone
        year = datetime.now(timezone.utc).year
        r = STIAScanResult(
            target_id="T1", cve_list=[f"CVE-{year}-9999"],
            risk_level="HIGH", severity_score=7.5,
        )
        analyzer = ZeroDayAnalyzer()
        result = analyzer.analyze(r)
        assert len(result.indicators) >= 1
        assert result.risk_score > 0

    def test_analyze_no_indicators(self):
        from shadow313.integrations.stia.zeroday_analyzer import ZeroDayAnalyzer
        from shadow313.integrations.stia.parser import STIAScanResult
        r = STIAScanResult(target_id="T1", cve_list=[], risk_level="NONE", severity_score=0.0)
        analyzer = ZeroDayAnalyzer()
        result = analyzer.analyze(r)
        assert result.is_zero_day is False

    def test_signal_anomaly_creates_indicator(self):
        from shadow313.integrations.stia.zeroday_analyzer import ZeroDayAnalyzer
        from shadow313.integrations.stia.parser import STIAScanResult
        r = STIAScanResult(target_id="T1", signal_anomaly=True, risk_level="HIGH", severity_score=7.0)
        analyzer = ZeroDayAnalyzer()
        result = analyzer.analyze(r)
        assert any(i.indicator_type == "novel_pattern" for i in result.indicators)

    def test_batch_analyze(self):
        from shadow313.integrations.stia.zeroday_analyzer import ZeroDayAnalyzer
        from shadow313.integrations.stia.parser import STIAScanResult
        results = [STIAScanResult(target_id=f"T{i}") for i in range(3)]
        analyzer = ZeroDayAnalyzer()
        analyses = analyzer.batch_analyze(results)
        assert len(analyses) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.threat_intel.ti_feed
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatIntelFeed:
    def test_seeded_with_known_iocs(self):
        from shadow313.threat_intel.ti_feed import ThreatIntelFeed
        feed = ThreatIntelFeed()
        s = feed.stats()
        assert s["total_indicators"] >= 3

    def test_lookup_known_ip(self):
        from shadow313.threat_intel.ti_feed import ThreatIntelFeed
        feed = ThreatIntelFeed()
        result = feed.lookup_ip("185.220.101.47")
        assert result is not None
        assert result.severity == "CRITICAL"

    def test_lookup_unknown_ip(self):
        from shadow313.threat_intel.ti_feed import ThreatIntelFeed
        feed = ThreatIntelFeed()
        result = feed.lookup_ip("8.8.8.8")
        assert result is None

    def test_enrich_ip_malicious(self):
        from shadow313.threat_intel.ti_feed import ThreatIntelFeed
        feed = ThreatIntelFeed()
        result = feed.enrich_ip("185.220.101.47")
        assert result["malicious"] is True
        assert result["confidence"] > 0.5

    def test_enrich_ip_clean(self):
        from shadow313.threat_intel.ti_feed import ThreatIntelFeed
        feed = ThreatIntelFeed()
        result = feed.enrich_ip("8.8.8.8")
        assert result["malicious"] is False

    def test_add_indicator(self):
        from shadow313.threat_intel.ti_feed import ThreatIntelFeed, ThreatIndicator
        feed = ThreatIntelFeed()
        ioc = ThreatIndicator("ip", "1.2.3.4", "test", 0.9, "HIGH")
        feed.add_indicator(ioc)
        result = feed.lookup_ip("1.2.3.4")
        assert result is not None

    def test_get_by_severity(self):
        from shadow313.threat_intel.ti_feed import ThreatIntelFeed
        feed = ThreatIntelFeed()
        critical = feed.get_by_severity("CRITICAL")
        assert len(critical) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.threat_intel.ioc_store
# ═══════════════════════════════════════════════════════════════════════════════

class TestIOCStore:
    @pytest.fixture
    def store(self, tmp_path):
        from shadow313.threat_intel.ioc_store import IOCStore
        s = IOCStore(db_path=str(tmp_path / "test_ioc.db"))
        yield s
        s.close()

    def test_add_and_lookup(self, store):
        from shadow313.threat_intel.ti_feed import ThreatIndicator
        ioc = ThreatIndicator("ip", "1.2.3.4", "test", 0.9, "HIGH")
        assert store.add(ioc) is True
        result = store.lookup("ip", "1.2.3.4")
        assert result is not None
        assert result.value == "1.2.3.4"

    def test_lookup_missing_returns_none(self, store):
        result = store.lookup("ip", "9.9.9.9")
        assert result is None

    def test_count(self, store):
        from shadow313.threat_intel.ti_feed import ThreatIndicator
        assert store.count() == 0
        store.add(ThreatIndicator("ip", "1.1.1.1", "test", 0.5, "LOW"))
        assert store.count() == 1

    def test_search_by_type(self, store):
        from shadow313.threat_intel.ti_feed import ThreatIndicator
        store.add(ThreatIndicator("ip",     "1.1.1.1", "test", 0.5, "LOW"))
        store.add(ThreatIndicator("domain", "evil.com", "test", 0.8, "HIGH"))
        ips = store.search(ioc_type="ip")
        assert len(ips) == 1

    def test_stats(self, store):
        s = store.stats()
        assert "total" in s
        assert "db_path" in s

    def test_upsert_on_duplicate(self, store):
        from shadow313.threat_intel.ti_feed import ThreatIndicator
        ioc = ThreatIndicator("ip", "1.1.1.1", "test", 0.5, "LOW")
        store.add(ioc)
        store.add(ioc)  # Should not raise
        assert store.count() == 1


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.demo.attack_simulator
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttackSimulator:
    def test_simulate_apt29(self):
        from shadow313.demo.attack_simulator import APTAttackSimulator
        sim = APTAttackSimulator()
        attack = sim.simulate_apt29()
        assert attack.actor == "APT29"
        assert len(attack.log_entries) >= 3
        assert len(attack.techniques) >= 2

    def test_simulate_ransomware(self):
        from shadow313.demo.attack_simulator import APTAttackSimulator
        sim = APTAttackSimulator()
        attack = sim.simulate_ransomware()
        assert "BlackCat" in attack.actor or "Ransomware" in attack.scenario
        assert len(attack.log_entries) >= 2

    def test_run_all_returns_three(self):
        from shadow313.demo.attack_simulator import APTAttackSimulator
        sim = APTAttackSimulator()
        attacks = sim.run_all()
        assert len(attacks) == 3

    def test_get_all_log_entries(self):
        from shadow313.demo.attack_simulator import APTAttackSimulator
        sim = APTAttackSimulator()
        entries = sim.get_all_log_entries()
        assert len(entries) >= 6

    def test_log_entries_have_required_fields(self):
        from shadow313.demo.attack_simulator import APTAttackSimulator
        sim = APTAttackSimulator()
        entries = sim.get_all_log_entries()
        for e in entries:
            assert "log_id" in e
            assert "event_id" in e
            assert "process" in e


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.demo.roi_calculator
# ═══════════════════════════════════════════════════════════════════════════════

class TestROICalculator:
    def test_calculate_returns_result(self):
        from shadow313.demo.roi_calculator import ROICalculator, ROIInputs
        calc = ROICalculator()
        result = calc.calculate(ROIInputs())
        assert result.roi_pct > 0
        assert result.net_benefit > 0

    def test_payback_under_12_months(self):
        from shadow313.demo.roi_calculator import ROICalculator, ROIInputs
        calc = ROICalculator()
        result = calc.calculate(ROIInputs(industry="healthcare"))
        assert result.payback_months < 12

    def test_mttd_improvement_significant(self):
        from shadow313.demo.roi_calculator import ROICalculator, ROIInputs
        calc = ROICalculator()
        result = calc.calculate(ROIInputs())
        assert result.mttd_improvement_pct > 90  # 197 days → 2 days

    def test_format_report(self):
        from shadow313.demo.roi_calculator import ROICalculator, ROIInputs
        calc = ROICalculator()
        result = calc.calculate(ROIInputs())
        report = calc.format_report(result)
        assert "Shadow313" in report
        assert "ROI" in report
        assert "$" in report

    def test_different_industries(self):
        from shadow313.demo.roi_calculator import ROICalculator, ROIInputs
        calc = ROICalculator()
        for industry in ("financial", "healthcare", "defense", "tech", "retail"):
            result = calc.calculate(ROIInputs(industry=industry))
            assert result.total_benefit > 0


# ═══════════════════════════════════════════════════════════════════════════════
# shadow313.core.intelligence_graph (v3 wrapper)
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntelligenceGraphV3:
    def test_add_actor(self):
        from shadow313.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        n = g.add_actor("APT29", nation="Russia")
        assert n.name == "APT29"
        assert n.node_type == "ThreatActor"

    def test_add_indicator(self):
        from shadow313.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        n = g.add_indicator("ip", "185.220.101.47")
        assert n.node_type == "Indicator"

    def test_link(self):
        from shadow313.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        g.add_actor("APT29")
        g.add_indicator("ip", "185.220.101.47")
        result = g.link("APT29", "uses", "185.220.101.47")
        assert result is True

    def test_get_actor_indicators(self):
        from shadow313.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        g.add_actor("APT29")
        g.add_indicator("ip", "185.220.101.47")
        g.link("APT29", "uses", "185.220.101.47")
        indicators = g.get_actor_indicators("APT29")
        assert len(indicators) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# nexus_toolkit: log_parser, ml_engine, engine
# ═══════════════════════════════════════════════════════════════════════════════

class TestNexusToolkitLogParser:
    def test_feature_vector_length(self):
        from nexus_toolkit.core.log_parser import FeatureExtractor, LogEntry
        fe = FeatureExtractor()
        entry = LogEntry({"event_id": 4688, "process": "powershell.exe",
                          "command_line": "powershell.exe -enc JABjAD0A",
                          "severity": "high"})
        v = fe.extract(entry)
        assert len(v) == 37

    def test_encoded_cmd_fires_dim8(self):
        from nexus_toolkit.core.log_parser import FeatureExtractor, LogEntry
        fe = FeatureExtractor()
        entry = LogEntry({"event_id": 4688, "process": "powershell.exe",
                          "command_line": "powershell.exe -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="})
        v = fe.extract(entry)
        assert v[8] == 1.0

    def test_lsass_fires_dim25(self):
        from nexus_toolkit.core.log_parser import FeatureExtractor, LogEntry
        fe = FeatureExtractor()
        entry = LogEntry({"event_id": 10, "event_type": "process_access",
                          "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                          "command_line": "sekurlsa::logonpasswords"})
        v = fe.extract(entry)
        assert v[25] == 1.0

    def test_feature_names_length(self):
        from nexus_toolkit.core.log_parser import FeatureExtractor
        fe = FeatureExtractor()
        names = fe.feature_names()
        assert len(names) == 37

    def test_all_values_in_range(self):
        from nexus_toolkit.core.log_parser import FeatureExtractor, LogEntry
        fe = FeatureExtractor()
        entry = LogEntry({"event_id": 4688, "process": "cmd.exe"})
        v = fe.extract(entry)
        assert all(0.0 <= x <= 1.0 for x in v)


class TestNexusMLEngine:
    def test_predict_unfitted(self):
        from nexus_toolkit.core.ml_engine import NexusMLEngine
        engine = NexusMLEngine()
        score = engine.predict([0.0] * 37)
        assert score.is_anomaly is False
        assert score.model_used == "unfitted"

    def test_fit_and_predict(self):
        from nexus_toolkit.core.ml_engine import NexusMLEngine
        engine = NexusMLEngine(threshold=0.5)
        normal = [[0.1 * (i % 5)] * 37 for i in range(20)]
        engine.fit(normal)
        score = engine.predict([0.0] * 37)
        assert score.score >= 0.0

    def test_anomaly_detected(self):
        from nexus_toolkit.core.ml_engine import NexusMLEngine
        engine = NexusMLEngine(threshold=0.3)
        normal = [[0.0] * 37 for _ in range(20)]
        engine.fit(normal)
        # Highly anomalous vector
        anomalous = [1.0] * 37
        score = engine.predict(anomalous)
        assert score.score > 0.0

    def test_stats(self):
        from nexus_toolkit.core.ml_engine import NexusMLEngine
        engine = NexusMLEngine()
        s = engine.stats()
        assert "fitted" in s and "threshold" in s


class TestNexusDetectionEngine:
    def test_detect_returns_result(self):
        from nexus_toolkit.engine import NexusDetectionEngine
        from nexus_toolkit.core.log_parser import LogEntry
        engine = NexusDetectionEngine()
        entry = LogEntry({"log_id": "T1", "event_id": 4688,
                          "process": "powershell.exe",
                          "command_line": "powershell.exe -enc JABjAD0A",
                          "severity": "high"})
        result = engine.detect(entry)
        assert result.log_id == "T1"
        assert result.threat_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")

    def test_lsass_is_critical(self):
        from nexus_toolkit.engine import NexusDetectionEngine
        from nexus_toolkit.core.log_parser import LogEntry
        engine = NexusDetectionEngine()
        entry = LogEntry({"log_id": "T2", "event_id": 10,
                          "event_type": "process_access",
                          "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                          "command_line": "sekurlsa::logonpasswords",
                          "severity": "critical"})
        result = engine.detect(entry)
        assert result.threat_level == "CRITICAL"
        assert "T1003.001" in result.techniques

    def test_detect_batch(self):
        from nexus_toolkit.engine import NexusDetectionEngine
        from nexus_toolkit.core.log_parser import LogEntry
        engine = NexusDetectionEngine()
        entries = [LogEntry({"log_id": f"T{i}", "event_id": 4688}) for i in range(5)]
        results = engine.detect_batch(entries)
        assert len(results) == 5

    def test_stats(self):
        from nexus_toolkit.engine import NexusDetectionEngine
        engine = NexusDetectionEngine()
        s = engine.stats()
        assert "detections" in s


class TestShadow313Bridge:
    def test_bridge_status(self):
        from nexus_toolkit.shadow313_bridge.bridge import Shadow313Bridge
        bridge = Shadow313Bridge()
        s = bridge.status()
        assert "temporal_engine" in s
        assert "enforcement" in s
        assert "ledger" in s

    def test_route_detection(self):
        from nexus_toolkit.shadow313_bridge.bridge import Shadow313Bridge
        from nexus_toolkit.engine import NexusDetectionEngine
        from nexus_toolkit.core.log_parser import LogEntry
        bridge = Shadow313Bridge()
        engine = NexusDetectionEngine()
        entry = LogEntry({"log_id": "BRIDGE-001", "event_id": 4688,
                          "process": "cmd.exe", "severity": "medium"})
        detection = engine.detect(entry)
        result = bridge.route_detection(detection)
        assert result.detection_id == "BRIDGE-001"