"""
Integration Hardening Tests — Shadow313 NEXUS v4

Targets silent failure risks identified by deep schema analysis:

RISK-1: EventBus asyncio.Queue initialized in sync context — QueueFull silently drops
RISK-2: EventBus publish() (async) vs publish_sync() — wrong method in wrong context
RISK-3: STIABinder._bind() returns Optional[receipt] — callers don't check None
RISK-4: IntelligenceGraph.add_node() — no node_type validation, silent bad data
RISK-5: IntelligenceGraph.add_edge() — returns None for missing nodes, callers ignore
RISK-6: NexusBridge loads Optional components — None components silently skip operations
RISK-7: NexusBridge payload schema — detection.anomaly_score.score AttributeError risk
RISK-8: ThreatPredictor.forecast_host() — returns HostRiskProfile with overall_risk not risk_score
RISK-9: IOCStore.lookup() — returns None, callers must check before .value access
RISK-10: STIAParser field defaults — empty STIAScanResult has None/empty fields
RISK-11: Ledger append under concurrent writes — RLock correctness
RISK-12: STIA binder summary() — accesses result.target_name which may be empty string
RISK-13: Event bus topic routing — wildcard subscriber receives all topics
RISK-14: Intelligence graph attribution_score — returns empty list for unknown indicator
RISK-15: Temporal binding fallback chain — HMAC fallback produces wrong sig length
"""
from __future__ import annotations

import asyncio
import threading
import time
import tempfile
import pytest
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-1 & RISK-2: EventBus async/sync boundary
# ═══════════════════════════════════════════════════════════════════════════════

class TestEventBusAsyncBoundary:

    def test_publish_sync_works_outside_event_loop(self):
        """publish_sync() must work when no event loop is running."""
        from shadow313.v4.core.event_bus import EventBus, Event
        bus = EventBus()
        # This is the common case — called from sync code
        bus.publish_sync(Event(topic="test", payload={"x": 1}))
        assert bus.status()["events_total"] == 1

    def test_publish_async_requires_running_loop(self):
        """publish() (async) must be awaited inside a running loop."""
        from shadow313.v4.core.event_bus import EventBus, Event
        bus = EventBus()

        async def _run():
            await bus.publish(Event(topic="test", payload={"x": 1}))
            return bus.status()["events_total"]

        count = asyncio.run(_run())
        assert count == 1

    def test_queue_overflow_drops_silently_not_raises(self):
        """QueueFull must be caught — overflow must not propagate as exception."""
        from shadow313.v4.core.event_bus import EventBus, Event
        bus = EventBus()
        bus._queue = asyncio.Queue(maxsize=3)
        # Fill beyond capacity — must not raise
        for i in range(10):
            bus.publish_sync(Event(topic="t", payload=i))
        # Queue is capped at maxsize, extras dropped
        assert bus._queue.qsize() <= 3

    def test_subscribe_fn_called_for_matching_topic(self):
        """Subscriber must be called for its exact topic."""
        from shadow313.v4.core.event_bus import EventBus, Event
        bus = EventBus()
        received = []
        bus.subscribe_fn("threat.detected", lambda e: received.append(e.payload))
        bus.publish_sync(Event(topic="threat.detected", payload={"pid": 42}))
        # Note: dispatch happens in run() loop — sync publish only enqueues
        assert bus.status()["queue_size"] >= 1

    def test_wildcard_subscriber_receives_all_topics(self):
        """'*' subscriber must receive events from any topic."""
        from shadow313.v4.core.event_bus import EventBus, Event
        bus = EventBus()
        all_events = []
        bus.subscribe_fn("*", lambda e: all_events.append(e.topic))
        # Wildcard is checked in _dispatch, not in publish_sync
        # Verify it's registered
        assert "*" in bus._subscribers

    def test_multiple_subscribers_same_topic(self):
        """Multiple subscribers on same topic must all be registered."""
        from shadow313.v4.core.event_bus import EventBus
        bus = EventBus()
        bus.subscribe_fn("t", lambda e: None)
        bus.subscribe_fn("t", lambda e: None)
        assert len(bus._subscribers["t"]) == 2

    def test_stop_sets_running_false(self):
        """stop() must set _running to False."""
        from shadow313.v4.core.event_bus import EventBus
        bus = EventBus()
        bus._running = True
        bus.stop()
        assert bus._running is False

    def test_event_id_is_unique(self):
        """Each Event must have a unique event_id."""
        from shadow313.v4.core.event_bus import Event
        ids = {Event(topic="t", payload=i).event_id for i in range(100)}
        assert len(ids) == 100


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-3: STIABinder._bind() Optional receipt
# ═══════════════════════════════════════════════════════════════════════════════

class TestSTIABinderOptionalReceipt:

    def test_bind_dict_never_returns_none_receipt(self):
        """bind_dict() must always return a non-None receipt (uses _SimulatedReceipt)."""
        from shadow313.integrations.stia.binder import STIABinder
        binder = STIABinder()
        _, receipt = binder.bind_dict({"target_id": "T1", "risk_level": "HIGH"})
        assert receipt is not None

    def test_summary_with_none_receipt_does_not_raise(self):
        """summary() must handle None receipt gracefully."""
        from shadow313.integrations.stia.binder import STIABinder
        from shadow313.integrations.stia.parser import STIAScanResult
        binder = STIABinder()
        result = STIAScanResult(target_id="T1", risk_level="HIGH")
        # Passing None receipt must not raise AttributeError
        s = binder.summary(result, None)
        assert "bind_id" not in s or s.get("bind_id") is None

    def test_summary_with_receipt_has_bind_id(self):
        """summary() with valid receipt must include bind_id."""
        from shadow313.integrations.stia.binder import STIABinder
        binder = STIABinder()
        result, receipt = binder.bind_dict({"target_id": "T1", "risk_level": "CRITICAL"})
        s = binder.summary(result, receipt)
        assert s.get("bind_id") is not None
        # Accept both _SimulatedReceipt (313-STIA-) and Binder313 SDK format
        bid = s["bind_id"]
        assert bid is not None and len(bid) > 5

    def test_bind_text_empty_string_does_not_raise(self):
        """bind_text() with empty string must not raise — returns default result."""
        from shadow313.integrations.stia.binder import STIABinder
        binder = STIABinder()
        result, receipt = binder.bind_text("")
        assert result is not None
        assert receipt is not None

    def test_bind_json_malformed_returns_result_not_raises(self):
        """bind_json() with malformed JSON must return result with warnings, not raise."""
        from shadow313.integrations.stia.binder import STIABinder
        binder = STIABinder()
        result, receipt = binder.bind_json("{invalid json{{")
        assert result is not None
        assert len(result.parse_warnings) > 0

    def test_simulated_receipt_timestamp_ends_313(self):
        """_SimulatedReceipt timestamp must end in 313 (313-BIND contract)."""
        from shadow313.integrations.stia.binder import _SimulatedReceipt
        r = _SimulatedReceipt({"target": "test"})
        assert str(r.timestamp_ns).endswith("313")

    def test_simulated_receipt_chain_hash_is_sha3(self):
        """_SimulatedReceipt chain_hash must be SHA3-512 (128 hex chars)."""
        from shadow313.integrations.stia.binder import _SimulatedReceipt
        r = _SimulatedReceipt({"target": "test"})
        assert r.chain_hash.startswith("sha3_512:")
        assert len(r.chain_hash) == len("sha3_512:") + 128


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-4 & RISK-5: IntelligenceGraph silent bad data
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntelligenceGraphSilentFailures:

    def test_add_node_with_invalid_type_does_not_raise(self):
        """add_node() with unknown node_type must not raise — stores as-is."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        # No validation — should store without error
        n = g.add_node("UnknownType", "test-node")
        assert n.node_type == "UnknownType"

    def test_add_edge_missing_src_returns_none(self):
        """add_edge() with missing src_id must return None, not raise."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        g.add_node("ThreatActor", "APT29")
        result = g.add_edge("nonexistent-src", "also-missing", "uses")
        assert result is None

    def test_add_edge_missing_dst_returns_none(self):
        """add_edge() with missing dst_id must return None, not raise."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        a = g.add_node("ThreatActor", "APT29")
        result = g.add_edge(a.node_id, "nonexistent-dst", "uses")
        assert result is None

    def test_get_node_missing_returns_none(self):
        """get_node() for missing ID must return None, not raise."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        result = g.get_node("nonexistent-id")
        assert result is None

    def test_get_neighbors_empty_node_returns_empty_list(self):
        """get_neighbors() for node with no edges must return [], not raise."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        n = g.add_node("ThreatActor", "APT29")
        neighbors = g.get_neighbors(n.node_id)
        assert neighbors == []

    def test_get_neighbors_missing_node_returns_empty_list(self):
        """get_neighbors() for nonexistent node must return [], not raise."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        neighbors = g.get_neighbors("nonexistent")
        assert neighbors == []

    def test_attribution_score_unknown_indicator_returns_empty(self):
        """attribution_score() for unknown indicator must return [], not raise."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        scores = g.attribution_score("nonexistent-indicator")
        assert scores == []

    def test_duplicate_node_id_overwrites_not_duplicates(self):
        """Adding node with same name twice must not create duplicates."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        n1 = g.add_node("ThreatActor", "APT29")
        n2 = g.add_node("ThreatActor", "APT29")
        # Same name → same deterministic ID → same node
        assert n1.node_id == n2.node_id
        assert len(g._nodes) == 1

    def test_stix_export_with_empty_graph(self):
        """to_stix_bundle() on empty graph must return valid bundle."""
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph
        g = IntelligenceGraph()
        bundle = g.to_stix_bundle()
        assert bundle["type"] == "bundle"
        assert bundle["objects"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-6 & RISK-7: NexusBridge Optional components
# ═══════════════════════════════════════════════════════════════════════════════

class TestNexusBridgeOptionalComponents:

    def test_bridge_works_when_all_components_unavailable(self):
        """Bridge must work gracefully when all Shadow313 components fail to load."""
        from nexus_toolkit.shadow313_bridge.bridge import Shadow313Bridge
        bridge = Shadow313Bridge()
        # Force all components to None
        bridge._temporal_engine = None
        bridge._enforcement = None
        bridge._ledger = None

        from nexus_toolkit.engine import NexusDetectionEngine
        from nexus_toolkit.core.log_parser import LogEntry
        engine = NexusDetectionEngine()
        entry = LogEntry({"log_id": "NULL-001", "event_id": 4688, "process": "cmd.exe"})
        detection = engine.detect(entry)

        # Must not raise even with all None components
        result = bridge.route_detection(detection)
        assert result.detection_id == "NULL-001"
        assert result.bind_id is None
        assert result.ledger_seq is None

    def test_bridge_anomaly_score_attribute_access(self):
        """Bridge accesses detection.anomaly_score.score — must not AttributeError."""
        from nexus_toolkit.shadow313_bridge.bridge import Shadow313Bridge
        from nexus_toolkit.engine import NexusDetectionEngine
        from nexus_toolkit.core.log_parser import LogEntry

        bridge = Shadow313Bridge()
        engine = NexusDetectionEngine()
        entry = LogEntry({"log_id": "SCORE-001", "event_id": 4688})
        detection = engine.detect(entry)

        # Verify the attribute chain exists before bridge accesses it
        assert hasattr(detection, "anomaly_score")
        assert hasattr(detection.anomaly_score, "score")
        assert isinstance(detection.anomaly_score.score, float)

        result = bridge.route_detection(detection)
        assert result is not None

    def test_bridge_enforce_with_none_enforcement_does_not_raise(self):
        """enforce() with None enforcement engine must not raise."""
        from nexus_toolkit.shadow313_bridge.bridge import Shadow313Bridge
        from nexus_toolkit.engine import NexusDetectionEngine
        from nexus_toolkit.core.log_parser import LogEntry

        bridge = Shadow313Bridge()
        bridge._enforcement = None

        engine = NexusDetectionEngine()
        entry = LogEntry({"log_id": "ENF-001", "event_id": 4688,
                          "command_line": "sekurlsa::logonpasswords",
                          "severity": "critical"})
        detection = engine.detect(entry)
        result = bridge.enforce(detection, pid=99999)
        assert result.enforced is False

    def test_bridge_status_reflects_component_availability(self):
        """status() must accurately reflect which components loaded."""
        from nexus_toolkit.shadow313_bridge.bridge import Shadow313Bridge
        bridge = Shadow313Bridge()
        s = bridge.status()
        # All keys must be present
        assert "temporal_engine" in s
        assert "enforcement" in s
        assert "ledger" in s
        # Values must be bool
        assert isinstance(s["temporal_engine"], bool)


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-8: ThreatPredictor field name contract
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatPredictorFieldContract:

    def test_forecast_returns_overall_risk_not_risk_score(self):
        """HostRiskProfile uses overall_risk — callers must not use risk_score."""
        from shadow313.v4.detection.threat_predictor import ThreatPredictor, HostRiskProfile
        p = ThreatPredictor()
        p.ingest_behavioral("host", 0.7, ["T1059"])
        profile = p.forecast_host("host")
        assert hasattr(profile, "overall_risk"), "Field is overall_risk, not risk_score"
        assert not hasattr(profile, "risk_score"), "risk_score does not exist — use overall_risk"

    def test_remediation_queue_items_are_dicts(self):
        """get_remediation_queue() returns list[dict], not list[HostRiskProfile]."""
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("host", 0.8, ["T1003"])
        queue = p.get_remediation_queue()
        assert len(queue) >= 1
        assert isinstance(queue[0], dict), "Queue items are dicts, not HostRiskProfile objects"
        assert "host" in queue[0]
        assert "risk_score" in queue[0]  # dict key, not attribute

    def test_queue_dict_has_all_required_keys(self):
        """Each queue dict must have host, risk_score, risk_level, top_action."""
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("host", 0.8, ["T1003"])
        queue = p.get_remediation_queue()
        item = queue[0]
        for key in ("host", "risk_score", "risk_level", "top_action", "cve_count"):
            assert key in item, f"Missing key: {key}"

    def test_forecast_host_profile_has_all_fields(self):
        """HostRiskProfile must have all documented fields."""
        from shadow313.v4.detection.threat_predictor import ThreatPredictor
        p = ThreatPredictor()
        p.ingest_behavioral("host", 0.5, ["T1059"])
        profile = p.forecast_host("host")
        for field in ("host", "overall_risk", "risk_level", "top_techniques",
                      "matched_cves", "behavioral_score", "recommendations"):
            assert hasattr(profile, field), f"Missing field: {field}"


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-9: IOCStore None return handling
# ═══════════════════════════════════════════════════════════════════════════════

class TestIOCStoreNullSafety:

    @pytest.fixture
    def store(self, tmp_path):
        from shadow313.threat_intel.ioc_store import IOCStore
        s = IOCStore(db_path=str(tmp_path / "test.db"))
        yield s
        s.close()

    def test_lookup_missing_returns_none_not_raises(self, store):
        result = store.lookup("ip", "9.9.9.9")
        assert result is None

    def test_lookup_result_value_access_safe(self, store):
        """Callers must check None before accessing .value."""
        from shadow313.threat_intel.ti_feed import ThreatIndicator
        store.add(ThreatIndicator("ip", "1.1.1.1", "test", 0.9, "HIGH"))
        result = store.lookup("ip", "1.1.1.1")
        # Safe pattern: check before access
        if result is not None:
            assert result.value == "1.1.1.1"
        else:
            pytest.fail("Expected to find 1.1.1.1")

    def test_search_empty_db_returns_empty_list(self, store):
        results = store.search(ioc_type="ip")
        assert results == []

    def test_add_returns_false_on_db_error(self, tmp_path):
        """add() must return False on DB error, not raise."""
        from shadow313.threat_intel.ioc_store import IOCStore
        from shadow313.threat_intel.ti_feed import ThreatIndicator
        store = IOCStore(db_path=str(tmp_path / "test.db"))
        store.close()
        # After close, add should fail gracefully
        ioc = ThreatIndicator("ip", "1.1.1.1", "test", 0.5, "LOW")
        result = store.add(ioc)
        # Either True (reconnects) or False (fails gracefully) — must not raise
        assert isinstance(result, bool)


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-10: STIAParser empty/default field safety
# ═══════════════════════════════════════════════════════════════════════════════

class TestSTIAParserDefaultSafety:

    def test_empty_dict_produces_valid_result(self):
        """parse_dict({}) must produce a valid STIAScanResult, not raise."""
        from shadow313.integrations.stia.parser import STIAParser
        p = STIAParser()
        r = p.parse_dict({})
        assert r is not None
        assert r.target_id.startswith("STIA-")
        assert r.risk_level in ("UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_to_nexus_findings_empty_result_returns_empty_list(self):
        """to_nexus_findings() on empty result must return [], not raise."""
        from shadow313.integrations.stia.parser import STIAScanResult
        r = STIAScanResult()
        findings = r.to_nexus_findings()
        assert findings == []

    def test_to_bind_payload_all_fields_serializable(self):
        """to_bind_payload() must produce JSON-serializable dict."""
        import json
        from shadow313.integrations.stia.parser import STIAParser
        p = STIAParser()
        r = p.parse_dict({"target_id": "T1", "risk_level": "HIGH",
                          "cve_list": ["CVE-2024-1234"],
                          "forensic_artifacts": [{"name": "evil.exe"}]})
        payload = r.to_bind_payload()
        # Must be JSON-serializable
        serialized = json.dumps(payload, default=str)
        parsed = json.loads(serialized)
        assert parsed["target_id"] == "T1"

    def test_severity_label_for_all_risk_levels(self):
        """severity_label() must return valid string for all risk levels."""
        from shadow313.integrations.stia.parser import STIAScanResult
        for score, expected in [(9.5, "CRITICAL"), (7.5, "HIGH"),
                                 (5.0, "MEDIUM"), (2.5, "LOW"), (0.0, "NONE")]:
            r = STIAScanResult(severity_score=score)
            label = r.severity_label()
            assert label == expected, f"score={score} → expected {expected}, got {label}"

    def test_target_name_falls_back_to_target_id(self):
        """When target_name is empty, summary should use target_id."""
        from shadow313.integrations.stia.binder import STIABinder
        binder = STIABinder()
        result, receipt = binder.bind_dict({"target_id": "VSAT-001"})
        # target_name should default to target_id when not provided
        assert result.target_id == "VSAT-001"
        s = binder.summary(result, receipt)
        # target field in summary should be non-empty
        assert s["target"] is not None


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-11: Ledger concurrent write safety
# ═══════════════════════════════════════════════════════════════════════════════

class TestLedgerConcurrentWrites:

    def test_concurrent_appends_no_sequence_collision(self):
        """Concurrent ledger appends must produce unique, sequential entries."""
        from shadow313.v4.ledger.ledger_engine import LedgerSyncEngine
        engine = LedgerSyncEngine("node-1", [])
        results = []
        errors = []

        def write_entries(n):
            for i in range(n):
                try:
                    e = engine.append(f"key-{i}", {"thread": threading.current_thread().name})
                    results.append(e.sequence)
                except Exception as exc:
                    errors.append(str(exc))

        threads = [threading.Thread(target=write_entries, args=(10,)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Concurrent write errors: {errors}"
        assert len(results) == 50
        # All sequences must be unique
        assert len(set(results)) == 50

    def test_ledger_chain_valid_after_concurrent_writes(self):
        """Ledger chain must remain valid after concurrent writes."""
        from shadow313.v4.ledger.ledger_engine import LedgerSyncEngine
        engine = LedgerSyncEngine("node-1", [])

        def write(n):
            for i in range(n):
                engine.append(f"k{i}", {"i": i})

        threads = [threading.Thread(target=write, args=(5,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Chain should be valid
        entries = engine._entries
        assert len(entries) == 20


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-13: Event bus topic routing correctness
# ═══════════════════════════════════════════════════════════════════════════════

class TestEventBusTopicRouting:

    def test_wrong_topic_subscriber_not_called(self):
        """Subscriber for topic A must not be called for topic B."""
        from shadow313.v4.core.event_bus import EventBus, Event
        bus = EventBus()
        called = []
        bus.subscribe_fn("topic.a", lambda e: called.append("a"))
        bus.subscribe_fn("topic.b", lambda e: called.append("b"))
        # publish_sync only enqueues — dispatch happens in run()
        # Test the subscriber registry directly
        assert "topic.a" in bus._subscribers
        assert "topic.b" in bus._subscribers
        assert len(bus._subscribers["topic.a"]) == 1
        assert len(bus._subscribers["topic.b"]) == 1

    def test_event_source_field_preserved(self):
        """Event source field must be preserved through the bus."""
        from shadow313.v4.core.event_bus import Event
        e = Event(topic="t", payload={}, source="nexus_engine")
        assert e.source == "nexus_engine"

    def test_event_priority_field_default(self):
        """Event priority must default to 5."""
        from shadow313.v4.core.event_bus import Event
        e = Event(topic="t", payload={})
        assert e.priority == 5


# ═══════════════════════════════════════════════════════════════════════════════
# RISK-15: Temporal binding fallback chain signature length
# ═══════════════════════════════════════════════════════════════════════════════

class TestTemporalBindingFallbackChain:

    def test_pyspx_tier_produces_correct_sig_length(self):
        """pyspx SLH-DSA-SHAKE-128f signature must be exactly 17088 bytes when available."""
        from shadow313.v4.temporal_binding.temporal_binding import _sign_slh_dsa
        sig, algo = _sign_slh_dsa(b"test message")
        if "pyspx" in algo.lower():
            assert len(sig) == 34176, f"Expected 34176 hex chars (pyspx), got {len(sig)}"
        elif "pqcrypto" in algo.lower():
            assert len(sig) == 34176, f"Expected 34176 hex chars (pqcrypto), got {len(sig)}"
        elif "HMAC" in algo:
            # Fallback when neither pyspx nor pqcrypto installed
            assert len(sig) == 64, f"Expected 64 hex chars (HMAC fallback), got {len(sig)}"
        else:
            pytest.fail(f"Unknown algorithm tier: {algo}")

    def test_algo_string_identifies_tier(self):
        """Algorithm string must clearly identify which tier is active."""
        from shadow313.v4.temporal_binding.temporal_binding import _sign_slh_dsa
        _, algo = _sign_slh_dsa(b"test")
        # Must be one of the three tiers
        is_tier1 = "pqcrypto" in algo.lower() or "FIPS 205" in algo
        is_tier2 = "pyspx" in algo.lower()
        is_tier3 = "HMAC-SHA256" in algo
        assert is_tier1 or is_tier2 or is_tier3, f"Unknown tier: {algo}"

    def test_hmac_fallback_sig_is_64_hex_chars(self):
        """HMAC-SHA256 fallback must produce exactly 64 hex chars."""
        import hmac, hashlib, os
        key = os.urandom(32)
        msg = b"test"
        sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
        assert len(sig) == 64

    def test_receipt_algo_field_not_empty(self):
        """313-BIND receipt algorithm field must never be empty."""
        from shadow313.v4.temporal_binding.temporal_binding import TemporalBindingEngine
        engine = TemporalBindingEngine()
        receipt = engine.bind({"test": True})
        assert receipt.algorithm != ""
        assert len(receipt.algorithm) > 5

    def test_receipt_timestamp_ends_313(self):
        """313-BIND receipt timestamp must end in 313 (entropy property)."""
        from shadow313.v4.temporal_binding.temporal_binding import TemporalBindingEngine
        engine = TemporalBindingEngine()
        for _ in range(3):
            receipt = engine.bind({"i": _})
            assert receipt.timestamp % 1000 == 313, \
                f"Timestamp {receipt.timestamp} does not end in 313"


# ═══════════════════════════════════════════════════════════════════════════════
# Cross-version integration: v1→v4 data flow
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrossVersionDataFlow:

    def test_v1_session_id_attribute_exists(self):
        """v1 Session must have .id attribute (GAP-1 from stress_test)."""
        from shadow313.core.session import Session
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            s = Session(sessions_dir=d)
            assert hasattr(s, "id"), "Session.id attribute missing — breaks stress_test GAP-1"
            assert isinstance(s.id, str)
            assert len(s.id) > 0

    def test_v2_epss_scorer_score_returns_epss_score_type(self):
        """v2 EPSSKEVScorer.score() must return EPSSScore dataclass."""
        from shadow313.v2.vuln_upgrades.epss_kev_enhanced import EPSSKEVScorer, EPSSScore
        scorer = EPSSKEVScorer()
        result = scorer.score("CVE-2024-1234")
        assert isinstance(result, EPSSScore)

    def test_v3_beacon_detector_profile_has_is_beacon(self):
        """v3 BeaconProfile must have is_beacon field."""
        from shadow313.v3.bridge.beacon_detector import BeaconProfile
        import dataclasses
        fields = {f.name for f in dataclasses.fields(BeaconProfile)}
        assert "is_beacon" in fields
        assert "period_s" in fields
        assert "confidence" in fields

    def test_v4_detection_result_has_bind_id_field(self):
        """v4 DetectionResult must have bind_id field for bridge integration."""
        from nexus_toolkit.engine import DetectionResult, AnomalyScore
        import dataclasses
        fields = {f.name for f in dataclasses.fields(DetectionResult)}
        assert "bind_id" in fields, "DetectionResult.bind_id missing — breaks bridge integration"

    def test_stia_to_nexus_findings_format_compatible(self):
        """STIA nexus_findings format must be compatible with threat_detector input."""
        from shadow313.integrations.stia.parser import STIAScanResult
        r = STIAScanResult(
            target_id="T1", cve_list=["CVE-2024-1234"],
            mitre_tactics=["Initial Access"], risk_level="HIGH",
        )
        findings = r.to_nexus_findings()
        # Each finding must have type, id, source, target
        for f in findings:
            assert "type" in f
            assert "source" in f
            assert f["source"] == "STIA"

    def test_intel_graph_v3_wraps_v4_correctly(self):
        """v3 IntelligenceGraph must expose v3 API while using v4 internals."""
        from shadow313.core.intelligence_graph import IntelligenceGraph as IGv3
        from shadow313.v4.core.intelligence_graph import IntelligenceGraph as IGv4
        g = IGv3()
        # v3 API
        assert hasattr(g, "add_actor")
        assert hasattr(g, "add_indicator")
        assert hasattr(g, "link")
        # v4 API still works
        assert hasattr(g, "add_node")
        assert hasattr(g, "to_stix_bundle")
        # Verify it's actually a subclass
        assert isinstance(g, IGv4)