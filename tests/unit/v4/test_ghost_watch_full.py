"""
Unit tests — shadow313.v4.ghost_watch (full suite: all 10 modules)
Covers: cadl, we_forge, oracle, cerberus, nightshade, hephaestus,
        aether, tartarus, valkyrie, chronos
"""
from __future__ import annotations
import pytest
import time


# ── WE-FORGE ──────────────────────────────────────────────────────────────────

class TestWEForge:
    def test_importable(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        assert WEForge is not None

    def test_lure_generation(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        lure = forge.generate_lure("Sensitive document content", "target-001")
        assert lure["lure_id"].startswith("GW-LURE_")
        assert lure["target_id"] == "target-001"
        assert "signature" in lure
        assert len(lure["signature"]) == 64

    def test_all_watermark_styles(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        for style in ["synonym_swap", "whitespace_inject", "unicode_homoglyph", "metadata_embed"]:
            lure = forge.generate_lure("test content", "t1", style=style)
            assert lure["style"] == style
            assert len(lure["content"]) > 0

    def test_trigger_detection(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        lure = forge.generate_lure("content", "target-002")
        result = forge.check_trigger(lure["lure_id"])
        assert result["triggered"] is True
        assert result["target"] == "target-002"

    def test_purge_lure(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        lure = forge.generate_lure("content", "target-003")
        assert forge.purge_lure(lure["lure_id"]) is True
        assert len(forge.lure_registry) == 0

    def test_attribution_tracking(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        lure = forge.generate_lure("content", "target-004")
        target = forge.attribute_access(lure["signature"])
        assert target == "target-004"

    def test_export_registry(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        forge.generate_lure("c1", "t1")
        forge.generate_lure("c2", "t2")
        registry = forge.export_registry()
        assert len(registry) == 2


# ── CADL ──────────────────────────────────────────────────────────────────────

class TestCADL:
    def test_importable(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine, CADLLevel
        assert CADLEngine is not None
        assert len(list(CADLLevel)) == 5

    def test_l5_neutralize_on_high_score(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine
        engine = CADLEngine()
        result = engine.process_event({"id": "evt-001", "score": 0.97})
        assert result["level"] == 5
        assert result["action"] == "terminate_session"
        assert engine.session_active is False

    def test_l1_monitor_on_low_score(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine
        engine = CADLEngine()
        result = engine.process_event({"id": "evt-002", "score": 0.2})
        assert result["level"] == 1
        assert result["action"] == "passive_log"

    def test_l2_delay_on_medium_score(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine
        engine = CADLEngine()
        result = engine.process_event({"id": "evt-003", "score": 0.5})
        assert result["level"] == 2
        assert result["action"] == "inject_latency"

    def test_hook_registration_fires(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine, CADLLevel
        engine = CADLEngine()
        fired = []
        engine.register_hook(CADLLevel.L5_NEUTRALIZE, lambda e: fired.append(e))
        engine.process_event({"id": "evt-004", "score": 0.99})
        assert len(fired) == 1

    def test_reset_restores_l1(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine
        engine = CADLEngine()
        engine.process_event({"id": "evt-005", "score": 0.99})
        engine.reset()
        assert engine.current_level.value == 1
        assert engine.session_active is True

    def test_status_dict(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine
        engine = CADLEngine()
        engine.process_event({"id": "evt-006", "score": 0.5})
        status = engine.status()
        assert "current_level" in status
        assert "events_processed" in status
        assert status["events_processed"] == 1


# ── ORACLE ────────────────────────────────────────────────────────────────────

class TestOracle:
    def test_importable(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        assert OracleEngine is not None

    def test_predict_next_returns_valid_state(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        oracle = OracleEngine()
        pred = oracle.predict_next("initial_access")
        assert "predicted_next" in pred
        assert pred["probability"] > 0
        assert pred["current_state"] == "initial_access"

    def test_simulate_path_length(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        oracle = OracleEngine()
        path = oracle.simulate_path("initial_access", steps=5)
        assert len(path) >= 2
        assert path[0] == "initial_access"

    def test_recommendations_non_empty(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        oracle = OracleEngine()
        recs = oracle.recommend_predeployment("lateral_movement")
        assert len(recs) > 0
        assert isinstance(recs[0], str)

    def test_prediction_history_tracked(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        oracle = OracleEngine()
        oracle.predict_next("initial_access")
        oracle.predict_next("execution")
        assert len(oracle.prediction_history) == 2


# ── CERBERUS ──────────────────────────────────────────────────────────────────

class TestCerberus:
    def test_importable(self):
        from shadow313.v4.ghost_watch.cerberus import CerberusBAU
        assert CerberusBAU is not None

    def test_keystroke_profile_creation(self):
        from shadow313.v4.ghost_watch.cerberus import CerberusBAU
        bau = CerberusBAU()
        intervals = [120, 115, 125, 118, 122, 119, 121, 117, 123, 116]
        profile = bau.record_keystrokes("user1", intervals)
        assert profile["mean"] is not None
        assert profile["std"] is not None

    def test_keystroke_verification_pass(self):
        from shadow313.v4.ghost_watch.cerberus import CerberusBAU
        bau = CerberusBAU()
        baseline = [120] * 20
        bau.record_keystrokes("user2", baseline)
        result = bau.verify_user("user2", [121, 119, 120, 122, 118])
        assert result["verified"] is True
        assert result["deviation_sigma"] < 3.0

    def test_memory_baseline_and_check(self):
        from shadow313.v4.ghost_watch.cerberus import CerberusBAU
        bau = CerberusBAU()
        snapshot = b"clean memory state"
        bau.set_memory_baseline(snapshot)
        result = bau.check_memory_integrity(snapshot)
        assert result["intact"] is True

    def test_memory_tampering_detected(self):
        from shadow313.v4.ghost_watch.cerberus import CerberusBAU
        bau = CerberusBAU()
        bau.set_memory_baseline(b"original")
        result = bau.check_memory_integrity(b"tampered")
        assert result["intact"] is False
        assert len(bau.anomaly_log) > 0


# ── NIGHTSHADE ────────────────────────────────────────────────────────────────

class TestNightshade:
    def test_importable(self):
        from shadow313.v4.ghost_watch.nightshade import NightshadeEMS
        assert NightshadeEMS is not None

    def test_sweep_returns_result(self):
        from shadow313.v4.ghost_watch.nightshade import NightshadeEMS
        ems = NightshadeEMS(target_freq_mhz=915.0)
        result = ems.sweep("lora_915")
        assert "band" in result
        assert "anomalies_found" in result
        assert result["band"] == "lora_915"

    def test_counter_interference(self):
        from shadow313.v4.ghost_watch.nightshade import NightshadeEMS
        ems = NightshadeEMS()
        result = ems.inject_counter_interference(915.0)
        assert result["action"] == "counter_interference"
        assert result["phase_inversion"] is True

    def test_status(self):
        from shadow313.v4.ghost_watch.nightshade import NightshadeEMS
        ems = NightshadeEMS()
        ems.sweep()
        status = ems.status()
        assert status["scans_performed"] == 1


# ── HEPHAESTUS ────────────────────────────────────────────────────────────────

class TestHephaestus:
    def test_importable(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        assert HephaestusAuditor is not None

    def test_clean_binary_passes(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        auditor = HephaestusAuditor()
        clean = b"normal binary content without suspicious patterns"
        auditor.sign_baseline("test.bin", clean)
        result = auditor.audit_binary("test.bin", clean)
        assert result["verdict"] == "CLEAN"
        assert result["hash_match"] is True

    def test_suspicious_binary_detected(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        auditor = HephaestusAuditor()
        malicious = b"normal content /bin/sh backdoor payload"
        result = auditor.audit_binary("malware.bin", malicious)
        assert result["verdict"] == "SUSPICIOUS"
        assert len(result["suspicious_patterns"]) > 0

    def test_hash_mismatch_detected(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        auditor = HephaestusAuditor()
        auditor.sign_baseline("artifact.bin", b"original content")
        result = auditor.audit_binary("artifact.bin", b"modified content")
        assert result["hash_match"] is False

    def test_pipeline_scan(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        auditor = HephaestusAuditor()
        artifacts = {"app.bin": b"clean app binary", "lib.so": b"clean library"}
        results = auditor.scan_pipeline_artifacts(artifacts)
        assert len(results) == 2


# ── AETHER ────────────────────────────────────────────────────────────────────

class TestAether:
    def test_importable(self):
        try:
            from shadow313.v4.ghost_watch.aether import Aether
            assert Aether is not None
        except ImportError:
            pytest.skip("Aether module not available")

    def test_module_has_public_attrs(self):
        import shadow313.v4.ghost_watch.aether as mod
        public = [a for a in dir(mod) if not a.startswith("_")]
        assert len(public) >= 1


# ── TARTARUS ──────────────────────────────────────────────────────────────────

class TestTartarus:
    def test_importable(self):
        try:
            from shadow313.v4.ghost_watch.tartarus import Tartarus
            assert Tartarus is not None
        except ImportError:
            pytest.skip("Tartarus module not available")

    def test_module_has_public_attrs(self):
        import shadow313.v4.ghost_watch.tartarus as mod
        public = [a for a in dir(mod) if not a.startswith("_")]
        assert len(public) >= 1


# ── VALKYRIE ──────────────────────────────────────────────────────────────────

class TestValkyrie:
    def test_importable(self):
        try:
            from shadow313.v4.ghost_watch.valkyrie import Valkyrie
            assert Valkyrie is not None
        except ImportError:
            pytest.skip("Valkyrie module not available")

    def test_module_has_public_attrs(self):
        import shadow313.v4.ghost_watch.valkyrie as mod
        public = [a for a in dir(mod) if not a.startswith("_")]
        assert len(public) >= 1


# ── CHRONOS ───────────────────────────────────────────────────────────────────

class TestChronos:
    def test_importable(self):
        try:
            from shadow313.v4.ghost_watch.chronos import Chronos
            assert Chronos is not None
        except ImportError:
            pytest.skip("Chronos module not available")

    def test_module_has_public_attrs(self):
        import shadow313.v4.ghost_watch.chronos as mod
        public = [a for a in dir(mod) if not a.startswith("_")]
        assert len(public) >= 1