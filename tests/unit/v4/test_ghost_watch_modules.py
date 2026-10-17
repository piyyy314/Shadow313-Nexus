"""Unit tests — shadow313.v4.ghost_watch (WE-FORGE, CADL, Oracle, Nightshade, Cerberus, Hephaestus)"""
import pytest
import time

class TestWEForge:
    def test_importable(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        assert WEForge is not None

    def test_lure_generation(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        lure = forge.generate_lure("Sensitive document content", "target-001")
        assert "lure_id" in lure
        assert lure["lure_id"].startswith("GW-LURE_")
        assert lure["target_id"] == "target-001"
        assert "signature" in lure

    def test_watermark_styles(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        for style in ["synonym_swap", "whitespace_inject", "unicode_homoglyph", "metadata_embed"]:
            lure = forge.generate_lure("test content", "t1", style=style)
            assert lure["style"] == style

    def test_trigger_detection(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        lure = forge.generate_lure("content", "target-002")
        result = forge.check_trigger(lure["lure_id"])
        assert result["triggered"] is True

    def test_purge_lure(self):
        from shadow313.v4.ghost_watch.we_forge import WEForge
        forge = WEForge()
        lure = forge.generate_lure("content", "target-003")
        assert forge.purge_lure(lure["lure_id"]) is True
        assert len(forge.lure_registry) == 0

class TestCADL:
    def test_importable(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine, CADLLevel
        assert CADLEngine is not None

    def test_level_escalation(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine
        engine = CADLEngine()
        result = engine.process_event({"id": "evt-001", "score": 0.97})
        assert result["level"] == 5
        assert result["action"] == "terminate_session"

    def test_low_score_monitor(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine
        engine = CADLEngine()
        result = engine.process_event({"id": "evt-002", "score": 0.2})
        assert result["level"] == 1
        assert result["action"] == "passive_log"

    def test_five_levels_exist(self):
        from shadow313.v4.ghost_watch.cadl import CADLLevel
        assert len(list(CADLLevel)) == 5

    def test_hook_registration(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine, CADLLevel
        engine = CADLEngine()
        called = []
        engine.register_hook(CADLLevel.L5_NEUTRALIZE, lambda e: called.append(e))
        engine.process_event({"id": "evt-003", "score": 0.99})
        assert len(called) == 1

    def test_reset(self):
        from shadow313.v4.ghost_watch.cadl import CADLEngine
        engine = CADLEngine()
        engine.process_event({"id": "evt-004", "score": 0.99})
        engine.reset()
        assert engine.current_level.value == 1
        assert engine.session_active is True

class TestOracle:
    def test_importable(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        assert OracleEngine is not None

    def test_predict_next(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        oracle = OracleEngine()
        pred = oracle.predict_next("initial_access")
        assert "predicted_next" in pred
        assert pred["probability"] > 0

    def test_simulate_path(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        oracle = OracleEngine()
        path = oracle.simulate_path("initial_access", steps=5)
        assert len(path) >= 2
        assert path[0] == "initial_access"

    def test_recommendations(self):
        from shadow313.v4.ghost_watch.oracle import OracleEngine
        oracle = OracleEngine()
        recs = oracle.recommend_predeployment("lateral_movement")
        assert len(recs) > 0

class TestHephaestus:
    def test_importable(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        assert HephaestusAuditor is not None

    def test_clean_binary(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        auditor = HephaestusAuditor()
        clean_data = b"normal binary content without suspicious patterns"
        auditor.sign_baseline("test.bin", clean_data)
        result = auditor.audit_binary("test.bin", clean_data)
        assert result["verdict"] == "CLEAN"
        assert result["hash_match"] is True

    def test_suspicious_binary(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        auditor = HephaestusAuditor()
        malicious = b"normal content /bin/sh backdoor payload"
        result = auditor.audit_binary("malware.bin", malicious)
        assert result["verdict"] == "SUSPICIOUS"
        assert len(result["suspicious_patterns"]) > 0

    def test_hash_mismatch_detection(self):
        from shadow313.v4.ghost_watch.hephaestus import HephaestusAuditor
        auditor = HephaestusAuditor()
        original = b"original content"
        modified = b"modified content"
        auditor.sign_baseline("artifact.bin", original)
        result = auditor.audit_binary("artifact.bin", modified)
        assert result["hash_match"] is False
