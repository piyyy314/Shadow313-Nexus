"""
Tests for shadow313.v4.intelligence.evidence_envelope
Validates the canonical evidence envelope schema and factory.
"""
import pytest
from shadow313.v4.intelligence.evidence_envelope import (
    EvidenceEnvelope,
    EvidenceFactory,
    ProvenanceClass,
    ProvenanceClassifier,
    Severity,
    ValidationStatus,
    RedactionStatus,
)


class TestEvidenceEnvelope:
    """Tests for the EvidenceEnvelope dataclass."""

    def test_create_minimal_envelope(self):
        e = EvidenceEnvelope(event_id="EVT-001")
        assert e.event_id == "EVT-001"

    def test_create_full_envelope(self):
        e = EvidenceEnvelope(
            event_id="EVT-002",
            event_type="DETECTION",
            source_system="nexus",
            severity="HIGH",
            technique="T1003.001",
            tactic="Credential Access",
            confidence=0.92,
        )
        assert e.event_id == "EVT-002"
        assert e.event_type == "DETECTION"
        assert e.severity == "HIGH"
        assert e.technique == "T1003.001"
        assert e.confidence == 0.92

    def test_to_dict_returns_dict(self):
        e = EvidenceEnvelope(event_id="EVT-003")
        d = e.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_has_required_fields(self):
        e = EvidenceEnvelope(event_id="EVT-004", source_system="nexus")
        d = e.to_dict()
        required = {"event_id", "schema_version", "source_system", "event_type",
                    "severity", "provenance_class", "validation_status"}
        for field in required:
            assert field in d, f"Missing field: {field}"

    def test_event_id_preserved(self):
        e = EvidenceEnvelope(event_id="EVT-UNIQUE-123")
        assert e.event_id == "EVT-UNIQUE-123"
        assert e.to_dict()["event_id"] == "EVT-UNIQUE-123"

    def test_default_severity_is_info(self):
        e = EvidenceEnvelope(event_id="EVT-005")
        assert e.severity == "INFO"

    def test_default_provenance_class(self):
        e = EvidenceEnvelope(event_id="EVT-006")
        assert e.provenance_class == "REAL_OBSERVATION"

    def test_default_validation_status(self):
        e = EvidenceEnvelope(event_id="EVT-007")
        assert e.validation_status == "PENDING"

    def test_default_schema_version(self):
        e = EvidenceEnvelope(event_id="EVT-008")
        assert e.schema_version == "1.0"

    def test_default_tenant(self):
        e = EvidenceEnvelope(event_id="EVT-009")
        assert e.tenant == "shadow313-nexus"

    def test_confidence_range(self):
        e = EvidenceEnvelope(event_id="EVT-010", confidence=0.75)
        assert 0.0 <= e.confidence <= 1.0

    def test_payload_optional(self):
        e = EvidenceEnvelope(event_id="EVT-011", payload={"key": "value"})
        assert e.payload == {"key": "value"}

    def test_payload_none_by_default(self):
        e = EvidenceEnvelope(event_id="EVT-012")
        assert e.payload is None

    def test_technique_optional(self):
        e = EvidenceEnvelope(event_id="EVT-013", technique="T1059.001")
        assert e.technique == "T1059.001"

    def test_chain_of_custody_is_list(self):
        e = EvidenceEnvelope(event_id="EVT-014")
        assert isinstance(e.chain_of_custody, list)

    def test_loss_indicator_default_false(self):
        e = EvidenceEnvelope(event_id="EVT-015")
        assert e.loss_indicator is False

    def test_observed_at_auto_populated(self):
        e = EvidenceEnvelope(event_id="EVT-016")
        assert e.observed_at is not None
        assert len(e.observed_at) > 0

    def test_ingested_at_auto_populated(self):
        e = EvidenceEnvelope(event_id="EVT-017")
        assert e.ingested_at is not None
        assert len(e.ingested_at) > 0

    def test_action_fields_optional(self):
        e = EvidenceEnvelope(
            event_id="EVT-018",
            action_requested="BLOCK",
            action_authorized="BLOCK",
            action_executed="BLOCK",
            action_result="SUCCESS",
        )
        assert e.action_requested == "BLOCK"
        assert e.action_result == "SUCCESS"

    def test_secret_redaction_status_default(self):
        e = EvidenceEnvelope(event_id="EVT-019")
        assert e.secret_redaction_status == "PENDING"

    def test_review_status_default(self):
        e = EvidenceEnvelope(event_id="EVT-020")
        assert e.review_status == "UNREVIEWED"


class TestEvidenceFactory:
    """Tests for the EvidenceFactory helper."""

    def test_factory_creates_envelope(self):
        factory = EvidenceFactory()
        assert factory is not None

    def test_factory_has_from_detection_method(self):
        assert hasattr(EvidenceFactory, "from_detection")

    def test_factory_from_detection_creates_envelope(self):
        factory = EvidenceFactory()
        e = factory.from_detection(
            technique="T1003.001",
            tactic="Credential Access",
            score=0.92,
            severity="CRITICAL",
        )
        assert e is not None
        assert isinstance(e, EvidenceEnvelope)
        assert e.technique == "T1003.001"


class TestProvenanceClass:
    """Tests for the ProvenanceClass enum."""

    def test_real_observation_exists(self):
        assert hasattr(ProvenanceClass, "REAL_OBSERVATION") or \
               "REAL_OBSERVATION" in [e.value if hasattr(e, 'value') else str(e)
                                       for e in ProvenanceClass]

    def test_provenance_class_is_iterable(self):
        values = list(ProvenanceClass)
        assert len(values) > 0


class TestProvenanceClassifier:
    """Tests for the ProvenanceClassifier."""

    def test_classifier_instantiates(self):
        pc = ProvenanceClassifier()
        assert pc is not None

    def test_classifier_has_classify_from_source(self):
        assert hasattr(ProvenanceClassifier, "classify_from_source")

    def test_classifier_is_production_eligible(self):
        assert hasattr(ProvenanceClassifier, "is_production_eligible")


class TestSeverityEnum:
    """Tests for the Severity enum."""

    def test_severity_has_critical(self):
        values = [str(e) for e in Severity]
        assert any("CRITICAL" in v.upper() for v in values)

    def test_severity_has_high(self):
        values = [str(e) for e in Severity]
        assert any("HIGH" in v.upper() for v in values)

    def test_severity_is_iterable(self):
        assert len(list(Severity)) > 0


class TestEnvelopeIntegration:
    """Integration tests for the evidence envelope system."""

    def test_multiple_envelopes_independent(self):
        e1 = EvidenceEnvelope(event_id="EVT-I001", severity="HIGH")
        e2 = EvidenceEnvelope(event_id="EVT-I002", severity="LOW")
        assert e1.event_id != e2.event_id
        assert e1.severity != e2.severity

    def test_to_dict_serializable(self):
        import json
        e = EvidenceEnvelope(
            event_id="EVT-I003",
            event_type="DETECTION",
            source_system="nexus",
            technique="T1055.001",
            payload={"pid": 1234, "process": "malware.exe"},
        )
        d = e.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d)
        assert len(json_str) > 0

    def test_envelope_with_all_optional_fields(self):
        e = EvidenceEnvelope(
            event_id="EVT-I004",
            schema_version="1.0",
            source_system="nexus-v4",
            source_identity="sensor-001",
            tenant="shadow313-nexus",
            environment="production",
            event_type="CREDENTIAL_ACCESS",
            severity="CRITICAL",
            confidence=0.95,
            provenance_class="REAL_OBSERVATION",
            asset="workstation-01",
            workload="lsass.exe",
            process="nanodump.exe",
            source_ip="192.168.1.100",
            technique="T1003.001",
            tactic="Credential Access",
            action_requested="BLOCK",
            action_authorized="BLOCK",
            action_executed="BLOCK",
            action_result="SUCCESS",
            payload={"dump_size_mb": 45},
            loss_indicator=False,
        )
        d = e.to_dict()
        assert d["event_id"] == "EVT-I004"
        assert d["severity"] == "CRITICAL"
        assert d["technique"] == "T1003.001"
