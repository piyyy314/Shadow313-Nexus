"""Regressions for evidence provenance and local delivery receipts."""

from pathlib import Path

from scripts.delivery import pipeline
from shadow313.v4.intelligence.evidence_envelope import (
    EvidenceEnvelope,
    ProvenanceClass,
    ProvenanceClassifier,
)

ROOT = Path(__file__).resolve().parents[2]


def test_unclassified_evidence_defaults_fail_closed():
    envelope = EvidenceEnvelope(event_id="EVT-UNCLASSIFIED")
    assert envelope.provenance_class == ProvenanceClass.UNCLASSIFIED.value
    assert not ProvenanceClassifier.is_production_eligible(envelope)


def test_unknown_production_source_is_not_assumed_to_be_real():
    assert (
        ProvenanceClassifier.classify_from_source("unknown-source", "production")
        == ProvenanceClass.UNCLASSIFIED
    )


def test_artifact_inventory_and_local_events_are_not_production_telemetry():
    assert ProvenanceClass.ARTIFACT_INVENTORY in ProvenanceClassifier.EXCLUDED_FROM_PRODUCTION
    assert ProvenanceClass.LOCAL_OPERATIONAL_EVENT in ProvenanceClassifier.EXCLUDED_FROM_PRODUCTION


def test_delivery_manifest_and_receipt_disclose_unsigned_local_provenance(monkeypatch):
    monkeypatch.setattr(pipeline, "get_version", lambda: "4.0.0")
    monkeypatch.setattr(pipeline, "get_git_sha", lambda: "abc1234")
    monkeypatch.setattr(pipeline, "get_git_branch", lambda: "feature/test")
    manifest = pipeline.generate_manifest(
        [{"name": "example.html", "size": 12, "priority": False, "type": "html"}]
    )
    receipt = pipeline.create_delivery_receipt(manifest)

    assert manifest["provenance_class"] == "ARTIFACT_INVENTORY"
    assert manifest["timestamp_status"] == "LOCAL_CLOCK_UNVERIFIED"
    assert receipt["signature_algorithm"] == "NONE"
    assert receipt["signature_status"] == "UNSIGNED"
    assert receipt["timestamp_status"] == "LOCAL_CLOCK_UNVERIFIED"

    daemon = (ROOT / "scripts/delivery/daemon.py").read_text(encoding="utf-8")
    hardened = (ROOT / "scripts/delivery/daemon_hardened.py").read_text(encoding="utf-8")
    assert '"signature_status": "UNSIGNED"' in daemon
    assert '"signature_status": "UNSIGNED"' in hardened


def test_delivery_daemons_do_not_claim_live_sensor_provenance():
    for relative in (
        "scripts/delivery/pipeline.py",
        "scripts/delivery/daemon.py",
        "scripts/delivery/daemon_hardened.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert '"REAL_OBSERVATION"' not in source
        assert "ARTIFACT_INVENTORY" in source
    hardened = (ROOT / "scripts/delivery/daemon_hardened.py").read_text(encoding="utf-8")
    assert '"LOCAL_OPERATIONAL_EVENT"' in hardened
