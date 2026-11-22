"""Regressions for evidence provenance and local delivery receipts."""

from pathlib import Path

from scripts.delivery import daemon, daemon_hardened, pipeline
from scripts.delivery.safe_paths import safe_docs_path
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


def test_local_delivery_daemon_auto_commit_is_opt_in_and_hook_safe():
    daemon = (ROOT / "scripts/delivery/daemon.py").read_text(encoding="utf-8")
    assert 'SHADOW313_AUTO_GIT_COMMIT' in daemon
    assert 'AUTO_GIT_COMMIT = True' not in daemon
    assert '"--no-verify"' not in daemon
    assert '"branch", "--show-current"' in daemon
    assert 'scripts" / "check-secrets.py' in daemon
    assert '"git", "commit"' in daemon


def test_safe_docs_path_rejects_traversal_and_symlink_escapes(tmp_path):
    docs = tmp_path / "docs"
    nested = docs / "nested"
    nested.mkdir(parents=True)
    safe_file = nested / "report.html"
    safe_file.write_text("safe", encoding="utf-8")
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")

    assert safe_docs_path(docs, "nested/report.html") == safe_file.resolve()
    for unsafe in (
        "../secret.txt",
        "%2e%2e/secret.txt",
        "nested/%2e%2e/%2e%2e/secret.txt",
        "/etc/passwd",
        r"..\\secret.txt",
        r"nested\\..\\secret.txt",
    ):
        assert safe_docs_path(docs, unsafe) is None

    link = docs / "escape.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pass
    else:
        assert safe_docs_path(docs, "escape.txt") is None


def test_both_delivery_daemons_use_safe_paths_and_loopback_binding():
    daemon_source = (ROOT / "scripts/delivery/daemon.py").read_text(encoding="utf-8")
    hardened_source = (ROOT / "scripts/delivery/daemon_hardened.py").read_text(encoding="utf-8")
    assert "safe_docs_path(DOCS_DIR, requested_name)" in daemon_source
    assert "safe_docs_path(DOCS_DIR, requested_name)" in hardened_source
    assert 'QuietServer(("127.0.0.1", SERVER_PORT)' in daemon_source
    assert 'BIND_HOST       = "127.0.0.1"' in hardened_source
    assert 'QuietServer(("", SERVER_PORT)' not in daemon_source

