"""Regressions for evidence provenance and local delivery receipts."""

import subprocess
import sys
from pathlib import Path

from scripts.delivery import pipeline
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


def test_delivery_daemon_supports_direct_script_execution():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/delivery/daemon.py"), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "S313 NEXUS Delivery Daemon" in result.stdout


def test_both_delivery_daemons_use_safe_paths_and_loopback_binding():
    daemon_source = (ROOT / "scripts/delivery/daemon.py").read_text(encoding="utf-8")
    hardened_source = (ROOT / "scripts/delivery/daemon_hardened.py").read_text(encoding="utf-8")
    assert "safe_docs_path(DOCS_DIR, requested_name)" in daemon_source
    assert "except ModuleNotFoundError" in daemon_source
    assert "from safe_paths import safe_docs_path" in daemon_source
    assert "safe_docs_path(DOCS_DIR, requested_name)" in hardened_source
    assert "except ModuleNotFoundError" in hardened_source
    assert "from safe_paths import safe_docs_path" in hardened_source
    assert 'QuietServer(("127.0.0.1", SERVER_PORT)' in daemon_source
    assert 'BIND_HOST       = "127.0.0.1"' in hardened_source
    assert 'QuietServer(("", SERVER_PORT)' not in daemon_source



def test_delivery_workflow_reuses_one_manifest_and_is_master_only():
    workflow = (ROOT / ".github/workflows/deliver.yml").read_text(encoding="utf-8")
    assert "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" in workflow
    assert "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" in workflow
    assert "delivery-records-${{ github.run_id }}" in workflow
    assert workflow.count("from scripts.delivery.pipeline import") == 1
    assert "if: github.ref == 'refs/heads/master'" in workflow
    assert "concurrency:" in workflow
    assert "git push origin HEAD:master" in workflow


def test_repository_root_is_not_a_second_github_pages_publisher():
    assert not (ROOT / ".github/workflows/github-pages.yml").exists()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "secondary delivery-artifact portal" in readme
    assert "Vercel remains the canonical public website host" in readme

def test_provenance_coverage_does_not_count_unclassified_as_classified():
    classified = EvidenceEnvelope(
        event_id="EVT-REAL",
        provenance_class=ProvenanceClass.REAL_OBSERVATION.value,
    )
    unclassified = EvidenceEnvelope(
        event_id="EVT-UNKNOWN",
        provenance_class=ProvenanceClass.UNCLASSIFIED.value,
    )
    report = ProvenanceClassifier.audit_provenance_coverage([classified, unclassified])

    assert report["total"] == 2
    assert report["classified"] == 1
    assert report["unclassified"] == 1
    assert report["coverage_pct"] == 50.0
    assert report["production_eligible"] == 1
