"""
Tests for shadow313.v4.temporal_binding.supply_chain_simulation

Covers the 313-BIND supply chain attack simulation:
  1. Clean release — no alerts
  2. Workflow injection — WHEEL_HASH_MISMATCH
  3. Dependency confusion — DEP_HASH_MISMATCH + INSTALL_AFTER_VERIFICATION_FAILURE
  4. Receipt deletion — OUT_OF_ORDER_BIND_INDEX
  5. OIDC token replay — DUPLICATE_VERSION_RELEASE
"""
from __future__ import annotations

import pytest
from shadow313.v4.temporal_binding.supply_chain_simulation import (
    ReceiptChain,
    Receipt,
    SupplyChainDetector,
    AlertSeverity,
    Alert,
    build_clean_release,
    build_workflow_injection,
    build_dep_confusion,
    build_oidc_replay,
    CLEAN_WHEEL_SHA,
    MALICIOUS_WHEEL_SHA,
    PYYAML_GOOD_SHA,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def chain():
    return ReceiptChain()

@pytest.fixture
def detector():
    return SupplyChainDetector()

@pytest.fixture
def clean_chain_and_receipts():
    c = ReceiptChain()
    rs = build_clean_release(c)
    return c, rs


# ── ReceiptChain tests ────────────────────────────────────────────────────────

class TestReceiptChain:

    def test_instantiates(self, chain):
        assert chain is not None

    def test_bind_returns_receipt(self, chain):
        r = chain.bind("TEST_EVENT", {"key": "value"})
        assert isinstance(r, Receipt)

    def test_bind_index_increments(self, chain):
        r1 = chain.bind("EVENT_A", {})
        r2 = chain.bind("EVENT_B", {})
        r3 = chain.bind("EVENT_C", {})
        assert r1.bind_index == 1
        assert r2.bind_index == 2
        assert r3.bind_index == 3

    def test_timestamp_ends_in_313(self, chain):
        r = chain.bind("TEST", {})
        assert str(r.timestamp_ns).endswith("313")

    def test_chain_hash_format(self, chain):
        r = chain.bind("TEST", {})
        assert r.chain_hash.startswith("sha3_512:")

    def test_payload_hash_format(self, chain):
        r = chain.bind("TEST", {})
        assert r.payload_hash.startswith("sha3_256:")

    def test_prev_chain_hash_links(self, chain):
        r1 = chain.bind("FIRST", {})
        r2 = chain.bind("SECOND", {})
        assert r2.prev_chain_hash == r1.chain_hash

    def test_first_receipt_prev_hash_is_zeros(self, chain):
        r = chain.bind("FIRST", {})
        assert r.prev_chain_hash == "0" * 128

    def test_receipts_property(self, chain):
        chain.bind("A", {})
        chain.bind("B", {})
        assert len(chain.receipts) == 2

    def test_seq_property(self, chain):
        chain.bind("A", {})
        chain.bind("B", {})
        assert chain.seq == 2

    def test_different_payloads_different_hashes(self, chain):
        r1 = chain.bind("EVENT", {"data": "foo"})
        r2 = chain.bind("EVENT", {"data": "bar"})
        assert r1.payload_hash != r2.payload_hash

    def test_receipt_to_dict(self, chain):
        r = chain.bind("TEST", {"key": "val"})
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["event"] == "TEST"
        assert d["bind_index"] == 1

    def test_bind_id_format(self, chain):
        r = chain.bind("TEST", {})
        assert r.bind_id.startswith("313-SC-")

    def test_signature_present(self, chain):
        r = chain.bind("TEST", {})
        assert len(r.signature) > 0

    def test_multiple_receipts_unique_chain_hashes(self, chain):
        hashes = [chain.bind(f"EVENT_{i}", {"i": i}).chain_hash for i in range(10)]
        assert len(set(hashes)) == 10


# ── Clean release tests ───────────────────────────────────────────────────────

class TestCleanRelease:

    def test_clean_release_produces_8_receipts(self, clean_chain_and_receipts):
        _, receipts = clean_chain_and_receipts
        assert len(receipts) == 8

    def test_clean_release_events_in_order(self, clean_chain_and_receipts):
        _, receipts = clean_chain_and_receipts
        events = [r.event for r in receipts]
        assert "DEPENDENCY_AUDIT_STARTED" in events
        assert "DEPENDENCY_AUDIT_PASSED" in events
        assert "BUILD_STARTED" in events
        assert "TESTS_PASSED" in events
        assert "DIST_BUILT" in events
        assert "PACKAGE_RELEASE" in events

    def test_clean_release_no_alerts(self, clean_chain_and_receipts, detector):
        _, receipts = clean_chain_and_receipts
        alerts = detector.analyze(receipts)
        assert len(alerts) == 0

    def test_clean_release_wheel_hashes_match(self, clean_chain_and_receipts):
        _, receipts = clean_chain_and_receipts
        dist_built = next(r for r in receipts if r.event == "DIST_BUILT")
        release    = next(r for r in receipts if r.event == "PACKAGE_RELEASE")
        assert dist_built.payload["wheel_sha256"] == release.payload["wheel_sha256"]

    def test_clean_release_sequential_indices(self, clean_chain_and_receipts):
        _, receipts = clean_chain_and_receipts
        for i, r in enumerate(receipts, start=1):
            assert r.bind_index == i

    def test_clean_release_all_timestamps_end_313(self, clean_chain_and_receipts):
        _, receipts = clean_chain_and_receipts
        for r in receipts:
            assert str(r.timestamp_ns).endswith("313")

    def test_clean_release_chain_links_correct(self, clean_chain_and_receipts):
        _, receipts = clean_chain_and_receipts
        for i in range(1, len(receipts)):
            assert receipts[i].prev_chain_hash == receipts[i-1].chain_hash

    def test_clean_release_pyyaml_verified(self, clean_chain_and_receipts):
        _, receipts = clean_chain_and_receipts
        dep_receipts = [r for r in receipts if r.event == "TRANSITIVE_DEP_VERIFIED"]
        pyyaml = next((r for r in dep_receipts if r.payload.get("package") == "pyyaml"), None)
        assert pyyaml is not None
        assert pyyaml.payload["match"] is True


# ── Workflow injection tests ──────────────────────────────────────────────────

class TestWorkflowInjection:

    def test_injection_produces_wheel_hash_mismatch_alert(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_workflow_injection(chain)
        all_receipts = clean + attack
        alerts = detector.analyze(all_receipts)
        mismatch_alerts = [a for a in alerts if a.gap_type == "WHEEL_HASH_MISMATCH"]
        assert len(mismatch_alerts) >= 1

    def test_injection_alert_is_critical(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_workflow_injection(chain)
        alerts = detector.analyze(clean + attack)
        mismatch = next(a for a in alerts if a.gap_type == "WHEEL_HASH_MISMATCH")
        assert mismatch.severity == AlertSeverity.CRITICAL

    def test_injection_alert_has_correct_technique(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_workflow_injection(chain)
        alerts = detector.analyze(clean + attack)
        mismatch = next(a for a in alerts if a.gap_type == "WHEEL_HASH_MISMATCH")
        assert "T1195.001" in mismatch.attack_technique

    def test_injection_evidence_shows_different_hashes(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_workflow_injection(chain)
        alerts = detector.analyze(clean + attack)
        mismatch = next(a for a in alerts if a.gap_type == "WHEEL_HASH_MISMATCH")
        assert mismatch.evidence["dist_built_sha256"] != mismatch.evidence["release_sha256"]

    def test_injection_automated_action_contains_yank(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_workflow_injection(chain)
        alerts = detector.analyze(clean + attack)
        mismatch = next(a for a in alerts if a.gap_type == "WHEEL_HASH_MISMATCH")
        assert "YANK" in mismatch.automated_action.upper()

    def test_injection_dist_built_has_clean_hash(self):
        chain = ReceiptChain()
        build_clean_release(chain)
        attack = build_workflow_injection(chain)
        dist_built = next(r for r in attack if r.event == "DIST_BUILT")
        assert dist_built.payload["wheel_sha256"] == CLEAN_WHEEL_SHA

    def test_injection_release_has_malicious_hash(self):
        chain = ReceiptChain()
        build_clean_release(chain)
        attack = build_workflow_injection(chain)
        release = next(r for r in attack if r.event == "PACKAGE_RELEASE")
        assert release.payload["wheel_sha256"] == MALICIOUS_WHEEL_SHA


# ── Dependency confusion tests ────────────────────────────────────────────────

class TestDependencyConfusion:

    def test_dep_confusion_produces_hash_mismatch_alert(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_dep_confusion(chain)
        alerts = detector.analyze(clean + attack)
        dep_alerts = [a for a in alerts if a.gap_type == "DEP_HASH_MISMATCH"]
        assert len(dep_alerts) >= 1

    def test_dep_confusion_produces_install_after_failure_alert(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_dep_confusion(chain)
        alerts = detector.analyze(clean + attack)
        install_alerts = [a for a in alerts if a.gap_type == "INSTALL_AFTER_VERIFICATION_FAILURE"]
        assert len(install_alerts) >= 1

    def test_dep_confusion_hash_mismatch_is_high_severity(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_dep_confusion(chain)
        alerts = detector.analyze(clean + attack)
        dep_alert = next(a for a in alerts if a.gap_type == "DEP_HASH_MISMATCH")
        assert dep_alert.severity == AlertSeverity.HIGH

    def test_dep_confusion_install_after_failure_is_critical(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_dep_confusion(chain)
        alerts = detector.analyze(clean + attack)
        install_alert = next(a for a in alerts if a.gap_type == "INSTALL_AFTER_VERIFICATION_FAILURE")
        assert install_alert.severity == AlertSeverity.CRITICAL

    def test_dep_confusion_identifies_wrong_version(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_dep_confusion(chain)
        alerts = detector.analyze(clean + attack)
        dep_alert = next(a for a in alerts if a.gap_type == "DEP_HASH_MISMATCH")
        assert dep_alert.evidence["installed_version"] == "99.0.0"
        assert dep_alert.evidence["expected_version"] == "1.2.3"

    def test_dep_confusion_identifies_package_name(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_dep_confusion(chain)
        alerts = detector.analyze(clean + attack)
        dep_alert = next(a for a in alerts if a.gap_type == "DEP_HASH_MISMATCH")
        assert dep_alert.evidence["package"] == "shadow313-internal"

    def test_dep_confusion_abort_action(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_dep_confusion(chain)
        alerts = detector.analyze(clean + attack)
        dep_alert = next(a for a in alerts if a.gap_type == "DEP_HASH_MISMATCH")
        assert "ABORT" in dep_alert.automated_action.upper()

    def test_dep_confusion_quarantine_action(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_dep_confusion(chain)
        alerts = detector.analyze(clean + attack)
        install_alert = next(a for a in alerts if a.gap_type == "INSTALL_AFTER_VERIFICATION_FAILURE")
        assert "QUARANTINE" in install_alert.automated_action.upper()


# ── Receipt deletion tests ────────────────────────────────────────────────────

class TestReceiptDeletion:

    def test_deletion_produces_out_of_order_alert(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack, _ = build_receipt_deletion_scenario(chain)
        alerts = detector.analyze(clean + attack)
        gap_alerts = [a for a in alerts if a.gap_type == "OUT_OF_ORDER_BIND_INDEX"]
        assert len(gap_alerts) >= 1

    def test_deletion_alert_is_critical(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack, _ = build_receipt_deletion_scenario(chain)
        alerts = detector.analyze(clean + attack)
        gap_alert = next(a for a in alerts if a.gap_type == "OUT_OF_ORDER_BIND_INDEX")
        assert gap_alert.severity == AlertSeverity.CRITICAL

    def test_deletion_alert_has_correct_technique(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack, _ = build_receipt_deletion_scenario(chain)
        alerts = detector.analyze(clean + attack)
        gap_alert = next(a for a in alerts if a.gap_type == "OUT_OF_ORDER_BIND_INDEX")
        assert "T1070.004" in gap_alert.attack_technique

    def test_deletion_evidence_shows_missing_count(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack, _ = build_receipt_deletion_scenario(chain)
        alerts = detector.analyze(clean + attack)
        gap_alert = next(a for a in alerts if a.gap_type == "OUT_OF_ORDER_BIND_INDEX")
        assert gap_alert.evidence["missing_count"] >= 1

    def test_deletion_block_action(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack, _ = build_receipt_deletion_scenario(chain)
        alerts = detector.analyze(clean + attack)
        gap_alert = next(a for a in alerts if a.gap_type == "OUT_OF_ORDER_BIND_INDEX")
        assert "BLOCK" in gap_alert.automated_action.upper()


# ── OIDC token replay tests ───────────────────────────────────────────────────

class TestOIDCTokenReplay:

    def test_replay_produces_duplicate_version_alert(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_oidc_replay(chain)
        alerts = detector.analyze(clean + attack)
        dup_alerts = [a for a in alerts if a.gap_type == "DUPLICATE_VERSION_RELEASE"]
        assert len(dup_alerts) >= 1

    def test_replay_alert_is_critical(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_oidc_replay(chain)
        alerts = detector.analyze(clean + attack)
        dup_alert = next(a for a in alerts if a.gap_type == "DUPLICATE_VERSION_RELEASE")
        assert dup_alert.severity == AlertSeverity.CRITICAL

    def test_replay_alert_has_correct_technique(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_oidc_replay(chain)
        alerts = detector.analyze(clean + attack)
        dup_alert = next(a for a in alerts if a.gap_type == "DUPLICATE_VERSION_RELEASE")
        assert "T1588.001" in dup_alert.attack_technique

    def test_replay_evidence_shows_different_hashes(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_oidc_replay(chain)
        alerts = detector.analyze(clean + attack)
        dup_alert = next(a for a in alerts if a.gap_type == "DUPLICATE_VERSION_RELEASE")
        assert dup_alert.evidence["first_sha256"] != dup_alert.evidence["second_sha256"]

    def test_replay_evidence_shows_same_version(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_oidc_replay(chain)
        alerts = detector.analyze(clean + attack)
        dup_alert = next(a for a in alerts if a.gap_type == "DUPLICATE_VERSION_RELEASE")
        assert dup_alert.evidence["version"] == "4.0.5"

    def test_replay_yank_action(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_oidc_replay(chain)
        alerts = detector.analyze(clean + attack)
        dup_alert = next(a for a in alerts if a.gap_type == "DUPLICATE_VERSION_RELEASE")
        assert "YANK" in dup_alert.automated_action.upper()


# ── Detector tests ────────────────────────────────────────────────────────────

class TestSupplyChainDetector:

    def test_empty_receipts_no_alerts(self, detector):
        alerts = detector.analyze([])
        assert alerts == []

    def test_single_receipt_no_alerts(self, detector):
        chain = ReceiptChain()
        r = chain.bind("TEST", {})
        alerts = detector.analyze([r])
        assert alerts == []

    def test_alerts_sorted_by_bind_index(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack2 = build_workflow_injection(chain)
        attack3 = build_dep_confusion(chain)
        all_receipts = clean + attack2 + attack3
        alerts = detector.analyze(all_receipts)
        indices = [a.bind_index_from for a in alerts]
        assert indices == sorted(indices)

    def test_alert_has_all_required_fields(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_workflow_injection(chain)
        alerts = detector.analyze(clean + attack)
        assert len(alerts) > 0
        a = alerts[0]
        assert hasattr(a, 'severity')
        assert hasattr(a, 'gap_type')
        assert hasattr(a, 'bind_index_from')
        assert hasattr(a, 'bind_index_to')
        assert hasattr(a, 'attack_technique')
        assert hasattr(a, 'description')
        assert hasattr(a, 'evidence')
        assert hasattr(a, 'recommendation')
        assert hasattr(a, 'automated_action')

    def test_alert_display_returns_string(self, detector):
        chain = ReceiptChain()
        clean = build_clean_release(chain)
        attack = build_workflow_injection(chain)
        alerts = detector.analyze(clean + attack)
        display = alerts[0].display()
        assert isinstance(display, str)
        assert len(display) > 0

    def test_full_simulation_detects_all_attacks(self, detector):
        """Full simulation: all 5 scenarios, all attacks detected."""
        chain = ReceiptChain()
        all_receipts = []
        all_receipts.extend(build_clean_release(chain))
        all_receipts.extend(build_workflow_injection(chain))
        all_receipts.extend(build_dep_confusion(chain))
        attack4, _ = build_receipt_deletion_scenario(chain)
        all_receipts.extend(attack4)
        all_receipts.extend(build_oidc_replay(chain))

        alerts = detector.analyze(all_receipts)
        gap_types = {a.gap_type for a in alerts}

        assert "WHEEL_HASH_MISMATCH" in gap_types
        assert "DEP_HASH_MISMATCH" in gap_types
        assert "INSTALL_AFTER_VERIFICATION_FAILURE" in gap_types
        assert "OUT_OF_ORDER_BIND_INDEX" in gap_types
        assert "DUPLICATE_VERSION_RELEASE" in gap_types

    def test_release_without_pipeline_detected(self, detector):
        """A PACKAGE_RELEASE with no preceding pipeline receipts fires alert."""
        chain = ReceiptChain()
        # Publish directly without any pipeline receipts
        r = chain.bind("PACKAGE_RELEASE", {
            "version": "9.9.9",
            "wheel_sha256": MALICIOUS_WHEEL_SHA,
            "publisher": "attacker",
        })
        alerts = detector.analyze([r])
        pipeline_alerts = [a for a in alerts if a.gap_type == "RELEASE_WITHOUT_PIPELINE"]
        assert len(pipeline_alerts) >= 1
        assert pipeline_alerts[0].severity == AlertSeverity.CRITICAL


# ── Helper for receipt deletion scenario ─────────────────────────────────────

def build_receipt_deletion_scenario(chain: ReceiptChain):
    """Build a receipt deletion scenario — returns (receipts, prev_seq)."""
    chain.bind("DEPENDENCY_AUDIT_PASSED", {"packages_checked": 47})
    chain.bind("BUILD_STARTED", {"git_commit": "mno345pqr678901", "git_tag": "v4.0.4"})
    prev_seq = chain.seq
    chain.bind("TESTS_PASSED", {"total": 2648, "passed": 2648})
    # Simulate deletion by skipping 2 indices
    chain._seq += 2
    rs = [chain.bind("PACKAGE_RELEASE", {
        "version": "4.0.4",
        "wheel_sha256": MALICIOUS_WHEEL_SHA,
        "publisher": "github-actions-oidc",
        "note": "RECEIPTS_DELETED_TO_COVER_TRACKS",
    })]
    return rs, prev_seq