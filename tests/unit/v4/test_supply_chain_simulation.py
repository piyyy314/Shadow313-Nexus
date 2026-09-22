"""
Tests for shadow313.v4.temporal_binding.supply_chain_simulation

Covers all three supply chain attack scenarios:
  1. Key Theft
  2. Key Compromise via CI/CD
  3. Plugin Backdoor

And the plugin signing integration (HMAC-SHA256 + cosign).
"""
from __future__ import annotations
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from shadow313.v4.temporal_binding.supply_chain_simulation import (
    KeyInfrastructure,
    create_receipt_with_key,
    verify_receipt_chain_with_key_audit,
    run_supply_chain_simulation,
    _IPFS_STORE,
)
import shadow313.v4.temporal_binding.supply_chain_simulation as sim_module


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_ipfs():
    """Reset global IPFS store and bind counter before each test."""
    sim_module._IPFS_STORE   = {}
    sim_module._BIND_COUNTER = 0
    yield
    sim_module._IPFS_STORE   = {}
    sim_module._BIND_COUNTER = 0


@pytest.fixture
def key_infra():
    return KeyInfrastructure()


# ═══════════════════════════════════════════════════════════════════════════════
# KEY INFRASTRUCTURE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestKeyInfrastructure:

    def test_legitimate_and_shadow_keys_are_different(self, key_infra):
        assert key_infra.legitimate_private_key != key_infra.shadow_private_key
        assert key_infra.legitimate_public_key  != key_infra.shadow_public_key
        assert key_infra.legitimate_fingerprint != key_infra.shadow_fingerprint

    def test_sign_and_verify_legitimate(self, key_infra):
        msg = b"test message"
        sig, fp = key_infra.sign_legitimate(msg)
        assert key_infra.verify_legitimate(msg, sig)
        assert not key_infra.verify_shadow(msg, sig)

    def test_sign_and_verify_shadow(self, key_infra):
        msg = b"test message"
        sig, fp = key_infra.sign_shadow(msg)
        assert key_infra.verify_shadow(msg, sig)
        assert not key_infra.verify_legitimate(msg, sig)

    def test_fingerprint_length(self, key_infra):
        assert len(key_infra.legitimate_fingerprint) == 16
        assert len(key_infra.shadow_fingerprint)     == 16

    def test_plugin_trust_registry_contains_legitimate_key(self, key_infra):
        result = key_infra.verify_plugin_trust(
            "shadow313-temporal",
            key_infra.legitimate_public_key,
        )
        assert result["trusted"] is True

    def test_plugin_trust_registry_rejects_shadow_key(self, key_infra):
        result = key_infra.verify_plugin_trust(
            "shadow313-temporal",
            key_infra.shadow_public_key,
        )
        assert result["trusted"] is False
        assert "mismatch" in result["reason"].lower() or "mismatch" in result.get("forensic_detail", "").lower()

    def test_plugin_trust_registry_rejects_unknown_plugin(self, key_infra):
        result = key_infra.verify_plugin_trust(
            "shadow313-unknown-plugin",
            key_infra.legitimate_public_key,
        )
        assert result["trusted"] is False

    def test_cosign_verifies_legitimate_key(self, key_infra):
        result = key_infra.verify_cosign(key_infra.legitimate_public_key)
        assert result["valid"] is True

    def test_cosign_rejects_shadow_key(self, key_infra):
        result = key_infra.verify_cosign(key_infra.shadow_public_key)
        assert result["valid"] is False
        assert "supply chain" in result.get("forensic_detail", "").lower()

    def test_cosign_signature_is_deterministic(self, key_infra):
        # Same key → same cosign signature
        sig1 = key_infra._cosign_sign(
            key_infra.legitimate_public_key,
            {"version": "4.0.0", "commit": "abc123", "builder": "github-actions"},
        )
        sig2 = key_infra._cosign_sign(
            key_infra.legitimate_public_key,
            {"version": "4.0.0", "commit": "abc123", "builder": "github-actions"},
        )
        assert sig1 == sig2


# ═══════════════════════════════════════════════════════════════════════════════
# RECEIPT CREATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestReceiptCreation:

    def test_legitimate_receipt_has_correct_fingerprint(self, key_infra):
        r = create_receipt_with_key(
            {"action": "scan"}, bind_index=1, key_infra=key_infra,
            use_shadow=False, verbose=False,
        )
        assert r["key_fingerprint"] == key_infra.legitimate_fingerprint

    def test_shadow_receipt_has_shadow_fingerprint(self, key_infra):
        r = create_receipt_with_key(
            {"action": "scan"}, bind_index=1, key_infra=key_infra,
            use_shadow=True, verbose=False,
        )
        assert r["key_fingerprint"] == key_infra.shadow_fingerprint

    def test_timestamp_ends_in_313(self, key_infra):
        for i in range(1, 4):
            r = create_receipt_with_key(
                {"action": f"scan_{i}"}, bind_index=i, key_infra=key_infra,
                use_shadow=False, verbose=False,
            )
            assert r["timestamp"] % 1000 == 313, f"Receipt {i} ts_mod={r['timestamp'] % 1000}"

    def test_receipt_has_ipfs_cid(self, key_infra):
        r = create_receipt_with_key(
            {"action": "scan"}, bind_index=1, key_infra=key_infra,
            use_shadow=False, verbose=False,
        )
        assert "ipfs_cid" in r
        assert r["ipfs_cid"].startswith("Qm")

    def test_receipt_stored_in_ipfs(self, key_infra):
        r = create_receipt_with_key(
            {"action": "scan"}, bind_index=1, key_infra=key_infra,
            use_shadow=False, verbose=False,
        )
        assert r["ipfs_cid"] in sim_module._IPFS_STORE

    def test_receipt_has_sha3_512(self, key_infra):
        r = create_receipt_with_key(
            {"action": "scan"}, bind_index=1, key_infra=key_infra,
            use_shadow=False, verbose=False,
        )
        assert "sha3_512" in r
        assert len(r["sha3_512"]) == 128  # SHA3-512 hex = 128 chars

    def test_receipt_bind_index_matches(self, key_infra):
        for i in [1, 5, 10, 100]:
            r = create_receipt_with_key(
                {"action": "scan"}, bind_index=i, key_infra=key_infra,
                use_shadow=False, verbose=False,
            )
            assert r["bind_index"] == i

    def test_different_content_produces_different_sha3(self, key_infra):
        r1 = create_receipt_with_key(
            {"action": "scan_a"}, bind_index=1, key_infra=key_infra,
            use_shadow=False, verbose=False,
        )
        r2 = create_receipt_with_key(
            {"action": "scan_b"}, bind_index=2, key_infra=key_infra,
            use_shadow=False, verbose=False,
        )
        assert r1["sha3_512"] != r2["sha3_512"]


# ═══════════════════════════════════════════════════════════════════════════════
# VERIFICATION TESTS — CLEAN CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerificationCleanChain:

    def _make_chain(self, key_infra, n: int, use_shadow: bool = False) -> list:
        return [
            create_receipt_with_key(
                {"id": i}, bind_index=i, key_infra=key_infra,
                use_shadow=use_shadow, verbose=False,
            )
            for i in range(1, n + 1)
        ]

    def test_clean_legitimate_chain_passes(self, key_infra):
        chain  = self._make_chain(key_infra, 5)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["valid"] is True
        assert result["layer1_timestamp"]["passed"]
        assert result["layer2_signature"]["passed"]
        assert result["layer2_bind_index"]["passed"]
        assert result["layer2_key_fingerprint"]["passed"]
        assert result["layer3_ipfs"]["passed"]
        assert result["layer4_plugin_trust"]["passed"]
        assert result["forensic_evidence"] == []

    def test_clean_chain_has_single_fingerprint(self, key_infra):
        chain  = self._make_chain(key_infra, 5)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert len(result["key_fingerprints_seen"]) == 1
        assert key_infra.legitimate_fingerprint in result["key_fingerprints_seen"]

    def test_empty_chain_passes(self, key_infra):
        result = verify_receipt_chain_with_key_audit([], key_infra)
        assert result["valid"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1: KEY THEFT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario1KeyTheft:
    """
    Key theft: attacker uses the legitimate key externally.
    The fraudulent receipt has a valid signature and correct fingerprint.
    Detection is limited — requires semantic audit.
    """

    def test_fraudulent_receipt_with_legitimate_key_passes_crypto_checks(self, key_infra):
        """
        This is the KEY THEFT limitation: if the attacker uses the legitimate key,
        the receipt is cryptographically indistinguishable from a real one.
        """
        legit_chain = [
            create_receipt_with_key(
                {"id": i, "result": "finding"}, bind_index=i, key_infra=key_infra,
                use_shadow=False, verbose=False,
            )
            for i in range(1, 6)
        ]
        # Attacker creates fraudulent receipt 6 with stolen legitimate key
        fraudulent = create_receipt_with_key(
            {"id": 6, "result": "no_findings"},  # Hides a finding
            bind_index=6, key_infra=key_infra,
            use_shadow=False,  # Uses legitimate key
            verbose=False,
        )
        chain  = legit_chain + [fraudulent]
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        # Key theft with legitimate key passes all cryptographic checks
        assert result["layer2_signature"]["passed"]
        assert result["layer2_key_fingerprint"]["passed"]
        assert not result["key_substitution_detected"]

    def test_key_theft_fingerprint_is_consistent(self, key_infra):
        """All receipts have the same fingerprint — no anomaly detectable."""
        chain = [
            create_receipt_with_key(
                {"id": i}, bind_index=i, key_infra=key_infra,
                use_shadow=False, verbose=False,
            )
            for i in range(1, 8)
        ]
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert len(result["key_fingerprints_seen"]) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2: KEY COMPROMISE VIA CI/CD
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario2KeyCompromise:
    """
    Key compromise: attacker injects shadow key via malicious CI/CD step.
    Receipts before compromise use legitimate key; after use shadow key.
    Detection: key fingerprint changes at the compromise point.
    """

    def _make_mixed_chain(self, key_infra, legit_count: int, shadow_count: int) -> list:
        chain = []
        for i in range(1, legit_count + 1):
            chain.append(create_receipt_with_key(
                {"id": i}, bind_index=i, key_infra=key_infra,
                use_shadow=False, verbose=False,
            ))
        for i in range(legit_count + 1, legit_count + shadow_count + 1):
            chain.append(create_receipt_with_key(
                {"id": i}, bind_index=i, key_infra=key_infra,
                use_shadow=True, verbose=False,
            ))
        return chain

    def test_mixed_chain_is_detected(self, key_infra):
        chain  = self._make_mixed_chain(key_infra, 5, 5)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["valid"] is False

    def test_key_substitution_detected(self, key_infra):
        chain  = self._make_mixed_chain(key_infra, 5, 5)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["key_substitution_detected"] is True

    def test_two_fingerprints_detected(self, key_infra):
        chain  = self._make_mixed_chain(key_infra, 5, 5)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert len(result["key_fingerprints_seen"]) == 2
        assert key_infra.legitimate_fingerprint in result["key_fingerprints_seen"]
        assert key_infra.shadow_fingerprint      in result["key_fingerprints_seen"]

    def test_compromise_point_identified(self, key_infra):
        chain  = self._make_mixed_chain(key_infra, 5, 5)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        failures = result["layer2_key_fingerprint"]["failures"]
        assert len(failures) >= 1
        # The key change should be detected at receipt 6 (first shadow receipt)
        assert failures[0]["bind_index"] == 6

    def test_l2a_signature_detects_shadow_key(self, key_infra):
        chain  = self._make_mixed_chain(key_infra, 3, 3)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["layer2_signature"]["passed"] is False
        # Failures should reference the shadow-signed receipts
        shadow_failures = [f for f in result["layer2_signature"]["failures"]
                           if "SHADOW" in f.get("detail", "")]
        assert len(shadow_failures) >= 1

    def test_l4_plugin_trust_fails_for_shadow_key(self, key_infra):
        chain  = self._make_mixed_chain(key_infra, 3, 3)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["layer4_plugin_trust"]["passed"] is False

    def test_forensic_evidence_contains_key_change_point(self, key_infra):
        chain  = self._make_mixed_chain(key_infra, 5, 5)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        layers = [ev["layer"] for ev in result["forensic_evidence"]]
        assert "L2_KEY_CHANGE_POINT" in layers or "L2_KEY_FINGERPRINT_INCONSISTENCY" in layers

    def test_forensic_evidence_severity_is_critical(self, key_infra):
        chain  = self._make_mixed_chain(key_infra, 3, 3)
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        for ev in result["forensic_evidence"]:
            assert ev["severity"] in ("CRITICAL", "HIGH")

    def test_single_shadow_receipt_in_chain_detected(self, key_infra):
        """Even a single compromised receipt in a long chain is detected."""
        chain = []
        for i in range(1, 10):
            use_shadow = (i == 5)  # Only receipt 5 is compromised
            chain.append(create_receipt_with_key(
                {"id": i}, bind_index=i, key_infra=key_infra,
                use_shadow=use_shadow, verbose=False,
            ))
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["valid"] is False
        assert result["key_substitution_detected"] is True

    def test_all_shadow_receipts_detected(self, key_infra):
        """Complete key replacement (all receipts use shadow key) is detected."""
        chain = [
            create_receipt_with_key(
                {"id": i}, bind_index=i, key_infra=key_infra,
                use_shadow=True, verbose=False,
            )
            for i in range(1, 6)
        ]
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["valid"] is False
        assert result["key_substitution_detected"] is True
        # Should detect wrong fingerprint (not inconsistency, but wrong key)
        layers = [ev["layer"] for ev in result["forensic_evidence"]]
        assert any("KEY_FINGERPRINT" in l for l in layers)


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3: PLUGIN BACKDOOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario3PluginBackdoor:

    def test_malicious_plugin_blocked_by_trust_registry(self, key_infra):
        result = key_infra.verify_plugin_trust(
            "shadow313-temporal",
            key_infra.shadow_public_key,
        )
        assert result["trusted"] is False

    def test_malicious_plugin_blocked_by_cosign(self, key_infra):
        result = key_infra.verify_cosign(key_infra.shadow_public_key)
        assert result["valid"] is False

    def test_backdoored_receipts_detected_via_fingerprint(self, key_infra):
        """If plugin bypasses trust check, key fingerprint audit still detects it."""
        chain = [
            create_receipt_with_key(
                {"id": i}, bind_index=i, key_infra=key_infra,
                use_shadow=True, verbose=False,
            )
            for i in range(1, 6)
        ]
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["valid"] is False
        assert result["layer4_plugin_trust"]["passed"] is False

    def test_legitimate_plugin_passes_all_checks(self, key_infra):
        trust  = key_infra.verify_plugin_trust("shadow313-temporal", key_infra.legitimate_public_key)
        cosign = key_infra.verify_cosign(key_infra.legitimate_public_key)
        assert trust["trusted"]  is True
        assert cosign["valid"]   is True

    def test_unknown_plugin_rejected(self, key_infra):
        result = key_infra.verify_plugin_trust(
            "shadow313-evil-plugin",
            key_infra.legitimate_public_key,
        )
        assert result["trusted"] is False
        assert "not in trust registry" in result["reason"].lower()


# ═══════════════════════════════════════════════════════════════════════════════
# BIND INDEX GAP DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestBindIndexGapDetection:

    def test_gap_in_bind_index_detected(self, key_infra):
        r1 = create_receipt_with_key({"id": 1}, bind_index=1, key_infra=key_infra, use_shadow=False, verbose=False)
        r2 = create_receipt_with_key({"id": 2}, bind_index=2, key_infra=key_infra, use_shadow=False, verbose=False)
        r4 = create_receipt_with_key({"id": 4}, bind_index=4, key_infra=key_infra, use_shadow=False, verbose=False)
        result = verify_receipt_chain_with_key_audit([r1, r2, r4], key_infra)
        assert result["layer2_bind_index"]["passed"] is False
        failures = result["layer2_bind_index"]["failures"]
        assert any(3 in f.get("missing", []) for f in failures)

    def test_no_gap_passes(self, key_infra):
        chain = [
            create_receipt_with_key({"id": i}, bind_index=i, key_infra=key_infra, use_shadow=False, verbose=False)
            for i in range(1, 6)
        ]
        result = verify_receipt_chain_with_key_audit(chain, key_infra)
        assert result["layer2_bind_index"]["passed"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# IPFS ORPHAN DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestIPFSOrphanDetection:

    def test_deleted_receipt_leaves_ipfs_orphan(self, key_infra):
        chain = [
            create_receipt_with_key({"id": i}, bind_index=i, key_infra=key_infra, use_shadow=False, verbose=False)
            for i in range(1, 6)
        ]
        # Attacker deletes receipt 3 from the chain
        chain_without_3 = [r for r in chain if r["bind_index"] != 3]
        result = verify_receipt_chain_with_key_audit(chain_without_3, key_infra)
        # Should detect both the bind_index gap AND the IPFS orphan
        assert result["layer2_bind_index"]["passed"] is False
        assert result["layer3_ipfs"]["passed"] is False
        orphan_evidence = [ev for ev in result["forensic_evidence"] if "ORPHAN" in ev["layer"]]
        assert len(orphan_evidence) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# FULL SIMULATION INTEGRATION TEST
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullSimulation:

    def test_simulation_runs_without_error(self):
        report = run_supply_chain_simulation(verbose=False)
        assert "scenarios" in report
        assert "summary"   in report

    def test_simulation_has_three_scenarios(self):
        report = run_supply_chain_simulation(verbose=False)
        assert len(report["scenarios"]) == 3

    def test_key_compromise_scenario_detected(self):
        report = run_supply_chain_simulation(verbose=False)
        s2 = report["scenarios"][1]
        assert s2["scenario"] == "Key Compromise via CI/CD"
        assert s2["detected"] is True

    def test_plugin_backdoor_scenario_detected(self):
        report = run_supply_chain_simulation(verbose=False)
        s3 = report["scenarios"][2]
        assert s3["scenario"] == "Plugin Backdoor"
        assert s3["detected"] is True

    def test_summary_counts_are_correct(self):
        report = run_supply_chain_simulation(verbose=False)
        summary = report["summary"]
        assert summary["scenarios_simulated"] == 3
        # Key compromise and plugin backdoor are always detected
        assert summary["key_compromise_detected"]  is True
        assert summary["plugin_backdoor_detected"] is True

    def test_summary_identifies_key_theft_gap(self):
        report = run_supply_chain_simulation(verbose=False)
        summary = report["summary"]
        assert "key theft" in summary["critical_gap"].lower() or \
               "legitimate key" in summary["critical_gap"].lower()

    def test_plugin_signing_closes_gap(self):
        report = run_supply_chain_simulation(verbose=False)
        assert report["summary"]["plugin_signing_closes_gap"] is True

    def test_all_scenarios_have_forensic_evidence_or_key_insight(self):
        report = run_supply_chain_simulation(verbose=False)
        for s in report["scenarios"]:
            assert "key_insight" in s
            assert len(s["key_insight"]) > 10

    def test_report_is_json_serializable(self):
        report = run_supply_chain_simulation(verbose=False)
        serialized = json.dumps(report, default=str)
        parsed     = json.loads(serialized)
        assert parsed["summary"]["scenarios_simulated"] == 3