"""
Tests for shadow313.v4.temporal_binding.hardened_binding

Covers:
  - HardenedKeyInfrastructure: SK.seed integrity, mlock, hedged mode, counter chain
  - MemoryIntegrityViolation: raised when SK.seed is corrupted (Rowhammer simulation)
  - Signing rate anomaly detection
  - MLDSATrustRegistry: quantum-resistant trust registry (ML-DSA-65 proxy)
  - QuantumResistantIPFS: SHA3-256 CIDv1 anchoring
  - HardenedReceiptCreator: full pipeline with all 5 fixes
  - Security status reporting
  - Threat model coverage assertions

Threat model:
  SLasH-DSA (arXiv:2509.13048, uASC 2026) — Rowhammer on SK.seed
  HNDL (Harvest-Now-Decrypt-Later) — pre-CRQC data harvesting
"""
from __future__ import annotations
import hashlib
import hmac
import time
import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from shadow313.v4.temporal_binding.hardened_binding import (
    HardenedKeyInfrastructure,
    MemoryIntegrityViolation,
    MLDSATrustRegistry,
    QuantumResistantIPFS,
    HardenedReceiptCreator,
    HardenedReceipt,
    MIN_SECURITY_LEVEL,
    MAX_SIGNING_RATE_PER_MINUTE,
    SK_SEED_SIZE,
    demo_hardened_binding,
)


# ═══════════════════════════════════════════════════════════════════════════════
# HARDENED KEY INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

class TestHardenedKeyInfrastructure:

    def test_sk_seed_is_random(self):
        k1 = HardenedKeyInfrastructure()
        k2 = HardenedKeyInfrastructure()
        assert k1._sk_seed != k2._sk_seed

    def test_sk_seed_size_is_32_bytes(self):
        k = HardenedKeyInfrastructure()
        assert len(k._sk_seed) == SK_SEED_SIZE

    def test_integrity_hash_computed_at_init(self):
        k = HardenedKeyInfrastructure()
        expected = hashlib.sha3_256(k._sk_seed).digest()
        assert k._seed_integrity_hash == expected

    def test_sign_succeeds_with_clean_seed(self):
        k = HardenedKeyInfrastructure()
        sig, chain = k.sign(b"test message")
        assert len(sig) == 64  # SHA3-256 hex
        assert len(chain) == 16

    def test_sign_increments_counter(self):
        k = HardenedKeyInfrastructure()
        assert k.sign_count == 0
        k.sign(b"msg1")
        assert k.sign_count == 1
        k.sign(b"msg2")
        assert k.sign_count == 2

    def test_counter_chain_changes_each_sign(self):
        k = HardenedKeyInfrastructure()
        _, chain1 = k.sign(b"msg1")
        _, chain2 = k.sign(b"msg2")
        assert chain1 != chain2

    def test_hedged_mode_produces_different_sigs_for_same_message(self):
        """Hedged mode adds randomness — same message produces different signatures."""
        k = HardenedKeyInfrastructure()
        sig1, _ = k.sign(b"same message", use_hedged_mode=True)
        sig2, _ = k.sign(b"same message", use_hedged_mode=True)
        # With hedged mode, signatures should differ (randomness added)
        # Note: may occasionally be equal by chance — test multiple times
        sigs = set()
        for _ in range(5):
            s, _ = k.sign(b"same message", use_hedged_mode=True)
            sigs.add(s)
        assert len(sigs) > 1, "Hedged mode should produce varied signatures"

    def test_rowhammer_simulation_raises_memory_integrity_violation(self):
        """
        Simulate Rowhammer: corrupt SK.seed in memory.
        The integrity check should catch it before signing.
        """
        k = HardenedKeyInfrastructure()
        # Simulate Rowhammer bit flip: corrupt one byte of SK.seed
        corrupted = bytearray(k._sk_seed)
        corrupted[0] ^= 0x01  # Flip one bit
        k._sk_seed = bytes(corrupted)
        # Signing should raise MemoryIntegrityViolation
        with pytest.raises(MemoryIntegrityViolation):
            k.sign(b"test message")

    def test_rowhammer_alert_recorded(self):
        """After Rowhammer simulation, alert should be in the alert log."""
        k = HardenedKeyInfrastructure()
        corrupted = bytearray(k._sk_seed)
        corrupted[0] ^= 0x01
        k._sk_seed = bytes(corrupted)
        try:
            k.sign(b"test")
        except MemoryIntegrityViolation:
            pass
        alerts = k.get_alerts()
        assert len(alerts) >= 1
        assert alerts[0]["type"] == "MEMORY_INTEGRITY_VIOLATION"
        assert alerts[0]["severity"] == "CRITICAL"

    def test_integrity_ok_with_clean_seed(self):
        k = HardenedKeyInfrastructure()
        assert k._verify_seed_ok() is True

    def test_integrity_fails_with_corrupted_seed(self):
        k = HardenedKeyInfrastructure()
        corrupted = bytearray(k._sk_seed)
        corrupted[0] ^= 0x01
        k._sk_seed = bytes(corrupted)
        assert k._verify_seed_ok() is False

    def test_public_key_and_fingerprint_are_strings(self):
        k = HardenedKeyInfrastructure()
        assert isinstance(k.public_key, str)
        assert isinstance(k.fingerprint, str)
        assert len(k.fingerprint) == 16

    def test_fingerprint_is_deterministic(self):
        """Same SK.seed → same fingerprint."""
        k = HardenedKeyInfrastructure()
        fp1 = k.fingerprint
        fp2 = k.fingerprint
        assert fp1 == fp2

    def test_get_status_has_required_fields(self):
        k = HardenedKeyInfrastructure()
        status = k.get_status()
        for field in ("sign_count", "mlocked", "integrity_ok", "rate_per_minute",
                      "alert_count", "security_level", "rowhammer_hardened"):
            assert field in status

    def test_security_level_is_5(self):
        k = HardenedKeyInfrastructure()
        assert k.get_status()["security_level"] == 5

    def test_rowhammer_hardened_flag_is_true(self):
        k = HardenedKeyInfrastructure()
        assert k.get_status()["rowhammer_hardened"] is True

    def test_min_security_level_constant(self):
        assert MIN_SECURITY_LEVEL == 5


# ═══════════════════════════════════════════════════════════════════════════════
# ML-DSA TRUST REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

class TestMLDSATrustRegistry:

    def test_register_and_trust_plugin(self):
        reg = MLDSATrustRegistry()
        reg.register_plugin("shadow313-temporal", "pubkey-abc123")
        result = reg.is_trusted("shadow313-temporal", "pubkey-abc123")
        assert result["trusted"] is True

    def test_untrusted_plugin_rejected(self):
        reg = MLDSATrustRegistry()
        result = reg.is_trusted("unknown-plugin", "any-key")
        assert result["trusted"] is False

    def test_wrong_key_rejected(self):
        reg = MLDSATrustRegistry()
        reg.register_plugin("shadow313-temporal", "correct-key")
        result = reg.is_trusted("shadow313-temporal", "wrong-key")
        assert result["trusted"] is False

    def test_registry_integrity_verified(self):
        reg = MLDSATrustRegistry()
        reg.register_plugin("plugin-a", "key-a")
        assert reg.verify_registry_integrity() is True

    def test_tampered_registry_detected(self):
        """Simulate registry tampering — integrity check should fail."""
        reg = MLDSATrustRegistry()
        reg.register_plugin("plugin-a", "key-a")
        # Tamper with registry directly (bypassing sign)
        reg._registry["malicious-plugin"] = "evil-key"
        # Integrity check should fail (signature no longer matches)
        assert reg.verify_registry_integrity() is False

    def test_tampered_registry_returns_untrusted(self):
        reg = MLDSATrustRegistry()
        reg.register_plugin("plugin-a", "key-a")
        reg._registry["malicious-plugin"] = "evil-key"
        result = reg.is_trusted("plugin-a", "key-a")
        assert result["trusted"] is False
        assert "integrity" in result["reason"].lower()

    def test_hndl_protected_flag_in_result(self):
        reg = MLDSATrustRegistry()
        reg.register_plugin("plugin-a", "key-a")
        result = reg.is_trusted("plugin-a", "key-a")
        assert result.get("hndl_protected") is True

    def test_signature_algo_is_ml_dsa(self):
        reg = MLDSATrustRegistry()
        status = reg.get_status()
        assert "ML-DSA" in status["signature_algo"]
        assert "FIPS 204" in status["signature_algo"]

    def test_get_status_has_required_fields(self):
        reg = MLDSATrustRegistry()
        status = reg.get_status()
        for field in ("registry_size", "signature_algo", "hndl_protected",
                      "integrity_ok", "signed_at"):
            assert field in status


# ═══════════════════════════════════════════════════════════════════════════════
# QUANTUM RESISTANT IPFS
# ═══════════════════════════════════════════════════════════════════════════════

class TestQuantumResistantIPFS:

    def test_cid_starts_with_qm3(self):
        """SHA3-256 CIDs use 'Qm3' prefix to distinguish from SHA-256 CIDs."""
        ipfs = QuantumResistantIPFS()
        cid = ipfs.add("test content")
        assert cid.startswith("Qm3")

    def test_cid_is_deterministic(self):
        ipfs = QuantumResistantIPFS()
        cid1 = ipfs.add_without_store("same content")
        cid2 = ipfs.add_without_store("same content")
        assert cid1 == cid2

    def test_different_content_different_cid(self):
        ipfs = QuantumResistantIPFS()
        cid1 = ipfs.add("content A")
        cid2 = ipfs.add("content B")
        assert cid1 != cid2

    def test_content_retrievable(self):
        ipfs = QuantumResistantIPFS()
        cid = ipfs.add("hello world")
        assert ipfs.get(cid) == "hello world"

    def test_nonexistent_cid_returns_none(self):
        ipfs = QuantumResistantIPFS()
        assert ipfs.get("Qm3nonexistent") is None

    def test_cid_verification_passes_for_correct_content(self):
        ipfs = QuantumResistantIPFS()
        cid = ipfs.add("verify me")
        assert ipfs.verify_cid(cid, "verify me") is True

    def test_cid_verification_fails_for_wrong_content(self):
        ipfs = QuantumResistantIPFS()
        cid = ipfs.add("original content")
        assert ipfs.verify_cid(cid, "tampered content") is False

    def test_algorithm_is_sha3_256(self):
        ipfs = QuantumResistantIPFS()
        assert ipfs.get_algorithm() == "sha3-256"

    def test_is_quantum_resistant(self):
        ipfs = QuantumResistantIPFS()
        assert ipfs.is_quantum_resistant() is True

    def test_sha3_256_prefix_in_cid(self):
        """CID should contain SHA3-256 multihash prefix (0x16, 0x20)."""
        ipfs = QuantumResistantIPFS()
        cid = ipfs.add("test")
        # The CID hex should contain the multihash prefix
        assert "1620" in cid  # 0x16=sha3-256, 0x20=32 bytes

    def test_cid_differs_from_sha256_cid(self):
        """SHA3-256 CID uses 'Qm3' prefix — distinguishable from standard SHA-256 'Qm' CIDs."""
        content = "test content"
        ipfs = QuantumResistantIPFS()
        sha3_cid = ipfs.add_without_store(content)
        # Our SHA3-256 CIDs start with "Qm3" (third char is "3")
        assert sha3_cid.startswith("Qm3")
        # The third character distinguishes it from standard SHA-256 CIDs
        assert sha3_cid[2] == "3"
        # The CID contains the SHA3-256 multihash prefix bytes (0x16, 0x20)
        assert "1620" in sha3_cid


# ═══════════════════════════════════════════════════════════════════════════════
# HARDENED RECEIPT CREATOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestHardenedReceiptCreator:

    @pytest.fixture
    def creator(self):
        return HardenedReceiptCreator()

    def test_create_receipt_returns_hardened_receipt(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert isinstance(receipt, HardenedReceipt)

    def test_timestamp_ends_in_313(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert receipt.timestamp % 1000 == 313

    def test_ipfs_cid_starts_with_qm3(self, creator):
        """SHA3-256 CIDs — quantum-resistant."""
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert receipt.ipfs_cid.startswith("Qm3")

    def test_security_level_is_5(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert receipt.security_level == 5

    def test_rowhammer_hardened_flag(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert receipt.rowhammer_hardened is True

    def test_hndl_protected_flag(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert receipt.hndl_protected is True

    def test_counter_chain_present(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert len(receipt.counter_chain) == 16

    def test_counter_chain_changes_between_receipts(self, creator):
        r1 = creator.create_receipt({"id": 1}, bind_index=1)
        r2 = creator.create_receipt({"id": 2}, bind_index=2)
        assert r1.counter_chain != r2.counter_chain

    def test_verify_valid_receipt(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        result = creator.verify_receipt(receipt)
        assert result["valid"] is True

    def test_verify_multiple_receipts(self, creator):
        for i in range(1, 4):
            receipt = creator.create_receipt({"id": i}, bind_index=i)
            result = creator.verify_receipt(receipt)
            assert result["valid"] is True, f"Receipt {i} failed verification"

    def test_verify_detects_content_tampering(self, creator):
        receipt = creator.create_receipt({"severity": "LOW"}, bind_index=1)
        # Tamper with content after anchoring
        receipt.content["severity"] = "CRITICAL"
        result = creator.verify_receipt(receipt)
        # L3 IPFS check should fail — content changed after anchoring
        assert result["l3_ipfs"] is False
        assert result["valid"] is False

    def test_verify_detects_key_fingerprint_mismatch(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        # Tamper with key fingerprint
        receipt.key_fingerprint = "deadbeef00000000"
        result = creator.verify_receipt(receipt)
        assert result["l2c_fingerprint"] is False
        assert result["valid"] is False

    def test_verify_detects_timestamp_not_313(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        # Tamper with timestamp
        receipt.timestamp = receipt.timestamp - (receipt.timestamp % 1000) + 100
        result = creator.verify_receipt(receipt)
        assert result["l1_timestamp"] is False
        assert result["valid"] is False

    def test_receipt_to_dict_serializable(self, creator):
        import json
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        d = receipt.to_dict()
        json_str = json.dumps(d)
        assert len(json_str) > 100

    def test_parameter_set_is_level5(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert "256" in receipt.parameter_set or "Level 5" in receipt.parameter_set

    def test_cid_algorithm_is_sha3_256(self, creator):
        receipt = creator.create_receipt({"test": "data"}, bind_index=1)
        assert "sha3-256" in receipt.cid_algorithm


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY STATUS AND THREAT MODEL
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityStatus:

    def test_all_5_countermeasures_active(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        cm = status["countermeasures"]
        assert cm["fix1_rowhammer_sk_seed_integrity"] is True
        assert cm["fix1_hedged_mode"]                 is True
        assert cm["fix2_signing_counter_chain"]       is True
        assert cm["fix3_ml_dsa_trust_registry"]       is True
        assert cm["fix4_sha3_256_ipfs_cids"]          is True
        assert cm["fix5_level5_parameter_set"]        is True

    def test_threat_model_slashdsa_mitigated(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        assert "MITIGATED" in status["threat_model"]["slashdsa_rowhammer"]

    def test_threat_model_hndl_l2a_mitigated(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        assert "MITIGATED" in status["threat_model"]["hndl_l2a"]

    def test_threat_model_hndl_l3_mitigated(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        assert "MITIGATED" in status["threat_model"]["hndl_l3"]

    def test_threat_model_hndl_l4_mitigated(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        assert "MITIGATED" in status["threat_model"]["hndl_l4"]

    def test_remaining_gap_documented(self):
        """The key theft gap should be honestly documented."""
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        gap = status["threat_model"]["remaining_gap"]
        assert "key theft" in gap.lower() or "hsm" in gap.lower()

    def test_ipfs_quantum_safe(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        assert status["ipfs_quantum_safe"] is True

    def test_ipfs_algorithm_is_sha3_256(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        assert status["ipfs_algorithm"] == "sha3-256"

    def test_trust_registry_hndl_protected(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        assert status["trust_registry"]["hndl_protected"] is True

    def test_trust_registry_uses_ml_dsa(self):
        creator = HardenedReceiptCreator()
        status = creator.get_security_status()
        assert "ML-DSA" in status["trust_registry"]["signature_algo"]


# ═══════════════════════════════════════════════════════════════════════════════
# DEMO FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestDemoFunction:

    def test_demo_runs_without_error(self, capsys):
        demo_hardened_binding()
        captured = capsys.readouterr()
        assert "HARDENED 313-BIND" in captured.out

    def test_demo_shows_all_countermeasures_active(self, capsys):
        demo_hardened_binding()
        captured = capsys.readouterr()
        assert "SK.seed integrity" in captured.out
        assert "Hedged mode" in captured.out
        assert "ML-DSA trust reg" in captured.out
        assert "SHA3-256 IPFS" in captured.out

    def test_demo_shows_mitigated_threats(self, capsys):
        demo_hardened_binding()
        captured = capsys.readouterr()
        assert "MITIGATED" in captured.out

    def test_demo_shows_valid_receipts(self, capsys):
        demo_hardened_binding()
        captured = capsys.readouterr()
        assert "VALID" in captured.out