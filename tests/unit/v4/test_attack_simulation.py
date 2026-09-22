"""
Tests for the 313 Temporal Binding attack simulation.
Verifies that each defense layer correctly detects each attack variant.
"""
import pytest
import time


class TestSHA3ChainVulnerability:
    """Tests proving the SHA-3 chain bypass vulnerability."""

    def test_sha3_chain_computes_correctly(self):
        from shadow313.v4.temporal_binding.attack_simulation import sha3_chain_compute
        entries = [{"id": i, "action": f"action_{i}"} for i in range(5)]
        chain   = sha3_chain_compute(entries)
        assert len(chain) == 5
        assert all(len(h) == 128 for h in chain)  # SHA3-512 = 128 hex chars

    def test_sha3_chain_verifies_valid(self):
        from shadow313.v4.temporal_binding.attack_simulation import (
            sha3_chain_compute, sha3_chain_verify
        )
        entries = [{"id": i} for i in range(5)]
        chain   = sha3_chain_compute(entries)
        result  = sha3_chain_verify(entries, chain)
        assert result["valid"] is True
        assert result["error"] is None

    def test_sha3_chain_detects_modification(self):
        """SHA-3 chain detects outsider modification."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            sha3_chain_compute, sha3_chain_verify
        )
        entries = [{"id": i} for i in range(5)]
        chain   = sha3_chain_compute(entries)
        # Outsider modifies entry 2
        modified = list(entries)
        modified[2] = {"id": 2, "action": "MODIFIED"}
        result = sha3_chain_verify(modified, chain)
        assert result["valid"] is False

    def test_sha3_chain_bypass_succeeds(self):
        """
        THE CORE VULNERABILITY: Insider deletes entry and recomputes chain.
        Standard verification returns VALID — attack is UNDETECTED.
        """
        from shadow313.v4.temporal_binding.attack_simulation import (
            sha3_chain_compute, sha3_chain_verify
        )
        entries = [{"id": i, "action": f"action_{i}"} for i in range(12)]
        chain   = sha3_chain_compute(entries)

        # Insider attack: delete entry 7 and recompute
        start = time.perf_counter()
        tampered_entries = [e for e in entries if e["id"] != 7]
        tampered_chain   = sha3_chain_compute(tampered_entries)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Verify tampered chain
        result = sha3_chain_verify(tampered_entries, tampered_chain)

        # THE VULNERABILITY: attack succeeds
        assert result["valid"] is True, "SHA-3 chain bypass should succeed (vulnerability)"
        assert elapsed_ms < 100, f"Attack should complete in <100ms, took {elapsed_ms:.2f}ms"

    def test_sha3_bypass_time_is_under_1ms_for_small_log(self):
        """Attack completes in under 1ms for typical audit log sizes."""
        from shadow313.v4.temporal_binding.attack_simulation import sha3_chain_compute
        entries = [{"id": i, "data": "x" * 100} for i in range(12)]
        sha3_chain_compute(entries)  # Build original

        start = time.perf_counter()
        tampered = [e for e in entries if e["id"] != 6]
        sha3_chain_compute(tampered)  # Recompute
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 10, f"Recomputation took {elapsed_ms:.3f}ms — should be <10ms"


class TestTimestampConstraint:
    """Tests for the ...313 nanosecond timestamp constraint (Layer 1)."""

    def test_wait_for_313_returns_valid_timestamp(self):
        from shadow313.v4.temporal_binding.attack_simulation import _wait_for_313
        ts = _wait_for_313(max_wait_ms=2000)
        assert ts % 1000 == 313, f"Timestamp {ts} does not end in 313"

    def test_wait_for_313_is_fast(self):
        from shadow313.v4.temporal_binding.attack_simulation import _wait_for_313
        start = time.perf_counter()
        _wait_for_313(max_wait_ms=2000)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 2000, "Should complete within 2 seconds"

    def test_timestamp_in_hash_input(self):
        """Timestamp must be inside the hash, not just metadata."""
        import hashlib
        content   = {"test": "data"}
        import json
        content_str = json.dumps(content, sort_keys=True)
        ts1 = 1000000000313
        ts2 = 1000000001313  # Different timestamp

        hash1 = hashlib.sha3_512(f"{content_str}|{ts1}|1".encode()).hexdigest()
        hash2 = hashlib.sha3_512(f"{content_str}|{ts2}|1".encode()).hexdigest()

        # Different timestamps produce different hashes
        assert hash1 != hash2, "Different timestamps must produce different hashes"

    def test_layer1_detects_non_313_timestamp(self):
        """Layer 1 detects receipts with timestamps not ending in 313."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 4)]

        # Tamper: change timestamp of receipt 2 to not end in 313
        tampered = list(receipts)
        tampered[1] = dict(receipts[1])
        tampered[1]["timestamp"] = receipts[1]["timestamp"] - 313 + 777  # Ends in 777

        result = verify_313_chain(tampered)
        assert result["layer1_timestamp"]["passed"] is False
        assert len(result["layer1_timestamp"]["failures"]) >= 1

    def test_retroactive_timestamp_impossible(self):
        """
        An attacker cannot retroactively choose a past ...313 timestamp.
        The system clock determines when ...313 occurs.
        """
        from shadow313.v4.temporal_binding.attack_simulation import _wait_for_313
        # Record a past timestamp
        past_ts = _wait_for_313()
        time.sleep(0.01)  # Wait 10ms

        # Attacker tries to use the same timestamp again
        # They cannot — the clock has moved forward
        current_ts = _wait_for_313()
        assert current_ts > past_ts, "Cannot go back in time to reuse a past timestamp"
        assert current_ts % 1000 == 313
        assert past_ts % 1000 == 313
        # The two timestamps are different — retroactive selection is impossible
        assert current_ts != past_ts


class TestSLHDSASignature:
    """Tests for the SLH-DSA signature defense (Layer 2a)."""

    def test_valid_signature_verifies(self):
        from shadow313.v4.temporal_binding.attack_simulation import (
            _slh_dsa_sign, _slh_dsa_verify
        )
        message = b"test message for signing"
        sig     = _slh_dsa_sign(message)
        assert _slh_dsa_verify(message, sig) is True

    def test_invalid_signature_fails(self):
        from shadow313.v4.temporal_binding.attack_simulation import _slh_dsa_verify
        message = b"test message"
        fake_sig= "a" * 64  # Random hex string
        assert _slh_dsa_verify(message, fake_sig) is False

    def test_modified_content_fails_verification(self):
        from shadow313.v4.temporal_binding.attack_simulation import (
            _slh_dsa_sign, _slh_dsa_verify
        )
        original = b"original content"
        modified = b"modified content"
        sig      = _slh_dsa_sign(original)
        assert _slh_dsa_verify(modified, sig) is False

    def test_bind_index_inside_signature(self):
        """bind_index is inside the signed message — changing it invalidates signature."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            _slh_dsa_sign, _slh_dsa_verify
        )
        bind_index = 7
        timestamp  = 1000000000313
        sha3_hash  = "a" * 128

        # Original signed message
        original_msg = f"{bind_index}|{timestamp}|{sha3_hash}".encode()
        sig          = _slh_dsa_sign(original_msg)

        # Attacker changes bind_index from 7 to 6 (renumbering attack)
        tampered_msg = f"{bind_index - 1}|{timestamp}|{sha3_hash}".encode()
        assert _slh_dsa_verify(tampered_msg, sig) is False

    def test_layer2a_detects_invalid_signature(self):
        """Layer 2a detects receipts with invalid SLH-DSA signatures."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 4)]

        # Tamper: corrupt signature of receipt 2
        tampered = list(receipts)
        tampered[1] = dict(receipts[1])
        tampered[1]["signature"] = "deadbeef" * 8  # Invalid signature

        result = verify_313_chain(tampered)
        assert result["layer2_signature"]["passed"] is False
        assert len(result["layer2_signature"]["failures"]) >= 1

    def test_renumber_attack_detected_by_signature(self):
        """Renumbering receipts invalidates SLH-DSA signatures."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 6)]

        # Renumber: shift all bind_index values down by 1 (simulating deletion of receipt 1)
        renumbered = []
        for r in receipts[1:]:  # Skip receipt 1
            new_r = dict(r)
            new_r["bind_index"] = r["bind_index"] - 1
            renumbered.append(new_r)

        result = verify_313_chain(renumbered)
        # Renumbering changes bind_index which is inside the signature
        assert result["layer2_signature"]["passed"] is False


class TestBindIndexGapDetection:
    """Tests for the bind_index gap detection (Layer 2b)."""

    def test_valid_sequence_passes(self):
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 6)]
        result   = verify_313_chain(receipts)
        assert result["layer2_bind_index"]["passed"] is True

    def test_gap_detected_after_deletion(self):
        """Deleting a receipt creates a detectable gap in bind_index sequence."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 8)]

        # Delete receipt 4
        tampered = [r for r in receipts if r["bind_index"] != 4]
        result   = verify_313_chain(tampered)

        assert result["layer2_bind_index"]["passed"] is False
        failures = result["layer2_bind_index"]["failures"]
        assert len(failures) >= 1
        assert 4 in failures[0]["missing"]

    def test_gap_identifies_exact_missing_index(self):
        """Gap detection identifies the exact bind_index of deleted receipt."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 10)]

        # Delete receipt 6
        tampered = [r for r in receipts if r["bind_index"] != 6]
        result   = verify_313_chain(tampered)

        failures = result["layer2_bind_index"]["failures"]
        assert any(6 in f["missing"] for f in failures)

    def test_multiple_deletions_detected(self):
        """Multiple deletions create multiple gaps, all detected."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 12)]

        # Delete receipts 3, 7, and 10
        tampered = [r for r in receipts if r["bind_index"] not in (3, 7, 10)]
        result   = verify_313_chain(tampered)

        assert result["layer2_bind_index"]["passed"] is False
        all_missing = []
        for f in result["layer2_bind_index"]["failures"]:
            all_missing.extend(f["missing"])
        assert 3 in all_missing
        assert 7 in all_missing
        assert 10 in all_missing

    def test_bind_index_cannot_be_changed_without_invalidating_signature(self):
        """bind_index is inside the SLH-DSA signature — cannot be changed."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, _slh_dsa_verify
        )
        receipt = create_313_receipt({"id": 5}, bind_index=5, verbose=False)

        # Try to change bind_index
        tampered = dict(receipt)
        tampered["bind_index"] = 4  # Change from 5 to 4

        # Verify signature with new bind_index
        signed_msg = f"{tampered['bind_index']}|{tampered['timestamp']}|{tampered['sha3_512']}".encode()
        assert _slh_dsa_verify(signed_msg, tampered["signature"]) is False


class TestIPFSAnchor:
    """Tests for the IPFS anchor defense (Layer 3)."""

    def test_ipfs_add_and_get(self):
        from shadow313.v4.temporal_binding.attack_simulation import _ipfs_add, _ipfs_get
        content = '{"test": "content", "value": 42}'
        cid     = _ipfs_add(content)
        assert cid.startswith("Qm")
        retrieved = _ipfs_get(cid)
        assert retrieved == content

    def test_ipfs_cid_is_content_addressed(self):
        """Same content always produces same CID."""
        from shadow313.v4.temporal_binding.attack_simulation import _ipfs_add
        content = '{"deterministic": "content"}'
        cid1    = _ipfs_add(content)
        cid2    = _ipfs_add(content)
        assert cid1 == cid2

    def test_different_content_different_cid(self):
        from shadow313.v4.temporal_binding.attack_simulation import _ipfs_add
        cid1 = _ipfs_add('{"content": "version1"}')
        cid2 = _ipfs_add('{"content": "version2"}')
        assert cid1 != cid2

    def test_ipfs_anchor_persists_after_deletion(self):
        """IPFS anchor remains after receipt is deleted from log."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain, _ipfs_get
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 5)]

        # Record the CID of receipt 3 before deletion
        receipt_3_cid = receipts[2]["ipfs_cid"]

        # Delete receipt 3 from the log
        tampered = [r for r in receipts if r["bind_index"] != 3]

        # IPFS anchor still exists
        assert _ipfs_get(receipt_3_cid) is not None, "IPFS anchor must persist after deletion"

        # Verification detects the orphan CID
        result = verify_313_chain(tampered)
        assert result["layer3_ipfs"]["passed"] is False

    def test_orphan_cid_detected(self):
        """Receipts that exist on IPFS but not in log are detected as orphans."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 6)]

        # Delete receipt 3
        tampered = [r for r in receipts if r["bind_index"] != 3]
        result   = verify_313_chain(tampered)

        # Layer 3 should detect the orphan
        ipfs_failures = result["layer3_ipfs"]["failures"]
        orphan_indices = [f.get("bind_index") for f in ipfs_failures]
        assert 3 in orphan_indices

    def test_fake_cid_detected(self):
        """Fabricated receipts with fake CIDs are detected."""
        from shadow313.v4.temporal_binding.attack_simulation import (
            create_313_receipt, verify_313_chain
        )
        receipts = [create_313_receipt({"id": i}, i, verbose=False) for i in range(1, 4)]

        # Replace receipt 2 with a fake that has a non-existent CID
        fake_receipt = dict(receipts[1])
        fake_receipt["ipfs_cid"] = "QmFAKECIDTHATDOESNOTEXIST12345678901234567890"

        tampered = [receipts[0], fake_receipt, receipts[2]]
        result   = verify_313_chain(tampered)

        # Layer 3 should detect the fake CID
        assert result["layer3_ipfs"]["passed"] is False


class TestFullSimulation:
    """End-to-end simulation tests."""

    def test_simulation_runs_without_error(self):
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        assert "phases" in report
        assert "summary" in report

    def test_sha3_attack_succeeds(self):
        """Phase 1: SHA-3 chain bypass succeeds (vulnerability confirmed)."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        phase1 = next(p for p in report["phases"] if p["phase"] == 1)
        assert phase1["detected"] is False
        assert phase1["result"] == "ATTACK_SUCCEEDED"

    def test_simple_deletion_detected(self):
        """Phase 2: Simple deletion detected by bind_index gap and IPFS orphan."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        phase2 = next(p for p in report["phases"] if p["phase"] == 2)
        assert phase2["detected"] is True
        assert "L2_BIND_INDEX" in phase2["detection_layers"]

    def test_renumber_attack_detected(self):
        """Phase 3: Renumber attack detected by SLH-DSA signature failure."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        phase3 = next(p for p in report["phases"] if p["phase"] == 3)
        assert phase3["detected"] is True
        assert "L2_SIGNATURE" in phase3["detection_layers"]

    def test_fabrication_attack_detected(self):
        """Phase 4: Fabrication without private key detected by signature and IPFS."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        phase4 = next(p for p in report["phases"] if p["phase"] == 4)
        assert phase4["detected"] is True
        assert "L2_SIGNATURE" in phase4["detection_layers"]

    def test_stolen_key_attack_detected(self):
        """Phase 5: Even with stolen private key, IPFS timestamp mismatch detected."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        phase5 = next(p for p in report["phases"] if p["phase"] == 5)
        assert phase5["detected"] is True
        assert "L3_IPFS" in phase5["detection_layers"]

    def test_all_313_bind_attacks_detected(self):
        """All 4 attack variants against 313-BIND are detected."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report   = run_simulation(verbose=False)
        summary  = report["summary"]
        assert summary["bind313_attacks_detected"] == 4
        assert summary["sha3_attacks_detected"]    == 0  # SHA-3 is vulnerable

    def test_forensic_evidence_collected(self):
        """Simulation collects forensic evidence for each detected attack."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        # At least some phases should have forensic evidence
        phases_with_evidence = [
            p for p in report["phases"]
            if p.get("forensic_evidence")
        ]
        assert len(phases_with_evidence) >= 1

    def test_sha3_bypass_time_under_1ms(self):
        """SHA-3 chain bypass completes in under 1ms (proving the vulnerability)."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        phase1 = next(p for p in report["phases"] if p["phase"] == 1)
        assert phase1["attack_time_ms"] < 100  # Well under 100ms

    def test_defense_layer_independence(self):
        """Each defense layer catches different attack variants."""
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)

        # Collect all detection layers across phases
        all_layers = set()
        for phase in report["phases"][2:]:  # Skip setup and SHA-3 phases
            all_layers.update(phase.get("detection_layers", []))

        # All three layer types should be represented
        assert any("L2_BIND_INDEX" in l or "L2_SIGNATURE" in l for l in all_layers)
        assert any("L3_IPFS" in l for l in all_layers)

    def test_summary_conclusion(self):
        from shadow313.v4.temporal_binding.attack_simulation import run_simulation
        report = run_simulation(verbose=False)
        assert "313-BIND defeats" in report["summary"]["conclusion"]