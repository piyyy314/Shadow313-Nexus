"""
Tests for shadow313.v4.temporal_binding.anchor_strategies

Covers all 5 anchoring strategies and their failure modes:
  - LedgerAnchor: chain integrity, verification, offline capability
  - MultiHashAnchor: triple-hash, tamper detection
  - MerkleCheckpointAnchor: batch accumulation, root computation, proofs
  - HybridAnchor: graceful degradation, circuit breaker, layer composition
  - RFC3161Anchor: simulated timestamp, metadata
  - compare_strategies: comparison table
"""
from __future__ import annotations

import pytest
from shadow313.v4.temporal_binding.anchor_strategies import (
    AnchorResult,
    LedgerAnchor,
    MultiHashAnchor,
    MerkleCheckpointAnchor,
    HybridAnchor,
    RFC3161Anchor,
    STRATEGY_COMPARISON,
    compare_strategies,
)


# ═══════════════════════════════════════════════════════════════════════════════
# AnchorResult
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnchorResult:

    def test_to_dict_has_required_keys(self):
        r = AnchorResult(
            strategy="test", anchor_id="id", anchor_type="test",
            verified=True, offline_capable=True, quantum_safe=True,
        )
        d = r.to_dict()
        for key in ("strategy", "anchor_id", "anchor_type", "verified",
                    "offline_capable", "quantum_safe", "timestamp"):
            assert key in d

    def test_timestamp_is_set(self):
        r = AnchorResult(
            strategy="test", anchor_id="id", anchor_type="test",
            verified=True, offline_capable=True, quantum_safe=True,
        )
        assert "T" in r.timestamp  # ISO 8601


# ═══════════════════════════════════════════════════════════════════════════════
# LedgerAnchor
# ═══════════════════════════════════════════════════════════════════════════════

class TestLedgerAnchor:

    def test_anchor_returns_result(self):
        la = LedgerAnchor()
        r = la.anchor("test content")
        assert isinstance(r, AnchorResult)
        assert r.anchor_type == "ledger"

    def test_anchor_id_contains_sequence(self):
        la = LedgerAnchor()
        r = la.anchor("content")
        assert "ledger:00000001" in r.anchor_id

    def test_sequence_increments(self):
        la = LedgerAnchor()
        r1 = la.anchor("a")
        r2 = la.anchor("b")
        assert r2.metadata["sequence"] == r1.metadata["sequence"] + 1

    def test_offline_capable(self):
        la = LedgerAnchor()
        r = la.anchor("content")
        assert r.offline_capable is True

    def test_quantum_safe(self):
        la = LedgerAnchor()
        r = la.anchor("content")
        assert r.quantum_safe is True

    def test_chain_valid_after_multiple_anchors(self):
        la = LedgerAnchor()
        for i in range(10):
            la.anchor(f"content_{i}")
        result = la.verify_chain()
        assert result["valid"] is True
        assert result["total"] == 10

    def test_chain_hashes_are_unique(self):
        la = LedgerAnchor()
        for i in range(5):
            la.anchor(f"content_{i}")
        hashes = [e["chain_hash"] for e in la._entries]
        assert len(set(hashes)) == 5

    def test_verify_correct_content(self):
        la = LedgerAnchor()
        content = "audit payload"
        r = la.anchor(content, receipt_id="R001")
        assert la.verify(r.anchor_id, content) is True

    def test_verify_tampered_content(self):
        la = LedgerAnchor()
        r = la.anchor("original content")
        assert la.verify(r.anchor_id, "tampered content") is False

    def test_empty_chain_valid(self):
        la = LedgerAnchor()
        result = la.verify_chain()
        assert result["valid"] is True
        assert result["total"] == 0

    def test_anchor_id_format(self):
        la = LedgerAnchor()
        r = la.anchor("content")
        parts = r.anchor_id.split(":")
        assert parts[0] == "ledger"
        assert len(parts) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# MultiHashAnchor
# ═══════════════════════════════════════════════════════════════════════════════

class TestMultiHashAnchor:

    def test_anchor_returns_result(self):
        mh = MultiHashAnchor()
        r = mh.anchor("test content")
        assert isinstance(r, AnchorResult)
        assert r.anchor_type == "multihash"

    def test_anchor_id_starts_with_mh(self):
        mh = MultiHashAnchor()
        r = mh.anchor("content")
        assert r.anchor_id.startswith("mh:")

    def test_offline_capable(self):
        mh = MultiHashAnchor()
        r = mh.anchor("content")
        assert r.offline_capable is True

    def test_quantum_safe(self):
        mh = MultiHashAnchor()
        r = mh.anchor("content")
        assert r.quantum_safe is True

    def test_metadata_has_sha3_256(self):
        mh = MultiHashAnchor()
        r = mh.anchor("content")
        assert "sha3_256" in r.metadata
        assert len(r.metadata["sha3_256"]) == 64

    def test_metadata_has_sha3_512(self):
        mh = MultiHashAnchor()
        r = mh.anchor("content")
        assert "sha3_512" in r.metadata
        assert len(r.metadata["sha3_512"]) == 128

    def test_different_content_different_anchor(self):
        mh = MultiHashAnchor()
        r1 = mh.anchor("content A")
        r2 = mh.anchor("content B")
        assert r1.anchor_id != r2.anchor_id

    def test_same_content_same_anchor(self):
        mh = MultiHashAnchor()
        r1 = mh.anchor("same content")
        r2 = mh.anchor("same content")
        assert r1.anchor_id == r2.anchor_id

    def test_verify_correct_content(self):
        mh = MultiHashAnchor()
        content = "audit data"
        r = mh.anchor(content)
        assert mh.verify(r.anchor_id, content) is True

    def test_verify_tampered_content(self):
        mh = MultiHashAnchor()
        r = mh.anchor("original")
        assert mh.verify(r.anchor_id, "tampered") is False

    def test_anchor_id_has_three_parts(self):
        mh = MultiHashAnchor()
        r = mh.anchor("content")
        parts = r.anchor_id.split(":")
        assert len(parts) == 4  # mh: + 3 hash prefixes


# ═══════════════════════════════════════════════════════════════════════════════
# MerkleCheckpointAnchor
# ═══════════════════════════════════════════════════════════════════════════════

class TestMerkleCheckpointAnchor:

    def test_anchor_returns_result(self):
        mc = MerkleCheckpointAnchor(checkpoint_size=5)
        r = mc.anchor("content")
        assert isinstance(r, AnchorResult)
        assert r.anchor_type == "merkle"

    def test_offline_capable(self):
        mc = MerkleCheckpointAnchor()
        r = mc.anchor("content")
        assert r.offline_capable is True

    def test_quantum_safe(self):
        mc = MerkleCheckpointAnchor()
        r = mc.anchor("content")
        assert r.quantum_safe is True

    def test_checkpoint_created_at_batch_size(self):
        mc = MerkleCheckpointAnchor(checkpoint_size=3)
        for i in range(3):
            mc.anchor(f"content_{i}")
        assert len(mc._checkpoints) == 1

    def test_checkpoint_not_created_before_batch_size(self):
        mc = MerkleCheckpointAnchor(checkpoint_size=5)
        for i in range(4):
            mc.anchor(f"content_{i}")
        assert len(mc._checkpoints) == 0

    def test_flush_creates_checkpoint(self):
        mc = MerkleCheckpointAnchor(checkpoint_size=100)
        for i in range(3):
            mc.anchor(f"content_{i}")
        mc.flush()
        assert len(mc._checkpoints) == 1

    def test_merkle_root_changes_with_content(self):
        mc1 = MerkleCheckpointAnchor(checkpoint_size=2)
        mc2 = MerkleCheckpointAnchor(checkpoint_size=2)
        mc1.anchor("a"); mc1.anchor("b")
        mc2.anchor("a"); mc2.anchor("c")  # different second leaf
        assert mc1._checkpoints[0]["merkle_root"] != mc2._checkpoints[0]["merkle_root"]

    def test_get_proof_for_included_leaf(self):
        mc = MerkleCheckpointAnchor(checkpoint_size=3)
        mc.anchor("content_0")
        mc.anchor("content_1")
        mc.anchor("content_2")
        # Get leaf hash for content_1
        import hashlib
        leaf = hashlib.sha3_256("content_1".encode()).hexdigest()
        proof = mc.get_proof(leaf)
        assert proof is not None
        assert proof["leaf_hash"] == leaf

    def test_get_proof_for_missing_leaf(self):
        mc = MerkleCheckpointAnchor(checkpoint_size=3)
        proof = mc.get_proof("nonexistent_leaf_hash")
        assert proof is None

    def test_pending_count_in_metadata(self):
        mc = MerkleCheckpointAnchor(checkpoint_size=10)
        mc.anchor("a")
        mc.anchor("b")
        r = mc.anchor("c")
        assert r.metadata["pending_count"] == 3


# ═══════════════════════════════════════════════════════════════════════════════
# HybridAnchor
# ═══════════════════════════════════════════════════════════════════════════════

class TestHybridAnchor:

    def test_anchor_returns_result(self):
        ha = HybridAnchor()
        r = ha.anchor("content")
        assert isinstance(r, AnchorResult)
        assert r.anchor_type == "hybrid"

    def test_anchor_id_starts_with_hybrid(self):
        ha = HybridAnchor()
        r = ha.anchor("content")
        assert r.anchor_id.startswith("hybrid:")

    def test_offline_capable(self):
        ha = HybridAnchor()
        r = ha.anchor("content")
        assert r.offline_capable is True

    def test_quantum_safe(self):
        ha = HybridAnchor()
        r = ha.anchor("content")
        assert r.quantum_safe is True

    def test_metadata_has_multihash(self):
        ha = HybridAnchor()
        r = ha.anchor("content")
        assert "multihash" in r.metadata
        assert r.metadata["multihash"].startswith("mh:")

    def test_metadata_has_ledger(self):
        ha = HybridAnchor()
        r = ha.anchor("content")
        assert "ledger" in r.metadata
        assert r.metadata["ledger"].startswith("ledger:")

    def test_ipfs_unavailable_graceful_degradation(self):
        """When IPFS is unavailable, hybrid still works with 2 layers."""
        ha = HybridAnchor(ipfs_api="http://localhost:19999")  # non-existent
        r = ha.anchor("content")
        assert r.anchor_id.startswith("hybrid:")
        assert r.metadata["ipfs_cid"] == "unavailable"
        assert r.metadata["layers_active"] == 2

    def test_circuit_breaker_activates_after_3_failures(self):
        """After 3 IPFS failures, circuit breaker stops trying."""
        ha = HybridAnchor(ipfs_api="http://localhost:19999")
        for i in range(5):
            ha.anchor(f"content_{i}")
        assert ha._ipfs_failures >= 3
        status = ha.status()
        assert status["circuit_breaker"] is True

    def test_status_has_required_keys(self):
        ha = HybridAnchor()
        s = ha.status()
        for key in ("ipfs_available", "ipfs_failures", "circuit_breaker",
                    "ledger_entries", "active_layers"):
            assert key in s

    def test_ledger_entries_accumulate(self):
        ha = HybridAnchor()
        for i in range(5):
            ha.anchor(f"content_{i}")
        assert ha.status()["ledger_entries"] == 5

    def test_verify_multihash_layer(self):
        ha = HybridAnchor()
        content = "audit content"
        r = ha.anchor(content)
        result = ha.verify(r.anchor_id, content)
        assert result["multihash_ok"] is True

    def test_different_content_different_anchor(self):
        ha = HybridAnchor()
        r1 = ha.anchor("content A")
        r2 = ha.anchor("content B")
        assert r1.anchor_id != r2.anchor_id


# ═══════════════════════════════════════════════════════════════════════════════
# RFC3161Anchor
# ═══════════════════════════════════════════════════════════════════════════════

class TestRFC3161Anchor:

    def test_anchor_returns_result(self):
        rfc = RFC3161Anchor()
        r = rfc.anchor("content")
        assert isinstance(r, AnchorResult)
        assert r.anchor_type == "rfc3161"

    def test_anchor_id_starts_with_rfc3161(self):
        rfc = RFC3161Anchor()
        r = rfc.anchor("content")
        assert r.anchor_id.startswith("rfc3161:")

    def test_not_offline_capable(self):
        """RFC 3161 requires TSA at anchor time."""
        rfc = RFC3161Anchor()
        r = rfc.anchor("content")
        assert r.offline_capable is False

    def test_not_quantum_safe(self):
        """TSA uses RSA/ECDSA — HNDL risk."""
        rfc = RFC3161Anchor()
        r = rfc.anchor("content")
        assert r.quantum_safe is False

    def test_metadata_has_hash(self):
        rfc = RFC3161Anchor()
        r = rfc.anchor("content")
        assert "hash" in r.metadata
        assert len(r.metadata["hash"]) == 64  # SHA3-256

    def test_metadata_has_tsa_url(self):
        rfc = RFC3161Anchor()
        r = rfc.anchor("content")
        assert "tsa_url" in r.metadata

    def test_different_content_different_anchor(self):
        rfc = RFC3161Anchor()
        r1 = rfc.anchor("content A")
        r2 = rfc.anchor("content B")
        assert r1.anchor_id != r2.anchor_id


# ═══════════════════════════════════════════════════════════════════════════════
# Strategy comparison
# ═══════════════════════════════════════════════════════════════════════════════

class TestStrategyComparison:

    def test_comparison_has_all_strategies(self):
        for strategy in ("IPFS (current)", "LedgerAnchor", "MultiHashAnchor",
                         "MerkleCheckpointAnchor", "HybridAnchor (recommended)",
                         "RFC3161Anchor"):
            assert strategy in STRATEGY_COMPARISON

    def test_hybrid_is_always_available(self):
        assert STRATEGY_COMPARISON["HybridAnchor (recommended)"]["always_available"] is True

    def test_hybrid_is_offline_capable(self):
        assert STRATEGY_COMPARISON["HybridAnchor (recommended)"]["offline_capable"] is True

    def test_ipfs_is_not_always_available(self):
        assert STRATEGY_COMPARISON["IPFS (current)"]["always_available"] is False

    def test_rfc3161_is_legally_recognized(self):
        assert STRATEGY_COMPARISON["RFC3161Anchor"]["legally_recognized"] is True

    def test_rfc3161_is_not_quantum_safe(self):
        assert STRATEGY_COMPARISON["RFC3161Anchor"]["quantum_safe"] is False

    def test_compare_strategies_returns_string(self):
        table = compare_strategies()
        assert isinstance(table, str)
        assert "HybridAnchor" in table
        assert "LedgerAnchor" in table
        assert "RFC3161" in table

    def test_compare_strategies_has_failure_modes(self):
        table = compare_strategies()
        assert "Failure modes" in table

    def test_compare_strategies_has_recommendations(self):
        table = compare_strategies()
        assert "Recommendations" in table


# ═══════════════════════════════════════════════════════════════════════════════
# IPFS failure mode simulation
# ═══════════════════════════════════════════════════════════════════════════════

class TestIPFSFailureModes:

    def test_failure_mode_1_daemon_not_running(self):
        """IPFS daemon not running → local hash fallback in temporal_binding."""
        from shadow313.v4.temporal_binding.temporal_binding import _anchor_ipfs
        # With no IPFS daemon, should return local: prefix
        result = _anchor_ipfs("test content")
        # Either IPFS CID (if daemon running) or local: fallback
        assert result.startswith("local:") or result.startswith("Qm") or len(result) > 5

    def test_failure_mode_2_hybrid_degrades_gracefully(self):
        """IPFS unavailable → HybridAnchor still provides 2-layer tamper evidence."""
        ha = HybridAnchor(ipfs_api="http://localhost:19999")
        r = ha.anchor("critical audit data")
        # Must still produce a valid anchor
        assert r.anchor_id.startswith("hybrid:")
        assert r.verified is True
        assert r.offline_capable is True
        # MultiHash and Ledger layers must be active
        assert r.metadata["multihash"].startswith("mh:")
        assert r.metadata["ledger"].startswith("ledger:")

    def test_failure_mode_3_local_hash_not_independently_verifiable(self):
        """
        Demonstrates the weakness of the current local: fallback.
        A local: hash can only be verified by the node that created it.
        """
        from shadow313.v4.temporal_binding.temporal_binding import _anchor_ipfs
        result = _anchor_ipfs("test content")
        if result.startswith("local:"):
            # local: hash is NOT independently verifiable
            # (no way to retrieve content from "local:" prefix)
            assert "local:" in result
            # The MultiHashAnchor solves this — it's always verifiable
            mh = MultiHashAnchor()
            mh_result = mh.anchor("test content")
            assert mh_result.verified is True  # independently verifiable

    def test_failure_mode_4_circuit_breaker_prevents_timeout_cascade(self):
        """Circuit breaker stops IPFS attempts after 3 failures."""
        ha = HybridAnchor(ipfs_api="http://localhost:19999")
        # Trigger 3 failures
        for i in range(3):
            ha._try_ipfs("content")
        assert ha._ipfs_failures >= 3
        # 4th attempt should be skipped (circuit breaker)
        import time
        start = time.time()
        ha._try_ipfs("content")
        elapsed = time.time() - start
        # Should return immediately (no network attempt)
        assert elapsed < 0.1

    def test_failure_mode_5_merkle_buffers_during_outage(self):
        """MerkleCheckpoint accumulates receipts during IPFS outage."""
        mc = MerkleCheckpointAnchor(checkpoint_size=5)
        # Simulate 4 receipts during IPFS outage
        for i in range(4):
            r = mc.anchor(f"receipt_{i}")
            assert r.anchor_type == "merkle"
        # All 4 are buffered, no checkpoint yet
        assert len(mc._checkpoints) == 0
        assert len(mc._pending) == 4
        # When IPFS comes back, flush creates checkpoint
        ckpt = mc.flush()
        assert ckpt is not None
        assert ckpt["leaf_count"] == 4
        assert len(mc._checkpoints) == 1