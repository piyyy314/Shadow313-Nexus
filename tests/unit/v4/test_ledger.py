"""Unit tests — shadow313.v4.ledger.ledger_engine"""
import json
import pytest
from shadow313.v4.ledger.ledger_engine import (
    VectorClock,
    MerkleTree,
    LedgerEntry,
    EpochCheckpoint,
    LedgerSyncEngine,
)


class TestVectorClock:
    def test_tick_increments_own_node(self):
        vc = VectorClock("node-1", ["node-1", "node-2"])
        snapshot = vc.tick()
        assert snapshot["node-1"] == 1

    def test_tick_multiple_times(self):
        vc = VectorClock("node-1", ["node-1", "node-2"])
        vc.tick()
        vc.tick()
        snapshot = vc.tick()
        assert snapshot["node-1"] == 3

    def test_update_merges_clocks(self):
        vc = VectorClock("node-1", ["node-1", "node-2"])
        vc.update({"node-1": 0, "node-2": 5})
        snapshot = vc.snapshot()
        assert snapshot["node-2"] == 5

    def test_dominates_when_all_greater(self):
        vc = VectorClock("node-1", ["node-1", "node-2"])
        vc._clock = {"node-1": 5, "node-2": 5}
        other = {"node-1": 3, "node-2": 3}
        assert vc.dominates(other) is True

    def test_not_dominates_when_equal(self):
        vc = VectorClock("node-1", ["node-1", "node-2"])
        vc._clock = {"node-1": 3, "node-2": 3}
        other = {"node-1": 3, "node-2": 3}
        assert vc.dominates(other) is False

    def test_concurrent_when_neither_dominates(self):
        vc = VectorClock("node-1", ["node-1", "node-2"])
        vc._clock = {"node-1": 5, "node-2": 1}
        other = {"node-1": 1, "node-2": 5}
        assert vc.concurrent_with(other) is True

    def test_snapshot_returns_copy(self):
        vc = VectorClock("node-1", ["node-1"])
        s1 = vc.snapshot()
        vc.tick()
        s2 = vc.snapshot()
        assert s1["node-1"] != s2["node-1"]


class TestMerkleTree:
    def test_root_deterministic(self):
        entries = [b"entry1", b"entry2", b"entry3"]
        t1 = MerkleTree(entries)
        t2 = MerkleTree(entries)
        assert t1.root == t2.root

    def test_root_changes_with_different_entries(self):
        t1 = MerkleTree([b"entry1", b"entry2"])
        t2 = MerkleTree([b"entry1", b"entry3"])
        assert t1.root != t2.root

    def test_empty_tree_has_root(self):
        t = MerkleTree([])
        assert t.root != ""
        assert len(t.root) == 64  # SHA-256 hex

    def test_single_entry_tree(self):
        t = MerkleTree([b"single"])
        assert t.root != ""

    def test_proof_generated(self):
        entries = [b"e1", b"e2", b"e3", b"e4"]
        t = MerkleTree(entries)
        proof = t.proof(0)
        assert isinstance(proof, list)

    def test_proof_verification(self):
        entries = [b"entry1", b"entry2", b"entry3", b"entry4"]
        t = MerkleTree(entries)
        for i in range(len(entries)):
            proof    = t.proof(i)
            verified = t.verify(entries[i], i, proof)
            assert verified is True

    def test_wrong_data_fails_verification(self):
        entries = [b"entry1", b"entry2"]
        t = MerkleTree(entries)
        proof = t.proof(0)
        assert t.verify(b"wrong_data", 0, proof) is False

    def test_large_tree(self):
        entries = [f"entry_{i}".encode() for i in range(100)]
        t = MerkleTree(entries)
        assert t.root != ""
        # Verify a few entries
        for i in [0, 25, 50, 99]:
            proof = t.proof(i)
            assert t.verify(entries[i], i, proof) is True


class TestLedgerEntry:
    def _make_entry(self, seq: int = 1) -> LedgerEntry:
        return LedgerEntry(
            entry_id     = f"entry-{seq}",
            sequence     = seq,
            epoch        = 1,
            key          = "test_key",
            payload      = {"value": seq},
            payload_hash = "abc123",
            vector_clock = {"node-1": seq},
            node_id      = "node-1",
            timestamp_ms = 1000 + seq,
        )

    def test_to_bytes_deterministic(self):
        e = self._make_entry()
        b1 = e.to_bytes()
        b2 = e.to_bytes()
        assert b1 == b2

    def test_compute_hash_deterministic(self):
        e = self._make_entry()
        h1 = e.compute_hash()
        h2 = e.compute_hash()
        assert h1 == h2

    def test_different_entries_different_hashes(self):
        e1 = self._make_entry(1)
        e2 = self._make_entry(2)
        assert e1.compute_hash() != e2.compute_hash()

    def test_to_dict(self):
        e = self._make_entry()
        d = e.to_dict()
        assert d["entry_id"]   == "entry-1"
        assert d["sequence"]   == 1
        assert d["key"]        == "test_key"
        assert d["node_id"]    == "node-1"

    def test_hash_is_sha256_hex(self):
        e = self._make_entry()
        h = e.compute_hash()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestLedgerSyncEngine:
    def _make_engine(self, tmp_path) -> LedgerSyncEngine:
        return LedgerSyncEngine(
            node_id    = "test-node",
            peer_nodes = ["peer-1", "peer-2"],
            ledger_dir = str(tmp_path / "ledger"),
        )

    def test_append_entry(self, tmp_path):
        engine = self._make_engine(tmp_path)
        entry  = engine.append("test_key", {"value": 42})
        assert entry.sequence == 1
        assert entry.key      == "test_key"
        assert entry.node_id  == "test-node"

    def test_sequence_increments(self, tmp_path):
        engine = self._make_engine(tmp_path)
        e1 = engine.append("key1", {"v": 1})
        e2 = engine.append("key2", {"v": 2})
        e3 = engine.append("key3", {"v": 3})
        assert e1.sequence == 1
        assert e2.sequence == 2
        assert e3.sequence == 3

    def test_get_entry_by_sequence(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.append("key1", {"v": 1})
        engine.append("key2", {"v": 2})
        entry = engine.get_entry(1)
        assert entry is not None
        assert entry.key == "key1"

    def test_get_nonexistent_entry(self, tmp_path):
        engine = self._make_engine(tmp_path)
        assert engine.get_entry(999) is None

    def test_query_by_key(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.append("key_a", {"v": 1})
        engine.append("key_b", {"v": 2})
        engine.append("key_a", {"v": 3})
        results = engine.query("key_a")
        assert len(results) == 2
        assert all(e.key == "key_a" for e in results)

    def test_epoch_close_creates_checkpoint(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.append("key1", {"v": 1})
        engine.append("key2", {"v": 2})
        cp = engine.force_epoch_close()
        assert cp is not None
        assert cp.merkle_root != ""
        assert cp.entry_count == 2

    def test_merkle_inclusion_verification(self, tmp_path):
        engine = self._make_engine(tmp_path)
        entry  = engine.append("key1", {"v": 1})
        engine.force_epoch_close()
        result = engine.verify_merkle_inclusion(entry)
        assert result["verified"] is True
        assert result["roots_match"] is True

    def test_conflict_resolution_lww(self, tmp_path):
        engine = self._make_engine(tmp_path)
        e1 = LedgerEntry(
            entry_id="e1", sequence=1, epoch=1, key="k",
            payload={"v":1}, payload_hash="h1",
            vector_clock={"node-1":1}, node_id="node-1", timestamp_ms=1000,
        )
        e2 = LedgerEntry(
            entry_id="e2", sequence=2, epoch=1, key="k",
            payload={"v":2}, payload_hash="h2",
            vector_clock={"node-1":2}, node_id="node-2", timestamp_ms=2000,
        )
        winner = engine.resolve_conflict(e1, e2)
        assert winner.entry_id == "e2"  # Higher timestamp wins

    def test_conflict_resolution_vector_clock(self, tmp_path):
        engine = self._make_engine(tmp_path)
        e1 = LedgerEntry(
            entry_id="e1", sequence=1, epoch=1, key="k",
            payload={"v":1}, payload_hash="h1",
            vector_clock={"node-1":5, "node-2":5}, node_id="node-1", timestamp_ms=1000,
        )
        e2 = LedgerEntry(
            entry_id="e2", sequence=2, epoch=1, key="k",
            payload={"v":2}, payload_hash="h2",
            vector_clock={"node-1":3, "node-2":3}, node_id="node-2", timestamp_ms=1000,
        )
        winner = engine.resolve_conflict(e1, e2)
        assert winner.entry_id == "e1"  # e1 dominates e2

    def test_conflict_resolution_node_id_tiebreak(self, tmp_path):
        engine = self._make_engine(tmp_path)
        e1 = LedgerEntry(
            entry_id="e1", sequence=1, epoch=1, key="k",
            payload={"v":1}, payload_hash="h1",
            vector_clock={"node-1":1, "node-2":1}, node_id="aaa-node", timestamp_ms=1000,
        )
        e2 = LedgerEntry(
            entry_id="e2", sequence=2, epoch=1, key="k",
            payload={"v":2}, payload_hash="h2",
            vector_clock={"node-1":1, "node-2":1}, node_id="zzz-node", timestamp_ms=1000,
        )
        winner = engine.resolve_conflict(e1, e2)
        assert winner.node_id == "aaa-node"  # Lowest lexicographic node_id

    def test_diagnose(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.append("key1", {"v": 1})
        diag = engine.diagnose()
        assert diag["node_id"]      == "test-node"
        assert diag["total_entries"]== 1
        assert "current_epoch"      in diag

    def test_resync_within_limit(self, tmp_path):
        engine = self._make_engine(tmp_path)
        for i in range(5):
            engine.append(f"key_{i}", {"v": i})
        result = engine.resync(from_epoch=1, source_entries=[])
        assert result["status"] == "OK"

    def test_resync_exceeds_limit_manual_gate(self, tmp_path):
        engine = self._make_engine(tmp_path)
        # Simulate large divergence
        engine._current_epoch = 20
        result = engine.resync(from_epoch=1, source_entries=[])
        assert result["status"] == "MANUAL_GATE"

    def test_snapshot_restore_validation(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.append("key1", {"v": 1})
        # Valid: snapshot_max_seq <= lowest_uncommitted
        assert engine.validate_snapshot_restore(0) is True

    def test_snapshot_restore_conflict_raises(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.append("key1", {"v": 1})
        # Invalid: snapshot_max_seq > lowest_uncommitted
        with pytest.raises(ValueError, match="SNAPSHOT_SEQUENCE_CONFLICT"):
            engine.validate_snapshot_restore(999)

    def test_freeze_blocks_writes(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.freeze(duration_sec=1)
        with pytest.raises(RuntimeError, match="frozen"):
            engine.append("key1", {"v": 1})
        engine.unfreeze()

    def test_unfreeze_allows_writes(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.freeze(duration_sec=100)
        engine.unfreeze()
        entry = engine.append("key1", {"v": 1})
        assert entry is not None

    def test_stats(self, tmp_path):
        engine = self._make_engine(tmp_path)
        engine.append("key1", {"v": 1})
        stats = engine.stats()
        assert stats["node_id"]       == "test-node"
        assert stats["total_entries"] == 1
        assert stats["total_writes"]  == 1
        assert stats["quorum_size"]   == 2  # (3 nodes) // 2 + 1

    def test_health_check(self, tmp_path):
        engine = self._make_engine(tmp_path)
        health = engine.health_check()
        assert health["status"] == "healthy"
        assert "epoch" in health
        assert "quorum" in health

    def test_entry_hash_chain(self, tmp_path):
        """Verify that entries form a hash chain (prev_hash links)."""
        engine = self._make_engine(tmp_path)
        e1 = engine.append("key1", {"v": 1})
        e2 = engine.append("key2", {"v": 2})
        assert e2.prev_hash == e1.compute_hash()

    def test_payload_hash_computed(self, tmp_path):
        engine = self._make_engine(tmp_path)
        entry  = engine.append("key1", {"value": "test"})
        assert entry.payload_hash != ""
        assert len(entry.payload_hash) == 64  # SHA-256 hex

    def test_vector_clock_in_entry(self, tmp_path):
        engine = self._make_engine(tmp_path)
        entry  = engine.append("key1", {"v": 1})
        assert "test-node" in entry.vector_clock
        assert entry.vector_clock["test-node"] >= 1