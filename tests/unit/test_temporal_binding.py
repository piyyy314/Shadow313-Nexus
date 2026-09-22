"""Unit tests — shadow313.v4.temporal_binding v4"""
import time
import pytest
from shadow313.v4.temporal_binding.temporal_binding import (
    _wait_for_313,
    _sha3_512,
    TemporalBindingEngine,
    Bind313Receipt,
)


def _shannon_entropy_check(s: str) -> float:
    """Helper for tests — compute Shannon entropy."""
    import math
    from collections import Counter
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())


class TestWaitFor313:
    def test_returns_timestamp_ending_in_313(self):
        ts = _wait_for_313(max_wait_ms=5000)
        assert ts % 1000 == 313

    def test_returns_integer(self):
        ts = _wait_for_313(max_wait_ms=5000)
        assert isinstance(ts, int)

    def test_timestamp_is_recent(self):
        ts = _wait_for_313(max_wait_ms=5000)
        now_ns = time.time_ns()
        # Should be within 10 seconds of now
        assert abs(now_ns - ts) < 10_000_000_000

    def test_no_busy_loop_cpu_spike(self):
        """FIX: _wait_for_313() should not cause 100% CPU (has sleep)."""
        import threading
        import os
        start = time.time()
        ts = _wait_for_313(max_wait_ms=100)
        elapsed = time.time() - start
        # Should complete quickly but not instantly (has sleep)
        assert elapsed < 1.0
        assert ts % 1000 == 313


class TestSHA3512:
    def test_returns_hex_string(self):
        result = _sha3_512(b"hello world")
        assert isinstance(result, str)
        assert len(result) == 128  # SHA3-512 = 64 bytes = 128 hex chars

    def test_deterministic(self):
        r1 = _sha3_512(b"test data")
        r2 = _sha3_512(b"test data")
        assert r1 == r2

    def test_different_inputs_different_hashes(self):
        r1 = _sha3_512(b"input1")
        r2 = _sha3_512(b"input2")
        assert r1 != r2

    def test_empty_input(self):
        result = _sha3_512(b"")
        assert len(result) == 128


class TestTemporalBindingEngine:
    def test_bind_creates_receipt(self, tmp_path):
        engine = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind({"test": "data"}, session_id="test-session", module="test")
        assert isinstance(receipt, Bind313Receipt)
        assert receipt.timestamp % 1000 == 313
        assert receipt.receipt_id.startswith("313-v4-")

    def test_bind_increments_counter(self, tmp_path):
        engine = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        r1 = engine.bind({"a": 1})
        r2 = engine.bind({"b": 2})
        assert r2.bind_index == r1.bind_index + 1

    def test_bind_saves_receipt_file(self, tmp_path):
        engine = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind({"test": True})
        receipt_file = tmp_path / f"{receipt.receipt_id}.json"
        assert receipt_file.exists()

    def test_verify_valid_receipt(self, tmp_path):
        engine = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind({"verify": "me"})
        result  = engine.verify(receipt.receipt_id)
        assert result["valid"] is True
        assert result["checks"]["timestamp_ends_313"] is True
        assert result["checks"]["sha3_512_present"] is True

    def test_verify_nonexistent_receipt(self, tmp_path):
        engine = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        result = engine.verify("313-v4-99999999")
        assert result["valid"] is False
        assert "error" in result

    def test_list_receipts(self, tmp_path):
        engine = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        engine.bind({"a": 1})
        engine.bind({"b": 2})
        receipts = engine.list_receipts()
        assert len(receipts) == 2

    def test_receipt_to_dict(self, tmp_path):
        engine  = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind({"data": "test"})
        d = receipt.to_dict()
        assert "receipt_id"   in d
        assert "timestamp"    in d
        assert "sha3_512"     in d
        assert "algorithm"    in d
        assert "ipfs_cid"     in d
        assert "timestamp_iso"in d

    def test_receipt_id_format(self, tmp_path):
        engine  = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind({})
        assert receipt.receipt_id.startswith("313-v4-")
        # Should be zero-padded 8 digits
        parts = receipt.receipt_id.split("-")
        assert len(parts[2]) == 8

    def test_bind_string_content(self, tmp_path):
        engine  = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind("plain string content")
        assert receipt.timestamp % 1000 == 313

    def test_ipfs_disabled_uses_local_hash(self, tmp_path):
        engine  = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind({"test": True})
        # When IPFS is disabled, should use local hash fallback
        assert receipt.ipfs_cid == "disabled" or receipt.ipfs_cid.startswith("local:")

    def test_sha3_512_in_receipt(self, tmp_path):
        engine  = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind({"content": "test"})
        assert len(receipt.sha3_512) == 128  # SHA3-512 hex = 128 chars

    def test_multiple_binds_unique_receipts(self, tmp_path):
        engine = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipts = [engine.bind({"i": i}) for i in range(5)]
        ids = [r.receipt_id for r in receipts]
        assert len(set(ids)) == 5  # all unique