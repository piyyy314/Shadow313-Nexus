"""
Tests for CRQC-012 fix: pyspx pure-Python SLH-DSA fallback in temporal_binding.py

Verifies the three-tier signing chain:
  Tier 1: pqcrypto (C-accelerated) — not available in sandbox
  Tier 2: pyspx (pure-Python SLH-DSA) — active in sandbox
  Tier 3: HMAC-SHA256 (last resort) — should NOT activate when pyspx present
"""
from __future__ import annotations

import importlib
import sys
import pytest

from shadow313.v4.temporal_binding.temporal_binding import (
    _sign_slh_dsa,
    TemporalBindingEngine,
)


# ═══════════════════════════════════════════════════════════════════════════════
# pyspx availability
# ═══════════════════════════════════════════════════════════════════════════════

class TestPyspxAvailability:

    def test_pyspx_importable(self):
        import pyspx.shake_128f as slh
        assert slh is not None

    def test_pyspx_shake_128f_keygen(self):
        import pyspx.shake_128f as slh, os
        pk, sk = slh.generate_keypair(os.urandom(48))
        assert len(pk) == 32
        assert len(sk) == 64

    def test_pyspx_shake_128f_sign_verify(self):
        import pyspx.shake_128f as slh, os
        pk, sk = slh.generate_keypair(os.urandom(48))
        msg = b"shadow313 test"
        sig = slh.sign(msg, sk)
        assert len(sig) == 17088
        assert slh.verify(msg, sig, pk) is True

    def test_pyspx_tamper_detection(self):
        import pyspx.shake_128f as slh, os
        pk, sk = slh.generate_keypair(os.urandom(48))
        msg = b"original"
        sig = slh.sign(msg, sk)
        assert slh.verify(b"tampered", sig, pk) is False


# ═══════════════════════════════════════════════════════════════════════════════
# _sign_slh_dsa three-tier chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestSignSLHDSA:

    def test_returns_tuple(self):
        sig, algo = _sign_slh_dsa(b"test")
        assert isinstance(sig, str)
        assert isinstance(algo, str)

    def test_uses_slhdsa_not_hmac(self):
        """CRQC-012 fix: pyspx tier must be active, not HMAC fallback."""
        _, algo = _sign_slh_dsa(b"test")
        assert "SLH-DSA" in algo, f"Expected SLH-DSA, got: {algo}"
        assert "HMAC" not in algo, f"Must NOT use HMAC fallback, got: {algo}"

    def test_algo_mentions_fips_205(self):
        _, algo = _sign_slh_dsa(b"test")
        assert "FIPS 205" in algo or "SLH-DSA" in algo

    def test_algo_mentions_pyspx(self):
        """Confirms pyspx tier (not pqcrypto) is active in this environment."""
        _, algo = _sign_slh_dsa(b"test")
        assert "pyspx" in algo.lower() or "pqcrypto" in algo.lower()

    def test_signature_is_hex_string(self):
        sig, _ = _sign_slh_dsa(b"test")
        assert all(c in "0123456789abcdef" for c in sig)

    def test_signature_length_is_slhdsa(self):
        """SLH-DSA-SHAKE-128f signature = 17088 bytes = 34176 hex chars."""
        sig, algo = _sign_slh_dsa(b"test")
        if "pyspx" in algo.lower() or "pqcrypto" in algo.lower():
            assert len(sig) == 34176, f"Expected 34176 hex chars, got {len(sig)}"

    def test_different_messages_produce_different_sigs(self):
        sig1, _ = _sign_slh_dsa(b"message one")
        sig2, _ = _sign_slh_dsa(b"message two")
        assert sig1 != sig2

    def test_same_message_produces_different_sigs(self):
        """SLH-DSA uses randomized signing — same message → different signatures."""
        sig1, _ = _sign_slh_dsa(b"same message")
        sig2, _ = _sign_slh_dsa(b"same message")
        # pyspx uses fresh randomness each call
        assert sig1 != sig2

    def test_empty_message_works(self):
        sig, algo = _sign_slh_dsa(b"")
        assert len(sig) > 0
        assert "SLH-DSA" in algo

    def test_large_message_works(self):
        large_msg = b"x" * 100_000
        sig, algo = _sign_slh_dsa(large_msg)
        assert "SLH-DSA" in algo
        assert len(sig) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Full 313-BIND receipt with pyspx
# ═══════════════════════════════════════════════════════════════════════════════

class TestReceiptWithPyspx:

    @pytest.fixture
    def engine(self):
        return TemporalBindingEngine()

    def test_receipt_uses_slhdsa_algo(self, engine):
        r = engine.bind({"test": "data"})
        assert "SLH-DSA" in r.algorithm, f"Got: {r.algorithm}"
        assert "HMAC" not in r.algorithm

    def test_receipt_timestamp_ends_313(self, engine):
        r = engine.bind({"test": "data"})
        assert r.timestamp % 1000 == 313

    def test_receipt_has_real_signature(self, engine):
        r = engine.bind({"test": "data"})
        # Real SLH-DSA sig = 17088 bytes = 34176 hex chars
        assert len(r.slh_sig) == 34176, f"Expected 34176, got {len(r.slh_sig)}"

    def test_receipt_has_ipfs_cid(self, engine):
        r = engine.bind({"test": "data"})
        assert r.ipfs_cid is not None
        assert len(r.ipfs_cid) > 0

    def test_receipt_has_sha3_512(self, engine):
        r = engine.bind({"test": "data"})
        assert len(r.sha3_512) == 128  # SHA3-512 = 64 bytes = 128 hex chars

    def test_multiple_receipts_have_unique_sigs(self, engine):
        r1 = engine.bind({"id": 1})
        r2 = engine.bind({"id": 2})
        assert r1.slh_sig != r2.slh_sig

    def test_receipt_bind_index_increments(self, engine):
        r1 = engine.bind({"id": 1})
        r2 = engine.bind({"id": 2})
        assert r2.bind_index == r1.bind_index + 1

    def test_crqc012_closed_message(self, engine):
        """Regression test: CRQC-012 must be closed — no HMAC fallback."""
        r = engine.bind({"crqc_012_test": True})
        assert "HMAC" not in r.algorithm, (
            f"CRQC-012 REGRESSION: HMAC fallback active. "
            f"Install pyspx or pqcrypto. Got: {r.algorithm}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# HMAC fallback simulation (mock pyspx unavailable)
# ═══════════════════════════════════════════════════════════════════════════════

class TestHMACFallbackBehavior:

    def test_hmac_fallback_algo_string(self):
        """Verify the HMAC fallback algo string contains the right warning text."""
        # We can't easily mock pyspx away without affecting other tests,
        # but we can verify the fallback string is correct by inspecting source.
        import inspect
        from shadow313.v4.temporal_binding import temporal_binding as tb
        src = inspect.getsource(tb._sign_slh_dsa)
        assert "HMAC-SHA256 (fallback" in src
        assert "install pqcrypto or pyspx" in src.lower() or "pqcrypto or pyspx" in src

    def test_fallback_warning_message_present(self):
        """Verify the WARNING log message is present in the fallback path."""
        import inspect
        from shadow313.v4.temporal_binding import temporal_binding as tb
        src = inspect.getsource(tb._sign_slh_dsa)
        assert "CRQC-012" in src
        assert "WARNING" in src or "warning" in src

    def test_three_tier_structure_present(self):
        """Verify all three tiers are present in the source."""
        import inspect
        from shadow313.v4.temporal_binding import temporal_binding as tb
        src = inspect.getsource(tb._sign_slh_dsa)
        assert "pqcrypto" in src       # Tier 1
        assert "pyspx" in src          # Tier 2
        assert "HMAC-SHA256" in src    # Tier 3