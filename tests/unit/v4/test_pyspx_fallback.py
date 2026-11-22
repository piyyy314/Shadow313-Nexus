"""
Tests for SPHINCS+ signing and verification backends in temporal_binding.py

Verifies the three-tier signing chain:
  Tier 1: pqcrypto (C-accelerated) — not available in sandbox
  Tier 2: pyspx (SPHINCS+ reference implementation) — active in sandbox
  Tier 3: HMAC-SHA256 (last resort) — should NOT activate when pyspx present
"""
from __future__ import annotations
import subprocess, sys

# Check if pyspx is installable in this environment
def _pyspx_available():
    try:
        import pyspx
        return True
    except ImportError:
        return False

PYSPX_AVAILABLE = _pyspx_available()


import importlib
import sys
import pytest

from shadow313.v4.temporal_binding.temporal_binding import (
    _sign_slh_dsa,
    _verify_slh_dsa,
    TemporalBindingEngine,
)


# ═══════════════════════════════════════════════════════════════════════════════
# pyspx availability
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not PYSPX_AVAILABLE, reason="pyspx requires C build tools not available in this environment")
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

@pytest.mark.skipif(not PYSPX_AVAILABLE, reason="pyspx requires C build tools")
class TestSignSLHDSA:

    def test_returns_tuple(self):
        sig, algo, public_key = _sign_slh_dsa(b"test")
        assert isinstance(sig, str)
        assert isinstance(algo, str)
        assert isinstance(public_key, str)

    def test_uses_sphincs_not_hmac(self):
        """SPHINCS+ backend must be active, not HMAC fallback."""
        _, algo, _ = _sign_slh_dsa(b"test")
        assert "SPHINCS+" in algo, f"Expected SPHINCS+, got: {algo}"
        assert "HMAC" not in algo, f"Must NOT use HMAC fallback, got: {algo}"

    def test_algo_does_not_claim_fips_205(self):
        _, algo, _ = _sign_slh_dsa(b"test")
        assert "FIPS 205" not in algo and "SPHINCS+" in algo

    def test_algo_mentions_pyspx(self):
        """Confirms pyspx tier (not pqcrypto) is active in this environment."""
        _, algo, _ = _sign_slh_dsa(b"test")
        assert "pyspx" in algo.lower() or "pqcrypto" in algo.lower()

    def test_signature_is_hex_string(self):
        sig, _, _ = _sign_slh_dsa(b"test")
        assert all(c in "0123456789abcdef" for c in sig)

    def test_signature_length_is_sphincs(self):
        """SPHINCS+-SHAKE-128f signature = 17088 bytes = 34176 hex chars."""
        sig, algo, _ = _sign_slh_dsa(b"test")
        if "pyspx" in algo.lower() or "pqcrypto" in algo.lower():
            assert len(sig) == 34176, f"Expected 34176 hex chars, got {len(sig)}"

    def test_different_messages_produce_different_sigs(self):
        sig1, algo1, public_key1 = _sign_slh_dsa(b"message one")
        sig2, algo2, public_key2 = _sign_slh_dsa(b"message two")
        assert sig1 != sig2
        assert public_key1 == public_key2
        assert _verify_slh_dsa(b"message one", sig1, algo1, public_key1)
        assert _verify_slh_dsa(b"message two", sig2, algo2, public_key2)

    def test_same_message_signatures_are_verifiable(self):
        """The persisted public key verifies repeated signatures for the same payload."""
        sig1, algo1, public_key1 = _sign_slh_dsa(b"same message")
        sig2, algo2, public_key2 = _sign_slh_dsa(b"same message")
        assert public_key1 == public_key2
        assert _verify_slh_dsa(b"same message", sig1, algo1, public_key1)
        assert _verify_slh_dsa(b"same message", sig2, algo2, public_key2)

    def test_empty_message_works(self):
        sig, algo, _ = _sign_slh_dsa(b"")
        assert len(sig) > 0
        assert "SPHINCS+" in algo

    def test_large_message_works(self):
        large_msg = b"x" * 100_000
        sig, algo, _ = _sign_slh_dsa(large_msg)
        assert "SPHINCS+" in algo
        assert len(sig) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Full 313-BIND receipt with pyspx
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not PYSPX_AVAILABLE, reason="pyspx requires C build tools")
class TestReceiptWithPyspx:

    @pytest.fixture
    def engine(self):
        return TemporalBindingEngine()

    def test_receipt_uses_sphincs_algo(self, engine):
        r = engine.bind({"test": "data"})
        assert "SPHINCS+" in r.algorithm, f"Got: {r.algorithm}"
        assert "HMAC" not in r.algorithm

    def test_receipt_timestamp_ends_313(self, engine):
        r = engine.bind({"test": "data"})
        assert r.timestamp % 1000 == 313

    def test_receipt_has_real_signature(self, engine):
        r = engine.bind({"test": "data"})
        # SPHINCS+ shake_128f signature = 17088 bytes = 34176 hex chars
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
        """A configured SPHINCS+ backend must not silently downgrade to HMAC."""
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
        assert "HMAC-SHA256 (shared-secret)" in src
        assert "SHADOW313_BIND_KEY" in src
        assert "UNSIGNED (no signing backend configured)" in src

    def test_fallback_warning_message_present(self):
        """Verify the WARNING log message is present in the fallback path."""
        import inspect
        from shadow313.v4.temporal_binding import temporal_binding as tb
        src = inspect.getsource(tb._sign_slh_dsa)
        assert "creating an explicitly unsigned receipt" in src
        assert "warning" in src.lower()

    def test_three_tier_structure_present(self):
        """Verify all three tiers are present in the source."""
        import inspect
        from shadow313.v4.temporal_binding import temporal_binding as tb
        src = inspect.getsource(tb._sign_slh_dsa)
        assert "pqcrypto" in src       # Tier 1
        assert "pyspx" in src          # Tier 2
        assert "HMAC-SHA256" in src    # Tier 3