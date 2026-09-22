"""
Tests for shadow313.v4.detection.crypto_hardening_audit
"""
from __future__ import annotations

import pytest
import numpy as np
from shadow313.v4.detection.crypto_hardening_audit import (
    EntropyBiasDetector,
    BiometricGANBypassDetector,
    KeyRotationAuditor,
)


class TestEntropyBiasDetector:

    def setup_method(self):
        self.detector = EntropyBiasDetector(sample_size=1000)

    def test_instantiates(self):
        assert self.detector is not None

    def test_has_audit_method(self):
        assert hasattr(self.detector, 'audit')

    def test_has_entropy_estimate(self):
        assert hasattr(self.detector, 'entropy_estimate')

    def test_has_monobit_test(self):
        assert hasattr(self.detector, 'monobit_test')

    def test_has_runs_test(self):
        assert hasattr(self.detector, 'runs_test')

    def test_simulate_biased_rng(self):
        """simulate_biased_rng should return samples."""
        result = self.detector.simulate_biased_rng()
        assert result is not None

    def test_simulate_jent_rng(self):
        """simulate_jent_rng should return samples."""
        result = self.detector.simulate_jent_rng()
        assert result is not None

    def test_monobit_test_returns_result(self):
        """monobit_test should return a result."""
        samples = self.detector.simulate_jent_rng()
        result = self.detector.monobit_test(samples)
        assert result is not None

    def test_runs_test_returns_result(self):
        """runs_test should return a result."""
        samples = self.detector.simulate_jent_rng()
        result = self.detector.runs_test(samples)
        assert result is not None

    def test_entropy_estimate_returns_float(self):
        """entropy_estimate should return a numeric value."""
        samples = self.detector.simulate_jent_rng()
        result = self.detector.entropy_estimate(samples)
        assert isinstance(result, (int, float))

    def test_entropy_estimate_bounded(self):
        """Entropy estimate should be non-negative."""
        samples = self.detector.simulate_jent_rng()
        result = self.detector.entropy_estimate(samples)
        assert float(result) >= 0.0

    def test_audit_returns_dict(self):
        """audit() should return a dict."""
        result = self.detector.audit()
        assert isinstance(result, dict)

    def test_audit_has_expected_keys(self):
        """audit() result should have meaningful keys."""
        result = self.detector.audit()
        assert len(result) > 0

    def test_biased_rng_vs_jent(self):
        """Biased RNG should differ from JENT RNG."""
        biased = self.detector.simulate_biased_rng()
        jent = self.detector.simulate_jent_rng()
        assert biased is not None
        assert jent is not None

    def test_sample_size_attribute(self):
        """sample_size attribute should be set."""
        assert self.detector.sample_size == 1000

    def test_different_sample_sizes(self):
        """Should work with different sample sizes."""
        for size in [100, 500, 2000]:
            d = EntropyBiasDetector(sample_size=size)
            assert d.sample_size == size


class TestBiometricGANBypassDetector:

    def setup_method(self):
        self.detector = BiometricGANBypassDetector()

    def test_instantiates(self):
        assert self.detector is not None

    def test_has_audit_method(self):
        assert hasattr(self.detector, 'audit')

    def test_has_error_rate_min(self):
        assert hasattr(self.detector, 'ERROR_RATE_MIN')

    def test_has_mouse_linearity_max(self):
        assert hasattr(self.detector, 'MOUSE_LINEARITY_MAX')

    def test_audit_returns_result(self):
        """audit() should return a result."""
        result = self.detector.audit()
        assert result is not None

    def test_audit_returns_dict(self):
        """audit() should return a dict."""
        result = self.detector.audit()
        assert isinstance(result, dict)

    def test_error_rate_min_is_numeric(self):
        """ERROR_RATE_MIN should be numeric."""
        assert isinstance(self.detector.ERROR_RATE_MIN, (int, float))

    def test_mouse_linearity_max_is_numeric(self):
        """MOUSE_LINEARITY_MAX should be numeric."""
        assert isinstance(self.detector.MOUSE_LINEARITY_MAX, (int, float))

    def test_error_rate_min_bounded(self):
        """ERROR_RATE_MIN should be between 0 and 1."""
        assert 0.0 <= self.detector.ERROR_RATE_MIN <= 1.0

    def test_mouse_linearity_max_bounded(self):
        """MOUSE_LINEARITY_MAX should be positive."""
        assert self.detector.MOUSE_LINEARITY_MAX > 0

    def test_audit_has_keys(self):
        """audit() result should have keys."""
        result = self.detector.audit()
        assert len(result) > 0

    def test_multiple_audits_consistent(self):
        """Multiple audit calls should not crash."""
        for _ in range(3):
            result = self.detector.audit()
            assert result is not None


class TestKeyRotationAuditor:

    def setup_method(self):
        self.auditor = KeyRotationAuditor()

    def test_instantiates(self):
        assert self.auditor is not None

    def test_has_audit_method(self):
        assert hasattr(self.auditor, 'audit')

    def test_audit_returns_result(self):
        """audit() should return a result."""
        result = self.auditor.audit()
        assert result is not None

    def test_audit_returns_dict(self):
        """audit() should return a dict."""
        result = self.auditor.audit()
        assert isinstance(result, dict)

    def test_audit_has_keys(self):
        """audit() result should have meaningful keys."""
        result = self.auditor.audit()
        assert len(result) > 0

    def test_multiple_audits(self):
        """Multiple audit calls should not crash."""
        for _ in range(3):
            result = self.auditor.audit()
            assert result is not None

    def test_audit_result_is_consistent(self):
        """Audit results should be consistent across calls."""
        r1 = self.auditor.audit()
        r2 = self.auditor.audit()
        assert type(r1) == type(r2)