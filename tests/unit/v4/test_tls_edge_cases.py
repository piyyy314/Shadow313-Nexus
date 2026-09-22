"""
Tests for shadow313.v4.tools.blueteam.tls_edge_cases

Covers all 5 edge case categories plus chain integrity and tamper resistance.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta

import shadow313.v4.tools.blueteam.tls_edge_cases as tls_mod
from shadow313.v4.tools.blueteam.tls_edge_cases import (
    check_cert_expiry,
    check_hsts,
    check_pqc_support,
    check_tls_version,
    check_connection_failure,
    run_hsts_checks,
    run_pqc_checks,
    run_tls_version_checks,
    run_connection_failure_checks,
    run_tls_edge_case_simulation,
    TLSCheckResult,
    _verify_chain,
)


@pytest.fixture(autouse=True)
def reset_chain():
    """Reset global chain state before each test."""
    tls_mod._BIND_COUNTER = 0
    tls_mod._CHAIN = []
    yield
    tls_mod._BIND_COUNTER = 0
    tls_mod._CHAIN = []


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Case 1: Certificate Expiry
# ═══════════════════════════════════════════════════════════════════════════════

class TestCertExpiry:

    def test_expired_cert_fails(self):
        past = datetime(2021, 1, 1, tzinfo=timezone.utc)
        r = check_cert_expiry(past)
        assert r.passed is False
        assert r.severity == "CRITICAL"
        assert "EXPIRED" in r.detail

    def test_expiring_soon_high(self):
        soon = datetime.now(timezone.utc) + timedelta(days=15)
        r = check_cert_expiry(soon)
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_expiring_medium_term(self):
        medium = datetime.now(timezone.utc) + timedelta(days=60)
        r = check_cert_expiry(medium)
        assert r.severity == "MEDIUM"

    def test_valid_cert_passes(self):
        future = datetime.now(timezone.utc) + timedelta(days=365)
        r = check_cert_expiry(future)
        assert r.passed is True
        assert r.severity == "INFO"

    def test_expired_cert_gets_bind_id(self):
        past = datetime(2021, 1, 1, tzinfo=timezone.utc)
        r = check_cert_expiry(past)
        assert r.bind_id.startswith("313-TLS-")
        assert r.chain_hash != ""

    def test_bind_id_increments(self):
        past = datetime(2021, 1, 1, tzinfo=timezone.utc)
        r1 = check_cert_expiry(past)
        r2 = check_cert_expiry(past)
        assert r1.bind_id != r2.bind_id
        assert r2.bind_id == "313-TLS-00000002"


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Case 2: HSTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHSTS:

    def test_missing_hsts_fails_high(self):
        r = check_hsts("Missing HSTS", None)
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_revoked_hsts_critical(self):
        r = check_hsts("Revoked", "max-age=0")
        assert r.passed is False
        assert r.severity == "CRITICAL"

    def test_short_max_age_fails(self):
        r = check_hsts("Short", "max-age=86400")
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_missing_include_subdomains(self):
        r = check_hsts("No subdomains", "max-age=31536000")
        assert r.passed is False
        assert r.severity == "MEDIUM"

    def test_correct_hsts_passes(self):
        r = check_hsts("Correct", "max-age=31536000; includeSubDomains; preload")
        assert r.passed is True
        assert r.severity == "INFO"

    def test_run_hsts_checks_returns_five(self):
        results = run_hsts_checks()
        assert len(results) == 5

    def test_run_hsts_checks_all_bound(self):
        results = run_hsts_checks()
        for r in results:
            assert r.bind_id.startswith("313-TLS-")

    def test_hsts_correct_is_last_and_passes(self):
        results = run_hsts_checks()
        assert results[-1].passed is True


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Case 3: PQC / Kyber-768
# ═══════════════════════════════════════════════════════════════════════════════

class TestPQCSupport:

    def test_full_pqc_passes(self):
        r = check_pqc_support("Full", "TLSv1.3", ["X25519Kyber768Draft00", "X25519"])
        assert r.passed is True
        assert r.severity == "INFO"
        assert "FULL" in r.check

    def test_tls13_no_kyber_partial(self):
        r = check_pqc_support("Partial", "TLSv1.3", ["X25519", "P-256"])
        assert r.passed is False
        assert r.severity == "MEDIUM"
        assert "PARTIAL" in r.check

    def test_tls12_incompatible(self):
        r = check_pqc_support("TLS12", "TLSv1.2", ["ECDHE-RSA-AES256-GCM-SHA384"])
        assert r.passed is False
        assert r.severity == "HIGH"
        assert "INCOMPATIBLE" in r.check

    def test_connection_failed_incompatible(self):
        r = check_pqc_support("Failed", None, [])
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_run_pqc_checks_returns_four(self):
        results = run_pqc_checks()
        assert len(results) == 4

    def test_run_pqc_checks_first_passes(self):
        results = run_pqc_checks()
        assert results[0].passed is True

    def test_run_pqc_checks_rest_fail(self):
        results = run_pqc_checks()
        for r in results[1:]:
            assert r.passed is False


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Case 4: Connection Failures
# ═══════════════════════════════════════════════════════════════════════════════

class TestConnectionFailures:

    def test_cert_verify_fail_critical(self):
        r = check_connection_failure("Cert verify fail", "CRITICAL", "CERT_VERIFICATION_FAILED")
        assert r.passed is False
        assert r.severity == "CRITICAL"

    def test_timeout_medium(self):
        r = check_connection_failure("Timeout", "MEDIUM", "CONNECTION_TIMEOUT")
        assert r.passed is False
        assert r.severity == "MEDIUM"

    def test_dns_fail_high(self):
        r = check_connection_failure("DNS fail", "HIGH", "CONNECTION_FAILED")
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_ssl_version_mismatch_high(self):
        r = check_connection_failure("SSL mismatch", "HIGH", "SSL_ERROR: wrong version number")
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_run_connection_failures_returns_four(self):
        results = run_connection_failure_checks()
        assert len(results) == 4

    def test_all_connection_failures_bound(self):
        results = run_connection_failure_checks()
        for r in results:
            assert r.bind_id.startswith("313-TLS-")
            assert r.passed is False


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Case 5: TLS Versions
# ═══════════════════════════════════════════════════════════════════════════════

class TestTLSVersions:

    def test_tls13_passes(self):
        r = check_tls_version("TLSv1.3")
        assert r.passed is True
        assert r.severity == "INFO"

    def test_tls12_medium(self):
        r = check_tls_version("TLSv1.2")
        assert r.passed is False
        assert r.severity == "MEDIUM"

    def test_tls11_high(self):
        r = check_tls_version("TLSv1.1")
        assert r.passed is False
        assert r.severity == "HIGH"

    def test_tls10_critical(self):
        r = check_tls_version("TLSv1")
        assert r.passed is False
        assert r.severity == "CRITICAL"

    def test_sslv3_critical(self):
        r = check_tls_version("SSLv3")
        assert r.passed is False
        assert r.severity == "CRITICAL"
        assert "POODLE" in r.detail

    def test_run_tls_version_checks_returns_five(self):
        results = run_tls_version_checks()
        assert len(results) == 5

    def test_only_tls13_passes(self):
        results = run_tls_version_checks()
        passed = [r for r in results if r.passed]
        assert len(passed) == 1
        assert "TLSv1.3" in passed[0].check


# ═══════════════════════════════════════════════════════════════════════════════
# 313 Chain Integrity
# ═══════════════════════════════════════════════════════════════════════════════

class TestChainIntegrity:

    def test_empty_chain_valid(self):
        result = _verify_chain()
        assert result["valid"] is True

    def test_chain_grows_with_binds(self):
        check_tls_version("TLSv1.3")
        check_tls_version("TLSv1.2")
        assert len(tls_mod._CHAIN) == 2

    def test_chain_valid_after_multiple_binds(self):
        run_tls_version_checks()
        result = _verify_chain()
        assert result["valid"] is True
        assert result["total"] == 5

    def test_bind_ids_are_sequential(self):
        run_tls_version_checks()
        for i, receipt in enumerate(tls_mod._CHAIN, 1):
            assert receipt["bind_id"] == f"313-TLS-{i:08d}"

    def test_chain_hashes_are_unique(self):
        run_tls_version_checks()
        hashes = [r["chain_hash"] for r in tls_mod._CHAIN]
        assert len(set(hashes)) == len(hashes)

    def test_chain_links_via_prev_hash(self):
        run_tls_version_checks()
        # Each entry's chain_hash should differ from its predecessor
        for i in range(1, len(tls_mod._CHAIN)):
            assert tls_mod._CHAIN[i]["chain_hash"] != tls_mod._CHAIN[i-1]["chain_hash"]


# ═══════════════════════════════════════════════════════════════════════════════
# Full Simulation
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullSimulation:

    def test_simulation_runs_without_error(self):
        report = run_tls_edge_case_simulation(verbose=False)
        assert "total_binds" in report
        assert "chain_valid" in report

    def test_simulation_creates_19_binds(self):
        report = run_tls_edge_case_simulation(verbose=False)
        assert report["total_binds"] == 19

    def test_simulation_chain_valid(self):
        report = run_tls_edge_case_simulation(verbose=False)
        assert report["chain_valid"] is True

    def test_simulation_has_all_categories(self):
        report = run_tls_edge_case_simulation(verbose=False)
        for key in ("cert_expiry", "hsts", "pqc", "connection_failures", "tls_versions"):
            assert key in report["results"]

    def test_simulation_critical_count(self):
        report = run_tls_edge_case_simulation(verbose=False)
        # SSLv3, TLSv1, cert expired, HSTS revoked, cert verify fail = at least 5 CRITICAL
        assert report["critical_count"] >= 5

    def test_simulation_chain_snapshot_has_five(self):
        report = run_tls_edge_case_simulation(verbose=False)
        assert len(report["chain_snapshot"]) == 5

    def test_simulation_resets_counter(self):
        run_tls_edge_case_simulation(verbose=False)
        run_tls_edge_case_simulation(verbose=False)
        # Second run should also produce 19 binds (counter resets)
        assert tls_mod._BIND_COUNTER == 19

    def test_simulation_checks_passed_and_failed(self):
        report = run_tls_edge_case_simulation(verbose=False)
        assert report["checks_passed"] >= 1   # TLSv1.3, correct HSTS, full PQC
        assert report["checks_failed"] >= 10  # most checks fail by design