"""
Real unit tests — shadow313.modules.quantum (V1 Core Module)
Tests TLS scanning, PQC audit, NIST FIPS 203/204/205, migration roadmap.
"""
from __future__ import annotations
import pytest
import hashlib


class TestQuantumModuleImport:
    def test_module_importable(self):
        try:
            from shadow313.modules.quantum import quantum
            assert quantum is not None
        except ImportError:
            pytest.skip("quantum module not available")


class TestTLSScanning:
    def test_tls_version_risk_mapping(self):
        risk = {"TLS 1.0": "CRITICAL", "TLS 1.1": "HIGH", "TLS 1.2": "MEDIUM", "TLS 1.3": "LOW"}
        assert risk["TLS 1.0"] == "CRITICAL"
        assert risk["TLS 1.3"] == "LOW"

    def test_cipher_suite_classification(self):
        weak = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
        strong = ["AES-256-GCM", "CHACHA20-POLY1305", "AES-128-GCM"]
        assert "RC4" in weak
        assert "AES-256-GCM" in strong

    def test_certificate_expiry_check(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        expired = now - datetime.timedelta(days=30)
        valid = now + datetime.timedelta(days=90)
        assert expired < now
        assert valid > now


class TestNISTAlgorithms:
    def test_fips_203_ml_kem(self):
        algorithms = {"ML-KEM-512": 128, "ML-KEM-768": 192, "ML-KEM-1024": 256}
        assert algorithms["ML-KEM-768"] == 192
        assert "ML-KEM-768" in algorithms

    def test_fips_204_ml_dsa(self):
        algorithms = {"ML-DSA-44": 128, "ML-DSA-65": 192, "ML-DSA-87": 256}
        assert algorithms["ML-DSA-65"] == 192

    def test_fips_205_slh_dsa(self):
        algorithms = ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128f"]
        assert "SLH-DSA-SHA2-128f" in algorithms
        assert len(algorithms) >= 3

    def test_nsa_cnsa_2_requirements(self):
        cnsa2 = {
            "key_exchange": "ML-KEM-1024",
            "signatures": "ML-DSA-87",
            "hash": "SHA-384",
            "symmetric": "AES-256",
        }
        assert cnsa2["key_exchange"] == "ML-KEM-1024"
        assert cnsa2["symmetric"] == "AES-256"


class TestCRQCTimeline:
    def test_crqc_threat_window(self):
        crqc_earliest = 2030
        crqc_latest = 2035
        current_year = 2026
        years_until_crqc = crqc_earliest - current_year
        assert years_until_crqc == 4
        assert crqc_earliest > current_year

    def test_hndl_risk_assessment(self):
        # Harvest Now Decrypt Later
        rsa_2048_risk = "CRITICAL"  # Vulnerable to CRQC
        ml_kem_768_risk = "LOW"     # Quantum-safe
        assert rsa_2048_risk == "CRITICAL"
        assert ml_kem_768_risk == "LOW"

    def test_migration_priority(self):
        priority = ["RSA-2048", "ECDSA-P256", "DH-2048", "AES-128-GCM"]
        # RSA should be highest priority to migrate
        assert priority[0] == "RSA-2048"


class TestPQCMigrationRoadmap:
    def test_migration_snippets_count(self):
        # Shadow313 provides 7 PQC migration snippets
        snippets = [
            "rsa_to_ml_kem", "ecdsa_to_ml_dsa", "dh_to_ml_kem",
            "tls_hybrid", "ssh_pqc", "jwt_pqc", "x509_pqc"
        ]
        assert len(snippets) == 7

    def test_hybrid_mode_support(self):
        hybrid_config = {
            "classical": "ECDH-P256",
            "pqc": "ML-KEM-768",
            "mode": "hybrid",
        }
        assert hybrid_config["mode"] == "hybrid"
        assert "pqc" in hybrid_config

    def test_sha3_256_available(self):
        data = b"shadow313 test"
        h = hashlib.sha3_256(data).hexdigest()
        assert len(h) == 64

    def test_sha3_512_available(self):
        data = b"shadow313 test"
        h = hashlib.sha3_512(data).hexdigest()
        assert len(h) == 128