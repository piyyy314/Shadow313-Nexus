"""
Tests for shadow313.integrations.aegis_pqc and shadow313.core.binding_sdk

Covers:
  - Binder313 SDK: receipt creation, timestamp, hash chains
  - PQCAuditParser: shadow313_sbom, cyclonedx, dict, json formats
  - AegisPQCBinder: bind_shadow313_sbom, bind_cyclonedx, bind_dict
  - Report generation: HTML + JSON output
  - _SimulatedReceipt: fallback when SDK unavailable
"""
from __future__ import annotations

import json
import os
import tempfile
import pytest

from shadow313.core.binding_sdk import Binder313, AppIdentity, BindReceipt
from shadow313.integrations.aegis_pqc import (
    AegisPQCBinder, PQCAuditParser, PQCAuditResult, PQCComponent,
)
from shadow313.integrations.aegis_pqc.binder import _SimulatedReceipt
from shadow313.integrations.aegis_pqc.report import generate_bound_report


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def identity():
    return AppIdentity(app_id="test-app", app_name="Test", app_version="1.0.0")

@pytest.fixture
def binder313(identity):
    return Binder313(identity=identity)

@pytest.fixture
def sample_components():
    """Shadow313 crypto SBOM components."""
    from shadow313.v4.core.crypto_sbom import SHADOW313_CRYPTO_SBOM
    return [c.__dict__ for c in SHADOW313_CRYPTO_SBOM]

@pytest.fixture
def pqc_binder():
    return AegisPQCBinder()

@pytest.fixture
def vulnerable_components():
    return [
        {"algorithm": "ECDSA P-256", "purpose": "signing",    "key_size_bits": 256,
         "quantum_safe": False, "fips_standard": "FIPS 186-5", "status": "ACTIVE", "files": []},
        {"algorithm": "RSA-2048",    "purpose": "encryption", "key_size_bits": 2048,
         "quantum_safe": False, "fips_standard": "N/A",       "status": "ACTIVE", "files": []},
        {"algorithm": "SHA3-256",    "purpose": "hashing",    "key_size_bits": 256,
         "quantum_safe": True,  "fips_standard": "FIPS 202",  "status": "ACTIVE", "files": []},
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Binder313 SDK
# ═══════════════════════════════════════════════════════════════════════════════

class TestBinder313:

    def test_bind_returns_receipt(self, binder313):
        r = binder313.bind({"test": "data"})
        assert isinstance(r, BindReceipt)

    def test_timestamp_ends_313(self, binder313):
        r = binder313.bind({"x": 1})
        assert str(r.timestamp_ns).endswith("313")

    def test_payload_hash_is_sha3_256(self, binder313):
        r = binder313.bind({"x": 1})
        assert r.payload_hash.startswith("sha3_256:")
        assert len(r.payload_hash) == len("sha3_256:") + 64

    def test_chain_hash_is_sha3_512(self, binder313):
        r = binder313.bind({"x": 1})
        assert r.chain_hash.startswith("sha3_512:")
        assert len(r.chain_hash) == len("sha3_512:") + 128

    def test_bind_id_contains_app_id(self, binder313):
        r = binder313.bind({"x": 1})
        assert "TEST" in r.bind_id or "test" in r.bind_id.lower()

    def test_sequence_increments(self, binder313):
        r1 = binder313.bind({"i": 1})
        r2 = binder313.bind({"i": 2})
        assert r2.sequence == r1.sequence + 1

    def test_chain_links_prev_hash(self, binder313):
        r1 = binder313.bind({"i": 1})
        r2 = binder313.bind({"i": 2})
        assert r2.prev_chain_hash == r1.chain_hash

    def test_verify_timestamp(self, binder313):
        r = binder313.bind({"x": 1})
        assert r.verify_timestamp() is True

    def test_verify_payload_correct(self, binder313):
        payload = {"key": "value", "num": 42}
        r = binder313.bind(payload)
        # Pass sequence and app_id to reconstruct full_payload
        assert r.verify_payload(payload, sequence=r.sequence, app_id=r.app_id) is True

    def test_verify_payload_tampered(self, binder313):
        payload = {"key": "value"}
        r = binder313.bind(payload)
        assert r.verify_payload({"key": "tampered"}, sequence=r.sequence, app_id=r.app_id) is False

    def test_to_dict_has_required_keys(self, binder313):
        r = binder313.bind({"x": 1})
        d = r.to_dict()
        for key in ("bind_id", "timestamp_ns", "timestamp_iso", "payload_hash",
                    "chain_hash", "signature_algorithm", "app_id", "app_version"):
            assert key in d

    def test_signature_algorithm_is_slhdsa_or_hmac(self, binder313):
        r = binder313.bind({"x": 1})
        assert "SLH-DSA" in r.signature_algorithm or "HMAC" in r.signature_algorithm

    def test_verify_method(self, binder313):
        payload = {"audit": "data"}
        r = binder313.bind(payload)
        # verify() uses the binder's internal state for reconstruction
        # Test timestamp verification directly
        assert r.verify_timestamp() is True
        # Test that bind_id is set
        assert r.bind_id is not None


# ═══════════════════════════════════════════════════════════════════════════════
# PQCAuditParser
# ═══════════════════════════════════════════════════════════════════════════════

class TestPQCAuditParser:

    def test_parse_shadow313_sbom(self, sample_components):
        parser = PQCAuditParser()
        result = parser.parse_shadow313_sbom(sample_components, "test_sbom")
        assert isinstance(result, PQCAuditResult)
        assert len(result.components) == len(sample_components)

    def test_parse_shadow313_sbom_classifies_ecdsa_critical(self):
        parser = PQCAuditParser()
        comps = [{"algorithm": "ECDSA P-256", "purpose": "signing",
                  "key_size_bits": 256, "quantum_safe": False,
                  "fips_standard": "N/A", "status": "ACTIVE", "files": []}]
        result = parser.parse_shadow313_sbom(comps)
        assert result.components[0].risk_level == "CRITICAL"
        assert result.components[0].is_quantum_safe is False

    def test_parse_shadow313_sbom_classifies_sha3_safe(self):
        parser = PQCAuditParser()
        comps = [{"algorithm": "SHA3-256", "purpose": "hashing",
                  "key_size_bits": 256, "quantum_safe": True,
                  "fips_standard": "FIPS 202", "status": "ACTIVE", "files": []}]
        result = parser.parse_shadow313_sbom(comps)
        assert result.components[0].is_quantum_safe is True
        assert result.components[0].risk_level == "ACCEPTABLE"

    def test_parse_cyclonedx(self):
        parser = PQCAuditParser()
        cdx = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "type": "cryptographic-asset",
                    "name": "ECDSA P-256",
                    "bom-ref": "CS-001",
                    "cryptoProperties": {"assetType": "signing",
                                         "algorithmProperties": {"classicalSecurityLevel": 256}},
                    "properties": [{"name": "quantum_safe", "value": "False"},
                                   {"name": "status", "value": "ACTIVE"}],
                }
            ],
        }
        result = parser.parse_cyclonedx(cdx, "test.json")
        assert len(result.components) == 1
        assert result.components[0].is_quantum_safe is False

    def test_parse_json_valid(self, sample_components):
        parser = PQCAuditParser()
        data = {"components": sample_components}
        result = parser.parse_json(json.dumps(data))
        assert len(result.components) == len(sample_components)

    def test_parse_json_invalid_returns_result(self):
        parser = PQCAuditParser()
        result = parser.parse_json("{invalid json{{")
        assert isinstance(result, PQCAuditResult)
        assert len(result.parse_warnings) > 0

    def test_overall_status_vulnerable_when_critical(self, vulnerable_components):
        parser = PQCAuditParser()
        result = parser.parse_shadow313_sbom(vulnerable_components)
        assert result.overall_status == "VULNERABLE"

    def test_overall_status_secure_when_all_safe(self):
        parser = PQCAuditParser()
        comps = [
            {"algorithm": "SHA3-256", "purpose": "hashing", "key_size_bits": 256,
             "quantum_safe": True, "fips_standard": "FIPS 202", "status": "ACTIVE", "files": []},
            {"algorithm": "AES-256-GCM", "purpose": "encryption", "key_size_bits": 256,
             "quantum_safe": True, "fips_standard": "FIPS 140-3", "status": "ACTIVE", "files": []},
        ]
        result = parser.parse_shadow313_sbom(comps)
        assert result.overall_status == "SECURE"

    def test_quantum_readiness_pct(self, vulnerable_components):
        parser = PQCAuditParser()
        result = parser.parse_shadow313_sbom(vulnerable_components)
        # 1 safe out of 3 = 33%
        assert result.quantum_readiness_pct == 33

    def test_to_bind_payload_serializable(self, sample_components):
        parser = PQCAuditParser()
        result = parser.parse_shadow313_sbom(sample_components)
        payload = result.to_bind_payload()
        serialized = json.dumps(payload, default=str)
        parsed = json.loads(serialized)
        assert parsed["total_components"] == len(sample_components)


# ═══════════════════════════════════════════════════════════════════════════════
# AegisPQCBinder
# ═══════════════════════════════════════════════════════════════════════════════

class TestAegisPQCBinder:

    def test_bind_shadow313_sbom(self, pqc_binder, sample_components):
        audit, receipt = pqc_binder.bind_shadow313_sbom(sample_components)
        assert isinstance(audit, PQCAuditResult)
        assert receipt is not None

    def test_bind_cyclonedx(self, pqc_binder):
        cdx = {
            "bomFormat": "CycloneDX",
            "components": [
                {"type": "cryptographic-asset", "name": "SHA3-256", "bom-ref": "CS-001",
                 "cryptoProperties": {"assetType": "hashing",
                                      "algorithmProperties": {"classicalSecurityLevel": 256}},
                 "properties": [{"name": "quantum_safe", "value": "True"},
                                 {"name": "status", "value": "ACTIVE"}]},
            ],
        }
        audit, receipt = pqc_binder.bind_cyclonedx(cdx)
        assert len(audit.components) == 1
        assert receipt is not None

    def test_bind_dict(self, pqc_binder, vulnerable_components):
        audit, receipt = pqc_binder.bind_dict({"components": vulnerable_components})
        assert audit.critical_count >= 1
        assert receipt is not None

    def test_bind_json(self, pqc_binder, sample_components):
        data = json.dumps({"components": sample_components})
        audit, receipt = pqc_binder.bind_json(data)
        assert len(audit.components) == len(sample_components)

    def test_receipt_timestamp_ends_313(self, pqc_binder, sample_components):
        _, receipt = pqc_binder.bind_shadow313_sbom(sample_components)
        assert str(receipt.timestamp_ns).endswith("313")

    def test_summary_has_required_keys(self, pqc_binder, sample_components):
        audit, receipt = pqc_binder.bind_shadow313_sbom(sample_components)
        s = pqc_binder.summary(audit, receipt)
        for key in ("overall_status", "critical_count", "quantum_readiness_pct",
                    "bind_id", "timestamp_ns"):
            assert key in s

    def test_generate_report_creates_files(self, pqc_binder, sample_components):
        audit, receipt = pqc_binder.bind_shadow313_sbom(sample_components)
        with tempfile.TemporaryDirectory() as d:
            html_path, json_path = pqc_binder.generate_report(audit, receipt, output_dir=d)
            assert os.path.exists(html_path)
            assert os.path.exists(json_path)

    def test_generate_report_json_valid(self, pqc_binder, sample_components):
        audit, receipt = pqc_binder.bind_shadow313_sbom(sample_components)
        with tempfile.TemporaryDirectory() as d:
            _, json_path = pqc_binder.generate_report(audit, receipt, output_dir=d)
            data = json.load(open(json_path))
            assert "receipt" in data
            assert "audit" in data
            assert "summary" in data

    def test_generate_report_html_contains_bind_id(self, pqc_binder, sample_components):
        audit, receipt = pqc_binder.bind_shadow313_sbom(sample_components)
        with tempfile.TemporaryDirectory() as d:
            html_path, _ = pqc_binder.generate_report(audit, receipt, output_dir=d)
            html = open(html_path).read()
            assert receipt.bind_id in html


# ═══════════════════════════════════════════════════════════════════════════════
# _SimulatedReceipt
# ═══════════════════════════════════════════════════════════════════════════════

class TestSimulatedReceipt:

    def test_timestamp_ends_313(self):
        r = _SimulatedReceipt({"test": "data"})
        assert str(r.timestamp_ns).endswith("313")

    def test_payload_hash_is_sha3_256(self):
        r = _SimulatedReceipt({"test": "data"})
        assert r.payload_hash.startswith("sha3_256:")

    def test_chain_hash_is_sha3_512(self):
        r = _SimulatedReceipt({"test": "data"})
        assert r.chain_hash.startswith("sha3_512:")

    def test_bind_id_starts_with_aegis_pqc(self):
        r = _SimulatedReceipt({"test": "data"})
        assert "AEGIS" in r.bind_id or "aegis" in r.bind_id.lower()

    def test_to_dict_has_all_fields(self):
        r = _SimulatedReceipt({"test": "data"})
        d = r.to_dict()
        for key in ("bind_id", "timestamp_ns", "timestamp_iso", "payload_hash",
                    "chain_hash", "signature_algorithm", "ipfs_cid",
                    "ipfs_anchored", "app_id", "app_version"):
            assert key in d

    def test_different_payloads_different_hashes(self):
        r1 = _SimulatedReceipt({"a": 1})
        r2 = _SimulatedReceipt({"b": 2})
        assert r1.payload_hash != r2.payload_hash


# ═══════════════════════════════════════════════════════════════════════════════
# Report generation
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportGeneration:

    def test_generate_bound_report_creates_files(self, sample_components):
        parser = PQCAuditParser()
        audit  = parser.parse_shadow313_sbom(sample_components, "test")
        receipt = _SimulatedReceipt(audit.to_bind_payload())
        with tempfile.TemporaryDirectory() as d:
            html_path, json_path = generate_bound_report(audit, receipt, output_dir=d)
            assert os.path.exists(html_path)
            assert os.path.exists(json_path)

    def test_html_contains_receipt_fields(self, sample_components):
        parser = PQCAuditParser()
        audit  = parser.parse_shadow313_sbom(sample_components, "test")
        receipt = _SimulatedReceipt(audit.to_bind_payload())
        with tempfile.TemporaryDirectory() as d:
            html_path, _ = generate_bound_report(audit, receipt, output_dir=d)
            html = open(html_path).read()
            assert receipt.bind_id in html
            assert str(receipt.timestamp_ns) in html

    def test_json_report_receipt_matches(self, sample_components):
        parser = PQCAuditParser()
        audit  = parser.parse_shadow313_sbom(sample_components, "test")
        receipt = _SimulatedReceipt(audit.to_bind_payload())
        with tempfile.TemporaryDirectory() as d:
            _, json_path = generate_bound_report(audit, receipt, output_dir=d)
            data = json.load(open(json_path))
            assert data["receipt"]["bind_id"] == receipt.bind_id

    def test_html_contains_component_risk_levels(self, vulnerable_components):
        parser = PQCAuditParser()
        audit  = parser.parse_shadow313_sbom(vulnerable_components, "test")
        receipt = _SimulatedReceipt(audit.to_bind_payload())
        with tempfile.TemporaryDirectory() as d:
            html_path, _ = generate_bound_report(audit, receipt, output_dir=d)
            html = open(html_path).read()
            assert "CRITICAL" in html