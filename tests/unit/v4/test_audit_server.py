"""
Tests for shadow313.api.audit_server — audit chain, link budget, health.
"""
from __future__ import annotations

import hashlib
import pytest
from shadow313.api.audit_server import (
    _add_to_chain,
    _audit_chain,
    _calculate_link_budget,
    create_app,
)


# ── Audit chain tests ─────────────────────────────────────────────────────────

class TestAuditChain:

    def setup_method(self):
        """Clear audit chain before each test."""
        _audit_chain.clear()

    def test_add_to_chain_returns_receipt(self):
        receipt = _add_to_chain({"type": "test", "data": "hello"})
        assert receipt is not None
        assert "bind_id" in receipt
        assert "chain_hash" in receipt
        assert "timestamp_ns" in receipt

    def test_timestamp_ends_in_313(self):
        receipt = _add_to_chain({"type": "test"})
        assert str(receipt["timestamp_ns"]).endswith("313")

    def test_bind_index_increments(self):
        r1 = _add_to_chain({"type": "a"})
        r2 = _add_to_chain({"type": "b"})
        r3 = _add_to_chain({"type": "c"})
        assert r1["bind_index"] == 0
        assert r2["bind_index"] == 1
        assert r3["bind_index"] == 2

    def test_chain_hash_format(self):
        receipt = _add_to_chain({"type": "test"})
        assert receipt["chain_hash"].startswith("sha3_512:")
        # SHA3-512 produces 128 hex chars
        hex_part = receipt["chain_hash"].replace("sha3_512:", "")
        assert len(hex_part) == 128

    def test_payload_hash_format(self):
        receipt = _add_to_chain({"type": "test"})
        assert receipt["payload_hash"].startswith("sha3_256:")
        hex_part = receipt["payload_hash"].replace("sha3_256:", "")
        assert len(hex_part) == 64

    def test_chain_grows(self):
        initial = len(_audit_chain)
        _add_to_chain({"type": "a"})
        _add_to_chain({"type": "b"})
        assert len(_audit_chain) == initial + 2

    def test_custom_bind_id(self):
        receipt = _add_to_chain({"type": "test"}, bind_id="313-CUSTOM-001")
        assert receipt["bind_id"] == "313-CUSTOM-001"

    def test_auto_bind_id_format(self):
        receipt = _add_to_chain({"type": "test"})
        assert receipt["bind_id"].startswith("313-API-")

    def test_different_payloads_different_hashes(self):
        r1 = _add_to_chain({"type": "a", "data": "foo"})
        r2 = _add_to_chain({"type": "b", "data": "bar"})
        assert r1["payload_hash"] != r2["payload_hash"]
        assert r1["chain_hash"] != r2["chain_hash"]

    def test_receipt_has_timestamp_iso(self):
        receipt = _add_to_chain({"type": "test"})
        assert "timestamp_iso" in receipt
        assert "T" in receipt["timestamp_iso"]  # ISO 8601 format

    def test_receipt_has_signature_algorithm(self):
        receipt = _add_to_chain({"type": "test"})
        assert "signature_algorithm" in receipt
        assert "SLH-DSA" in receipt["signature_algorithm"]


# ── Link budget tests ─────────────────────────────────────────────────────────

class TestLinkBudget:

    def test_basic_calculation_returns_dict(self):
        result = _calculate_link_budget({})
        assert isinstance(result, dict)
        assert "fspl_db" in result
        assert "snr_db" in result
        assert "status" in result

    def test_fspl_positive(self):
        result = _calculate_link_budget({"frequency_ghz": 11.7, "distance_km": 38500})
        assert result["fspl_db"] > 0

    def test_geo_satellite_fspl_range(self):
        """GEO satellite FSPL should be ~205-210 dB at Ku-band."""
        result = _calculate_link_budget({
            "frequency_ghz": 11.7,
            "distance_km": 38500,
        })
        assert 200 <= result["fspl_db"] <= 215

    def test_status_nominal_good_link(self):
        """High gain, short distance should give NOMINAL status."""
        result = _calculate_link_budget({
            "frequency_ghz": 11.7,
            "distance_km": 550,  # LEO
            "tx_power_dbw": 15.0,
            "tx_gain_dbi": 50.0,
            "rx_gain_dbi": 40.0,
        })
        assert result["status"] in ("NOMINAL", "DEGRADED")

    def test_status_critical_bad_link(self):
        """Very low gain, very long distance should give CRITICAL or DEGRADED."""
        result = _calculate_link_budget({
            "frequency_ghz": 11.7,
            "distance_km": 100000,
            "tx_power_dbw": 0.0,
            "tx_gain_dbi": 0.0,
            "rx_gain_dbi": 0.0,
        })
        assert result["status"] in ("CRITICAL", "DEGRADED")

    def test_params_echoed_in_result(self):
        params = {"frequency_ghz": 20.0, "distance_km": 38500}
        result = _calculate_link_budget(params)
        assert result["params"]["frequency_ghz"] == 20.0

    def test_eirp_calculation(self):
        """EIRP = tx_power + tx_gain."""
        result = _calculate_link_budget({
            "tx_power_dbw": 10.0,
            "tx_gain_dbi": 45.0,
        })
        assert abs(result["eirp_dbw"] - 55.0) < 0.1

    def test_higher_frequency_higher_fspl(self):
        """Higher frequency → higher FSPL."""
        r_ku = _calculate_link_budget({"frequency_ghz": 11.7, "distance_km": 38500})
        r_ka = _calculate_link_budget({"frequency_ghz": 20.0, "distance_km": 38500})
        assert r_ka["fspl_db"] > r_ku["fspl_db"]

    def test_shorter_distance_lower_fspl(self):
        """Shorter distance → lower FSPL."""
        r_geo = _calculate_link_budget({"frequency_ghz": 11.7, "distance_km": 38500})
        r_leo = _calculate_link_budget({"frequency_ghz": 11.7, "distance_km": 550})
        assert r_leo["fspl_db"] < r_geo["fspl_db"]


# ── FastAPI app tests ─────────────────────────────────────────────────────────

class TestAuditServerApp:

    @pytest.fixture(autouse=True)
    def clear_chain(self):
        """Clear audit chain before each test."""
        _audit_chain.clear()
        yield
        _audit_chain.clear()

    @pytest.fixture
    def client(self):
        """Create a FastAPI test client."""
        try:
            from fastapi.testclient import TestClient
            app = create_app()
            return TestClient(app)
        except ImportError:
            pytest.skip("FastAPI/httpx not available")

    def test_health_endpoint(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["platform"] == "Shadow313 NEXUS"

    def test_audit_chain_empty(self, client):
        _audit_chain.clear()
        resp = client.get("/api/audit/chain")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_receipts"] == 0

    def test_audit_code_endpoint(self, client):
        resp = client.post("/api/audit-code", json={
            "code": "import os\nos.system('ls')",
            "language": "python",
            "depth": "tactical",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "complete"
        assert data["findings_count"] >= 1
        assert "receipt" in data

    def test_audit_code_detects_eval(self, client):
        resp = client.post("/api/audit-code", json={
            "code": "eval(user_input)",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        findings = data["findings"]
        cwes = [f["cwe"] for f in findings]
        assert "CWE-95" in cwes

    def test_audit_code_clean_code(self, client):
        resp = client.post("/api/audit-code", json={
            "code": "x = 1 + 1\nprint(x)",
            "language": "python",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "LOW"

    def test_audit_code_adds_to_chain(self, client):
        _audit_chain.clear()
        client.post("/api/audit-code", json={"code": "test"})
        resp = client.get("/api/audit/chain")
        data = resp.json()
        assert data["total_receipts"] >= 1

    def test_link_budget_endpoint(self, client):
        resp = client.post("/api/link-budget", json={
            "frequency_ghz": 11.7,
            "distance_km": 38500.0,
            "satellite": "GEO",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "snr_db" in data
        assert "status" in data
        assert "receipt" in data

    def test_link_budget_profiles_endpoint(self, client):
        resp = client.get("/api/link-budget/profiles")
        assert resp.status_code == 200
        data = resp.json()
        assert "profiles" in data
        assert len(data["profiles"]) >= 3

    def test_public_key_endpoint(self, client):
        resp = client.get("/api/public-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["algorithm"] == "SLH-DSA-SHAKE-128f"
        assert data["standard"] == "NIST FIPS 205"
        assert "fingerprint" in data

    def test_chain_valid_after_multiple_audits(self, client):
        _audit_chain.clear()
        for i in range(5):
            client.post("/api/audit-code", json={"code": f"test_{i}"})
        resp = client.get("/api/audit/chain")
        data = resp.json()
        assert data["chain_valid"] is True
        assert data["total_receipts"] == 5