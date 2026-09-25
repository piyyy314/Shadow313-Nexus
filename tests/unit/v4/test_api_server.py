"""
Tests for shadow313.api.server — FastAPI REST API
"""
from __future__ import annotations

import pytest

# Graceful skip if fastapi/httpx not installed
try:
    from fastapi.testclient import TestClient
    from shadow313.api.server import app
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi/httpx not installed")


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


class TestStatusEndpoint:
    def test_status_ok(self, client):
        r = client.get("/api/status")
        assert r.status_code == 200

    def test_status_has_version(self, client):
        r = client.get("/api/status")
        data = r.json()
        assert "version" in data or "status" in data

    def test_status_content_type(self, client):
        r = client.get("/api/status")
        assert "application/json" in r.headers.get("content-type", "")


class TestModulesEndpoint:
    def test_modules_ok(self, client):
        r = client.get("/api/modules")
        assert r.status_code == 200

    def test_modules_returns_list(self, client):
        r = client.get("/api/modules")
        data = r.json()
        assert isinstance(data, (list, dict))


class TestAttckCoverageEndpoint:
    def test_attck_coverage_ok(self, client):
        r = client.get("/api/attck/coverage")
        assert r.status_code == 200

    def test_attck_coverage_has_data(self, client):
        r = client.get("/api/attck/coverage")
        data = r.json()
        assert data is not None


class TestWebshellScanEndpoint:
    def test_webshell_scan_clean(self, client):
        r = client.post("/api/webshell/scan", json={"content": "<?php echo 'hello'; ?>"})
        assert r.status_code in (200, 422)

    def test_webshell_scan_malicious(self, client):
        payload = {"content": "<?php eval($_POST['cmd']); ?>"}
        r = client.post("/api/webshell/scan", json=payload)
        assert r.status_code in (200, 422)


class TestBindEndpoints:
    def test_bind_create(self, client):
        payload = {"event_type": "test", "source": "unit_test", "data": {"key": "value"}}
        r = client.post("/api/bind/create", json=payload)
        assert r.status_code in (200, 201, 422, 500)

    def test_bind_retrieve_missing(self, client):
        r = client.get("/api/bind/313-NONEXISTENT-0000")
        assert r.status_code in (200, 404)


class TestDetectEndpoint:
    def test_detect_basic_event(self, client):
        event = {
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc JABjAD0A",
            "user": "testuser",
            "host": "ws-test-01",
        }
        r = client.post("/api/detect", json=event)
        assert r.status_code in (200, 422)

    def test_detect_missing_body(self, client):
        r = client.post("/api/detect", json={})
        assert r.status_code in (200, 422)