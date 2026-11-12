"""API status endpoint reports implemented versus unavailable remote capabilities."""

from fastapi.testclient import TestClient

from shadow313.api.server import create_app


def test_status_distinguishes_local_modules_from_remote_api_capabilities():
    client = TestClient(create_app(api_key="status-test-key"))

    response = client.get("/api/status")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "operational"
    assert body["modules"]["recon"] is True
    assert body["api_endpoints"]["recon_scan"] == "unavailable"
    assert body["api_endpoints"]["vulnerability_scan"] == "unavailable"
    assert body["api_endpoints"]["detection"] == "available"
    assert body["api_endpoints"]["webshell_scan"] == "available"
    assert body["api_endpoints"]["chat"] == "requires_configured_ai_backend"
    assert body["api_endpoints"]["bind_receipts"] == "unsigned_demo_only"
