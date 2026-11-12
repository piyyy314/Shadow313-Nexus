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
    assert "chat" not in body["api_endpoints"]
    assert body["api_endpoints"]["bind_receipts"] == "unsigned_demo_only"



def test_production_rejects_short_or_placeholder_api_keys(monkeypatch):
    import pytest

    monkeypatch.setenv("SHADOW313_ENV", "production")
    for value in ("short", "replace-with-a-random-api-key"):
        with pytest.raises(RuntimeError, match="at least 32 characters"):
            create_app(api_key=value)

    app = create_app(api_key="a" * 40)
    assert app.title == "Shadow313 NEXUS API"
