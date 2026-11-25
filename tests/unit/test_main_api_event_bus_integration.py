"""Main API integration tests for the persistent platform event bus."""

from fastapi.testclient import TestClient

from shadow313.api import create_app
from shadow313_platform import event_bus


def test_main_api_event_routes_use_persistent_authenticated_store(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "SHADOW313_EVENT_STORE_PATH",
        str(tmp_path / "main-api-events.sqlite3"),
    )
    event_bus._default_bus = None
    client = TestClient(create_app(api_key="main-api-test-key"))
    headers = {"x-api-key": "main-api-test-key"}

    unauthenticated = client.get("/api/events")
    published = client.post(
        "/api/events",
        headers=headers,
        json={
            "event_type": "detection.alert",
            "source": "main-api-test",
            "severity": "HIGH",
            "payload": {"technique_id": "T1059"},
        },
    )
    queried = client.get("/api/events", headers=headers)
    stats = client.get("/api/events/stats", headers=headers)
    coverage = client.get("/api/attck/coverage", headers=headers)

    assert unauthenticated.status_code == 401
    assert published.status_code == 200
    assert published.json()["persisted"] is True
    assert queried.status_code == 200
    assert queried.json()["storage"] == "sqlite"
    assert queried.json()["count"] == 1
    assert stats.status_code == 200
    assert stats.json()["total_events"] == 1
    assert coverage.status_code == 200
    assert coverage.json()["status"] == "unavailable"
    assert coverage.json()["overall_pct"] is None
