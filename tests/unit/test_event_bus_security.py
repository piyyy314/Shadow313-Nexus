"""Tests for durable event persistence and API authentication."""

from fastapi.testclient import TestClient

from shadow313_platform import event_bus
from shadow313_platform.event_bus_security import (
    SQLiteEventStore,
    SecureEventPublisher,
)
from shadow313_platform.event_bus import PlatformEvent


def test_sqlite_event_store_persists_and_filters(tmp_path):
    db_path = tmp_path / "events.sqlite3"
    store = SQLiteEventStore(db_path, max_events=10)
    event = PlatformEvent(
        event_type="detection.alert",
        source="unit-test",
        severity="HIGH",
        payload={"technique_id": "T1059"},
    )

    store.append(event)
    reopened = SQLiteEventStore(db_path, max_events=10)

    assert len(reopened) == 1
    assert reopened.get_by_type("detection.alert")[0].event_id == event.event_id
    assert reopened.get_by_severity("HIGH")[0].payload["technique_id"] == "T1059"


def test_sqlite_event_store_deduplicates_and_bounds_retention(tmp_path):
    store = SQLiteEventStore(tmp_path / "events.sqlite3", max_events=2)
    first = PlatformEvent(event_type="one")
    second = PlatformEvent(event_type="two")
    third = PlatformEvent(event_type="three")

    store.append(first)
    store.append(first)
    store.append(second)
    store.append(third)

    assert len(store) == 2
    assert [event.event_type for event in store.get_all()] == ["two", "three"]


def test_event_bus_package_uses_persistent_publisher():
    assert event_bus.EventPublisher is SecureEventPublisher
    assert event_bus.EventStore is SQLiteEventStore


def test_event_api_requires_key_and_persists_events(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOW313_EVENT_BUS_API_KEY", "unit-test-api-key")
    publisher = SecureEventPublisher(tmp_path / "events.sqlite3")
    client = TestClient(publisher.build_app())

    health = client.get("/api/health")
    unauthenticated = client.get("/api/events")
    published = client.post(
        "/api/events/publish",
        headers={"x-api-key": "unit-test-api-key"},
        json={
            "event_type": "detection.alert",
            "source": "unit-test",
            "severity": "HIGH",
            "payload": {"technique_id": "T1059"},
        },
    )
    queried = client.get(
        "/api/events",
        headers={"x-api-key": "unit-test-api-key"},
    )

    assert health.status_code == 200
    assert unauthenticated.status_code == 401
    assert published.status_code == 200
    assert published.json()["persisted"] is True
    assert queried.status_code == 200
    assert queried.json()["count"] == 1


def test_event_api_disables_data_routes_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("SHADOW313_EVENT_BUS_API_KEY", raising=False)
    publisher = SecureEventPublisher(tmp_path / "events.sqlite3")
    client = TestClient(publisher.build_app())

    response = client.get("/api/events")

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"].lower()


def test_event_api_rejects_invalid_severity_and_oversized_payload(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SHADOW313_EVENT_BUS_API_KEY", "unit-test-api-key")
    publisher = SecureEventPublisher(tmp_path / "events.sqlite3")
    client = TestClient(publisher.build_app())
    headers = {"x-api-key": "unit-test-api-key"}

    invalid_severity = client.post(
        "/api/events/publish",
        headers=headers,
        json={"severity": "PANIC", "payload": {}},
    )
    oversized = client.post(
        "/api/events/publish",
        headers=headers,
        json={"payload": {"sample": "x" * (65 * 1024)}},
    )

    assert invalid_severity.status_code == 422
    assert oversized.status_code == 413
