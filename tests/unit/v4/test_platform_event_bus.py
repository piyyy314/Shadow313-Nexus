"""
Tests for platform.event_bus — EventPublisher, EventStore, PlatformEvent.
"""
from __future__ import annotations

import threading
import time
import pytest
from shadow313_platform.event_bus import (
    PlatformEvent,
    EventStore,
    EventPublisher,
    get_event_bus,
    publish,
)


# ── PlatformEvent tests ───────────────────────────────────────────────────────

class TestPlatformEvent:

    def test_default_fields(self):
        e = PlatformEvent()
        assert e.event_type == "generic"
        assert e.source == "unknown"
        assert e.severity == "INFO"
        assert e.event_id is not None
        assert e.timestamp is not None

    def test_custom_fields(self):
        e = PlatformEvent(
            event_type="detection.alert",
            source="beacon_detector",
            severity="HIGH",
            payload={"score": 0.85},
        )
        assert e.event_type == "detection.alert"
        assert e.severity == "HIGH"
        assert e.payload["score"] == 0.85

    def test_to_dict(self):
        e = PlatformEvent(event_type="test", severity="MEDIUM")
        d = e.to_dict()
        assert isinstance(d, dict)
        assert d["event_type"] == "test"
        assert d["severity"] == "MEDIUM"

    def test_to_json(self):
        e = PlatformEvent(event_type="test")
        j = e.to_json()
        assert isinstance(j, str)
        assert "test" in j

    def test_unique_event_ids(self):
        ids = {PlatformEvent().event_id for _ in range(100)}
        assert len(ids) == 100


# ── EventStore tests ──────────────────────────────────────────────────────────

class TestEventStore:

    def test_append_and_get_all(self):
        store = EventStore()
        e = PlatformEvent(event_type="test")
        store.append(e)
        assert len(store.get_all()) == 1

    def test_max_events_enforced(self):
        store = EventStore(max_events=10)
        for i in range(20):
            store.append(PlatformEvent(event_type=f"t{i}"))
        assert len(store.get_all()) == 10

    def test_get_by_type(self):
        store = EventStore()
        store.append(PlatformEvent(event_type="alpha"))
        store.append(PlatformEvent(event_type="beta"))
        store.append(PlatformEvent(event_type="alpha"))
        results = store.get_by_type("alpha")
        assert len(results) == 2

    def test_get_by_severity(self):
        store = EventStore()
        store.append(PlatformEvent(severity="HIGH"))
        store.append(PlatformEvent(severity="LOW"))
        results = store.get_by_severity("HIGH")
        assert len(results) == 1

    def test_get_recent(self):
        store = EventStore()
        for i in range(20):
            store.append(PlatformEvent(event_type=f"t{i}"))
        recent = store.get_recent(5)
        assert len(recent) == 5

    def test_clear(self):
        store = EventStore()
        store.append(PlatformEvent())
        store.clear()
        assert len(store) == 0

    def test_len(self):
        store = EventStore()
        for _ in range(7):
            store.append(PlatformEvent())
        assert len(store) == 7

    def test_thread_safe_append(self):
        store = EventStore()
        errors = []

        def worker():
            try:
                for _ in range(100):
                    store.append(PlatformEvent())
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(store) == 1000


# ── EventPublisher tests ──────────────────────────────────────────────────────

class TestEventPublisher:

    def test_publish_stores_event(self):
        bus = EventPublisher()
        e = PlatformEvent(event_type="test.event")
        bus.publish(e)
        events = bus.get_events()
        assert len(events) == 1

    def test_subscribe_and_receive(self):
        bus = EventPublisher()
        received = []
        bus.subscribe("detection.alert", lambda e: received.append(e))
        bus.publish(PlatformEvent(event_type="detection.alert", severity="HIGH"))
        assert len(received) == 1
        assert received[0].severity == "HIGH"

    def test_wildcard_subscriber(self):
        bus = EventPublisher()
        received = []
        bus.subscribe("*", lambda e: received.append(e))
        bus.publish(PlatformEvent(event_type="anything"))
        bus.publish(PlatformEvent(event_type="something_else"))
        assert len(received) == 2

    def test_unsubscribe(self):
        bus = EventPublisher()
        received = []
        handler = lambda e: received.append(e)
        bus.subscribe("test", handler)
        bus.publish(PlatformEvent(event_type="test"))
        bus.unsubscribe("test", handler)
        bus.publish(PlatformEvent(event_type="test"))
        assert len(received) == 1

    def test_publish_detection_severity_mapping(self):
        bus = EventPublisher()
        received = []
        bus.subscribe("detection.alert", lambda e: received.append(e))

        bus.publish_detection("test", "T1078", 0.90, {})
        bus.publish_detection("test", "T1078", 0.75, {})
        bus.publish_detection("test", "T1078", 0.50, {})
        bus.publish_detection("test", "T1078", 0.20, {})

        severities = [e.severity for e in received]
        assert "CRITICAL" in severities
        assert "HIGH" in severities
        assert "MEDIUM" in severities
        assert "INFO" in severities

    def test_get_events_filter_by_type(self):
        bus = EventPublisher()
        bus.publish(PlatformEvent(event_type="alpha"))
        bus.publish(PlatformEvent(event_type="beta"))
        bus.publish(PlatformEvent(event_type="alpha"))
        results = bus.get_events(event_type="alpha")
        assert len(results) == 2

    def test_get_events_filter_by_severity(self):
        bus = EventPublisher()
        bus.publish(PlatformEvent(severity="CRITICAL"))
        bus.publish(PlatformEvent(severity="INFO"))
        results = bus.get_events(severity="CRITICAL")
        assert len(results) == 1

    def test_stats(self):
        bus = EventPublisher()
        bus.publish(PlatformEvent(event_type="detection.alert", severity="HIGH"))
        bus.publish(PlatformEvent(event_type="detection.alert", severity="CRITICAL"))
        bus.publish(PlatformEvent(event_type="audit.receipt", severity="INFO"))
        stats = bus.stats()
        assert stats["total_events"] == 3
        assert "HIGH" in stats["by_severity"]
        assert "detection.alert" in stats["by_type"]

    def test_handler_exception_does_not_crash_bus(self):
        bus = EventPublisher()

        def bad_handler(e):
            raise ValueError("Handler error")

        bus.subscribe("test", bad_handler)
        # Should not raise
        bus.publish(PlatformEvent(event_type="test"))
        assert len(bus.get_events()) == 1

    def test_multiple_subscribers_same_type(self):
        bus = EventPublisher()
        r1, r2 = [], []
        bus.subscribe("test", lambda e: r1.append(e))
        bus.subscribe("test", lambda e: r2.append(e))
        bus.publish(PlatformEvent(event_type="test"))
        assert len(r1) == 1
        assert len(r2) == 1

    def test_module_level_get_event_bus_singleton(self):
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

    def test_module_level_publish(self):
        bus = get_event_bus()
        initial = len(bus.get_events())
        publish(PlatformEvent(event_type="module.test"))
        assert len(bus.get_events()) == initial + 1