"""
shadow313.platform.event_bus
─────────────────────────────
FastAPI-backed event bus for Shadow313 NEXUS platform events.
Provides publish/subscribe for detection findings, audit receipts,
and inter-module communication.

Fallback: pure-Python dataclass bus when FastAPI is unavailable.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger("shadow313.platform.event_bus")

# ── Optional FastAPI ──────────────────────────────────────────────────────────
try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.info("[!] FastAPI not installed. Run: pip install fastapi uvicorn")

# ── Event model ───────────────────────────────────────────────────────────────
@dataclass
class PlatformEvent:
    """A single platform event published to the bus."""
    event_id:   str = field(default_factory=lambda: str(uuid4()))
    event_type: str = "generic"
    source:     str = "unknown"
    severity:   str = "INFO"          # INFO / MEDIUM / HIGH / CRITICAL
    payload:    Dict[str, Any] = field(default_factory=dict)
    timestamp:  str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    bind_id:    Optional[str] = None  # 313-BIND receipt ID if available

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# ── Event store ───────────────────────────────────────────────────────────────
class EventStore:
    """Thread-safe in-memory event store with optional persistence."""

    def __init__(self, max_events: int = 10_000):
        self._events: List[PlatformEvent] = []
        self._lock = threading.RLock()
        self._max = max_events

    def append(self, event: PlatformEvent) -> None:
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max:
                self._events = self._events[-self._max:]

    def get_all(self) -> List[PlatformEvent]:
        with self._lock:
            return list(self._events)

    def get_by_type(self, event_type: str) -> List[PlatformEvent]:
        with self._lock:
            return [e for e in self._events if e.event_type == event_type]

    def get_by_severity(self, severity: str) -> List[PlatformEvent]:
        with self._lock:
            return [e for e in self._events if e.severity == severity]

    def get_recent(self, n: int = 100) -> List[PlatformEvent]:
        with self._lock:
            return list(self._events[-n:])

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


# ── Event publisher ───────────────────────────────────────────────────────────
class EventPublisher:
    """
    Publish/subscribe event bus for Shadow313 NEXUS.

    Usage:
        bus = EventPublisher()
        bus.subscribe("detection.alert", my_handler)
        bus.publish(PlatformEvent(event_type="detection.alert", ...))
    """

    def __init__(self):
        self._store = EventStore()
        self._subscribers: Dict[str, List[Callable]] = {}
        self._lock = threading.RLock()
        self._app: Optional[Any] = None  # FastAPI app

    # ── Pub/Sub ───────────────────────────────────────────────────────────────

    def subscribe(self, event_type: str, handler: Callable) -> None:
        """Register a handler for a specific event type."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(handler)
        logger.debug("Subscribed %s to %s", handler.__name__, event_type)

    def unsubscribe(self, event_type: str, handler: Callable) -> None:
        """Remove a handler."""
        with self._lock:
            if event_type in self._subscribers:
                self._subscribers[event_type] = [
                    h for h in self._subscribers[event_type] if h != handler
                ]

    def publish(self, event: PlatformEvent) -> None:
        """Publish an event to all subscribers and store it."""
        self._store.append(event)
        with self._lock:
            handlers = list(self._subscribers.get(event.event_type, []))
            # Also notify wildcard subscribers
            handlers += list(self._subscribers.get("*", []))

        for handler in handlers:
            try:
                handler(event)
            except Exception as exc:
                logger.warning("Handler %s failed: %s", handler.__name__, exc)

    def publish_detection(
        self,
        source: str,
        technique_id: str,
        score: float,
        details: dict,
        bind_id: Optional[str] = None,
    ) -> PlatformEvent:
        """Convenience method for publishing detection events."""
        severity = (
            "CRITICAL" if score >= 0.85 else
            "HIGH"     if score >= 0.70 else
            "MEDIUM"   if score >= 0.45 else
            "INFO"
        )
        event = PlatformEvent(
            event_type="detection.alert",
            source=source,
            severity=severity,
            payload={
                "technique_id": technique_id,
                "score": score,
                "details": details,
            },
            bind_id=bind_id,
        )
        self.publish(event)
        return event

    # ── Query ─────────────────────────────────────────────────────────────────

    def get_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[PlatformEvent]:
        """Query stored events with optional filters."""
        events = self._store.get_all()
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if severity:
            events = [e for e in events if e.severity == severity]
        return events[-limit:]

    def stats(self) -> dict:
        """Return bus statistics."""
        all_events = self._store.get_all()
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for e in all_events:
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        return {
            "total_events": len(all_events),
            "by_severity": by_severity,
            "by_type": by_type,
            "subscribers": {k: len(v) for k, v in self._subscribers.items()},
        }

    # ── FastAPI REST API ──────────────────────────────────────────────────────

    def build_app(self) -> Any:
        """Build and return a FastAPI app exposing the event bus."""
        if not FASTAPI_AVAILABLE:
            raise RuntimeError("FastAPI not installed. pip install fastapi uvicorn")

        app = FastAPI(
            title="Shadow313 NEXUS Event Bus",
            description="Platform event bus for Shadow313 detection findings",
            version="4.0.0",
        )

        @app.get("/api/events")
        async def get_events(
            event_type: Optional[str] = None,
            severity: Optional[str] = None,
            limit: int = 100,
        ):
            events = self.get_events(event_type, severity, limit)
            return {"events": [e.to_dict() for e in events], "count": len(events)}

        @app.get("/api/events/stats")
        async def get_stats():
            return self.get_stats()

        @app.post("/api/events/publish")
        async def publish_event(body: dict):
            event = PlatformEvent(
                event_type=body.get("event_type", "generic"),
                source=body.get("source", "api"),
                severity=body.get("severity", "INFO"),
                payload=body.get("payload", {}),
            )
            self.publish(event)
            return {"status": "published", "event_id": event.event_id}

        @app.get("/api/health")
        async def health():
            return {
                "status": "healthy",
                "platform": "Shadow313 NEXUS",
                "version": "4.0.0",
                "events_stored": len(self._store),
            }

        self._app = app
        return app

    def serve(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        """Start the FastAPI server (blocking)."""
        app = self.build_app()
        uvicorn.run(app, host=host, port=port)


# ── Module-level singleton ────────────────────────────────────────────────────
_default_bus: Optional[EventPublisher] = None


def get_event_bus() -> EventPublisher:
    """Get or create the default module-level event bus."""
    global _default_bus
    if _default_bus is None:
        _default_bus = EventPublisher()
    return _default_bus


def publish(event: PlatformEvent) -> None:
    """Publish to the default bus."""
    get_event_bus().publish(event)