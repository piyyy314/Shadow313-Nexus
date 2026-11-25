"""shadow313.api — FastAPI REST interface for Shadow313 NEXUS.

The public API's event routes are backed by the canonical persistent platform
event store rather than a disconnected in-memory placeholder.
"""
from __future__ import annotations

import json
import os
from typing import Any

from fastapi import Depends, HTTPException, Query, Request

from .access import authorize
from . import server as _server
from shadow313_platform.event_bus import PlatformEvent, get_event_bus

_original_create_app = _server.create_app
VALID_EVENT_SEVERITIES = {"INFO", "MEDIUM", "HIGH", "CRITICAL"}


def create_app(api_key: str | None = None):
    """Create the main API and bind its event routes to the durable event bus."""
    app = _original_create_app(api_key)
    resolved_api_key = api_key or os.environ.get("SHADOW313_API_KEY")

    def verify_event_access(request: Request) -> None:
        authorize(request, resolved_api_key)

    app.router.routes = [
        route
        for route in app.router.routes
        if not (
            getattr(route, "path", None) == "/api/events"
            and "GET" in getattr(route, "methods", set())
        )
    ]

    async def list_events(
        event_type: str | None = None,
        severity: str | None = None,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        events = get_event_bus().get_events(event_type, severity, limit)
        return {
            "status": "ok",
            "storage": "sqlite",
            "count": len(events),
            "events": [event.to_dict() for event in events],
        }

    async def publish_event(body: dict) -> dict[str, Any]:
        if len(json.dumps(body, default=str).encode("utf-8")) > 64 * 1024:
            raise HTTPException(status_code=413, detail="Event payload exceeds 64 KiB")
        event_type = body.get("event_type", "generic")
        source = body.get("source", "api")
        severity = str(body.get("severity", "INFO")).upper()
        payload = body.get("payload", {})
        bind_id = body.get("bind_id")
        if (
            not isinstance(event_type, str)
            or not 1 <= len(event_type) <= 128
            or any(ord(character) < 32 for character in event_type)
        ):
            raise HTTPException(status_code=422, detail="Invalid event_type")
        if (
            not isinstance(source, str)
            or not 1 <= len(source) <= 128
            or any(ord(character) < 32 for character in source)
        ):
            raise HTTPException(status_code=422, detail="Invalid source")
        if severity not in VALID_EVENT_SEVERITIES:
            raise HTTPException(status_code=422, detail="Invalid severity")
        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=422,
                detail="Event payload must be an object",
            )
        if bind_id is not None and (
            not isinstance(bind_id, str) or len(bind_id) > 128
        ):
            raise HTTPException(status_code=422, detail="Invalid bind_id")

        event = PlatformEvent(
            event_type=event_type,
            source=source,
            severity=severity,
            payload=payload,
            bind_id=bind_id,
        )
        get_event_bus().publish(event)
        return {
            "status": "published",
            "event_id": event.event_id,
            "persisted": True,
            "storage": "sqlite",
        }

    async def event_stats() -> dict[str, Any]:
        return get_event_bus().stats()

    app.add_api_route(
        "/api/events",
        list_events,
        methods=["GET"],
        dependencies=[Depends(verify_event_access)],
        name="list_persisted_events",
    )
    app.add_api_route(
        "/api/events",
        publish_event,
        methods=["POST"],
        dependencies=[Depends(verify_event_access)],
        name="publish_persisted_event",
    )
    app.add_api_route(
        "/api/events/stats",
        event_stats,
        methods=["GET"],
        dependencies=[Depends(verify_event_access)],
        name="persisted_event_stats",
    )
    return app


# Preserve the historical import path: create_app from shadow313.api.server.
_server.create_app = create_app
