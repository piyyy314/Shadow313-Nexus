"""FastAPI routes for the ShiatoAli SOC event and alert service."""
from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from shadow313.v4.shiatoali.service import EventInput, ShiatoAliStore


class EventRequest(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=100)
    message: str = Field(min_length=1, max_length=20_000)
    severity: str = "low"
    username: str | None = Field(default=None, max_length=255)
    src_ip: str | None = Field(default=None, max_length=64)
    timestamp: str | None = None
    event_id: str | None = Field(default=None, max_length=100)
    raw: dict[str, Any] = Field(default_factory=dict)


def build_router(auth_dependency: Callable[..., Any]) -> APIRouter:
    router = APIRouter(
        prefix="/api/shiatoali",
        tags=["ShiatoAli SOC"],
        dependencies=[Depends(auth_dependency)],
    )
    store = ShiatoAliStore()

    @router.get("/health")
    async def health() -> dict[str, Any]:
        return store.health()

    @router.post("/events", status_code=202)
    async def ingest_event(request: EventRequest) -> dict[str, Any]:
        try:
            return store.ingest(EventInput(**request.dict()))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.get("/events")
    async def list_events(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        items = store.list_events(limit=limit, offset=offset)
        return {"items": items, "limit": limit, "offset": offset}

    @router.get("/alerts")
    async def list_alerts(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        items = store.list_alerts(limit=limit, offset=offset)
        return {"items": items, "limit": limit, "offset": offset}

    return router
