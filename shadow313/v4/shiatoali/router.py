"""FastAPI routes for the ShiatoAli SOC event and alert service."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from shadow313.v4.shiatoali.service import EventInput, ShiatoAliStore


def _model_payload(model: BaseModel) -> dict[str, Any]:
    """Serialize request models across supported Pydantic major versions."""
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=10000)
    priority: str = "medium"
    created_by: str = Field(default="analyst", max_length=255)
    alert_id: str | None = None


class CaseUpdateRequest(BaseModel):
    actor: str = Field(default="analyst", max_length=255)
    status: str | None = None
    assignee: str | None = Field(default=None, max_length=255)
    note: str | None = Field(default=None, max_length=5000)


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
            return store.ingest(EventInput(**_model_payload(request)))
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
        since: datetime | None = Query(default=None),
        order: str = Query(default="desc", pattern="^(asc|desc)$"),
    ) -> dict[str, Any]:
        items = store.list_alerts(
            limit=limit,
            offset=offset,
            since=since,
            order=order,
        )
        return {
            "items": items,
            "limit": limit,
            "offset": offset,
            "since": since.isoformat() if since else None,
            "order": order,
        }

    @router.post("/cases", status_code=201)
    async def create_case(request: CaseCreateRequest) -> dict[str, Any]:
        try:
            return store.create_case(**_model_payload(request))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.get("/cases")
    async def list_cases(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        items = store.list_cases(limit=limit, offset=offset)
        return {"items": items, "limit": limit, "offset": offset}

    @router.get("/cases/{case_id}")
    async def get_case(case_id: str) -> dict[str, Any]:
        case = store.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case not found")
        return case

    @router.patch("/cases/{case_id}")
    async def update_case(case_id: str, request: CaseUpdateRequest) -> dict[str, Any]:
        try:
            return store.update_case(case_id, **_model_payload(request))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="case not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return router
