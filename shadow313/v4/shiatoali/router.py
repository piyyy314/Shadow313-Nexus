"""FastAPI routes for the ShiatoAli SOC event and alert service."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

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
    alert_id: str | None = None

    model_config = ConfigDict(extra="forbid")


class CaseUpdateRequest(BaseModel):
    status: str | None = None
    assignee: str | None = Field(default=None, max_length=255)
    note: str | None = Field(default=None, max_length=5000)

    model_config = ConfigDict(extra="forbid")


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
        return await run_in_threadpool(store.health)

    @router.post("/events", status_code=202)
    async def ingest_event(request: EventRequest) -> dict[str, Any]:
        try:
            event = EventInput(**_model_payload(request))
            return await run_in_threadpool(store.ingest, event)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.get("/events")
    async def list_events(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        items = await run_in_threadpool(
            store.list_events,
            limit=limit,
            offset=offset,
        )
        return {"items": items, "limit": limit, "offset": offset}

    @router.get("/alerts")
    async def list_alerts(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        since: Annotated[datetime | None, Query()] = None,
        order: Annotated[str, Query()] = "desc",
    ) -> dict[str, Any]:
        if order not in {"asc", "desc"}:
            raise HTTPException(status_code=422, detail="order must be asc or desc")
        items = await run_in_threadpool(
            store.list_alerts,
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
    async def create_case(
        request: CaseCreateRequest,
        actor: str = Depends(auth_dependency),
    ) -> dict[str, Any]:
        try:
            payload = _model_payload(request)
            payload["created_by"] = actor
            return await run_in_threadpool(store.create_case, **payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.get("/cases")
    async def list_cases(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        items = await run_in_threadpool(
            store.list_cases,
            limit=limit,
            offset=offset,
        )
        return {"items": items, "limit": limit, "offset": offset}

    @router.get("/cases/{case_id}")
    async def get_case(case_id: str) -> dict[str, Any]:
        case = await run_in_threadpool(store.get_case, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="case not found")
        return case

    @router.patch("/cases/{case_id}")
    async def update_case(
        case_id: str,
        request: CaseUpdateRequest,
        actor: str = Depends(auth_dependency),
    ) -> dict[str, Any]:
        try:
            payload = _model_payload(request)
            payload["actor"] = actor
            return await run_in_threadpool(store.update_case, case_id, **payload)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="case not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return router
