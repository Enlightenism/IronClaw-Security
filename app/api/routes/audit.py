from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.services.audit_store import (
    AuditEventRecord as StoredAuditEventRecord,
    get_audit_store,
)


router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    dependencies=[Depends(require_api_key)],
)


class AuditEventView(BaseModel):
    event_id: str
    event_type: str
    severity: str
    created_at: str
    actor_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    integration_id: str | None = None
    verdict: str | None = None
    summary: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditEventListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[AuditEventView] = Field(default_factory=list)


class AuditEventCreateRequest(BaseModel):
    event_type: str = Field(min_length=1, max_length=120)
    severity: str = Field(min_length=1, max_length=40)
    summary: str = Field(min_length=3, max_length=2000)
    actor_id: str | None = Field(default=None, max_length=120)
    session_id: str | None = Field(default=None, max_length=120)
    request_id: str | None = Field(default=None, max_length=200)
    trace_id: str | None = Field(default=None, max_length=200)
    integration_id: str | None = Field(default=None, max_length=120)
    verdict: str | None = Field(default=None, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditEventResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    event: AuditEventView


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _to_view(item: StoredAuditEventRecord) -> AuditEventView:
    return AuditEventView(**item.to_dict())


@router.get("/events", response_model=AuditEventListResponse)
def list_audit_events(
    actor_id: str | None = Query(default=None),
    request_id: str | None = Query(default=None),
    trace_id: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> AuditEventListResponse:
    items = get_audit_store().list_events(
        actor_id=actor_id,
        request_id=request_id,
        trace_id=trace_id,
        verdict=verdict,
        event_type=event_type,
        limit=limit,
    )

    return AuditEventListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(items),
        items=[_to_view(item) for item in items],
    )


@router.post("/events", response_model=AuditEventResponse)
def create_audit_event(payload: AuditEventCreateRequest) -> AuditEventResponse:
    event = get_audit_store().create_event(
        event_type=payload.event_type,
        severity=payload.severity,
        summary=payload.summary,
        actor_id=payload.actor_id,
        session_id=payload.session_id,
        request_id=payload.request_id,
        trace_id=payload.trace_id,
        integration_id=payload.integration_id,
        verdict=payload.verdict,
        metadata=payload.metadata,
    )

    return AuditEventResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        event=_to_view(event),
    )


@router.get("/events/by-actor/{actor_id}", response_model=list[AuditEventView])
def list_audit_events_by_actor(actor_id: str) -> list[AuditEventView]:
    return [_to_view(item) for item in get_audit_store().get_by_actor(actor_id)]


@router.get("/events/by-request/{request_id}", response_model=list[AuditEventView])
def list_audit_events_by_request(request_id: str) -> list[AuditEventView]:
    return [_to_view(item) for item in get_audit_store().get_by_request(request_id)]


@router.get("/events/by-trace/{trace_id}", response_model=list[AuditEventView])
def list_audit_events_by_trace(trace_id: str) -> list[AuditEventView]:
    return [_to_view(item) for item in get_audit_store().get_by_trace(trace_id)]