from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.core.auth import get_api_key
from app.services.auditstore import (
    create_audit_event as create_audit_event_record,
)
from app.services.auditstore import (
    list_audit_events,
    list_audit_events_by_actor,
    list_audit_events_by_request,
    list_audit_events_by_trace,
)

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    dependencies=[get_api_key],
)


class AuditEventCreateRequest(BaseModel):
    actor_id: str | None = Field(default=None, max_length=200)
    request_id: str | None = Field(default=None, max_length=200)
    trace_id: str | None = Field(default=None, max_length=200)
    event_type: str = Field(min_length=1, max_length=120)
    verdict: str | None = Field(default=None, max_length=120)
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    message: str = Field(min_length=1, max_length=4000)
    metadata: dict[str, object] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class AuditEventView(BaseModel):
    event_id: str
    timestamp: str
    actor_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    event_type: str
    verdict: str | None = None
    severity: str | None = None
    message: str
    metadata: dict[str, object] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class AuditEventListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[AuditEventView]

    model_config = ConfigDict(extra="allow")


class AuditEventResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    item: AuditEventView

    model_config = ConfigDict(extra="allow")


@router.get(
    "/events",
    response_model=AuditEventListResponse,
    summary="List Audit Events",
)
def list_audit_events_route(
    actor_id: str | None = Query(default=None),
    request_id: str | None = Query(default=None),
    trace_id: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> AuditEventListResponse:
    response = list_audit_events(
        actor_id=actor_id,
        request_id=request_id,
        trace_id=trace_id,
        verdict=verdict,
        event_type=event_type,
        limit=limit,
    )
    return AuditEventListResponse.model_validate(response)


@router.post(
    "/events",
    response_model=AuditEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Create Audit Event",
)
def create_audit_event_route(payload: AuditEventCreateRequest) -> AuditEventResponse:
    response = create_audit_event_record(payload.model_dump())
    return AuditEventResponse.model_validate(response)


@router.get(
    "/events/by-actor/{actor_id}",
    response_model=list[AuditEventView],
    summary="List Audit Events By Actor",
)
def list_audit_events_by_actor_route(actor_id: str) -> list[AuditEventView]:
    items = list_audit_events_by_actor(actor_id)
    return [AuditEventView.model_validate(item) for item in items]


@router.get(
    "/events/by-request/{request_id}",
    response_model=list[AuditEventView],
    summary="List Audit Events By Request",
)
def list_audit_events_by_request_route(request_id: str) -> list[AuditEventView]:
    items = list_audit_events_by_request(request_id)
    return [AuditEventView.model_validate(item) for item in items]


@router.get(
    "/events/by-trace/{trace_id}",
    response_model=list[AuditEventView],
    summary="List Audit Events By Trace",
)
def list_audit_events_by_trace_route(trace_id: str) -> list[AuditEventView]:
    items = list_audit_events_by_trace(trace_id)
    return [AuditEventView.model_validate(item) for item in items]
