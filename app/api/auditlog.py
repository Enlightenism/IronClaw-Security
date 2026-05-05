from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from app.dependencies.auth import require_api_key
from app.services.auditlogservice import AuditLogService, get_audit_log_service

router = APIRouter(
    prefix="/api/audit",
    tags=["audit"],
    dependencies=[Depends(require_api_key)],
)


@router.get(
    "/events",
    summary="List Audit Events",
    response_model=dict,
)
def list_audit_events(
    actorid: str | None = Query(default=None, alias="actorid"),
    requestid: str | None = Query(default=None, alias="requestid"),
    traceid: str | None = Query(default=None, alias="traceid"),
    verdict: str | None = Query(default=None, alias="verdict"),
    eventtype: str | None = Query(default=None, alias="eventtype"),
    limit: int = Query(default=100, ge=1, le=500),
    service: AuditLogService = Depends(get_audit_log_service),
) -> dict[str, Any]:
    return service.list_events(
        actorid=actorid,
        requestid=requestid,
        traceid=traceid,
        verdict=verdict,
        eventtype=eventtype,
        limit=limit,
    )


@router.post(
    "/events",
    summary="Create Audit Event",
    response_model=dict,
)
def create_audit_event(
    payload: dict[str, Any],
    service: AuditLogService = Depends(get_audit_log_service),
) -> dict[str, Any]:
    return service.create_event(payload)


@router.get(
    "/events/by-actor/{actorid}",
    summary="List Audit Events By Actor",
    response_model=list[dict[str, Any]],
)
def list_audit_events_by_actor(
    actorid: str,
    service: AuditLogService = Depends(get_audit_log_service),
) -> list[dict[str, Any]]:
    return service.list_events_by_actor(actorid)


@router.get(
    "/events/by-request/{requestid}",
    summary="List Audit Events By Request",
    response_model=list[dict[str, Any]],
)
def list_audit_events_by_request(
    requestid: str,
    service: AuditLogService = Depends(get_audit_log_service),
) -> list[dict[str, Any]]:
    return service.list_events_by_request(requestid)


@router.get(
    "/events/by-trace/{traceid}",
    summary="List Audit Events By Trace",
    response_model=list[dict[str, Any]],
)
def list_audit_events_by_trace(
    traceid: str,
    service: AuditLogService = Depends(get_audit_log_service),
) -> list[dict[str, Any]]:
    return service.list_events_by_trace(traceid)