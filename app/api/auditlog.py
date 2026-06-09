from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.dependencies.auth import require_access_dependency
from app.services.auditlogservice import AuditLogService, build_audit_log_service

_audit_read_dep = require_access_dependency(action="audit:read", permission="audit:read")
_audit_write_dep = require_access_dependency(action="audit:write", permission="audit:write")

_SERVICE_SINGLETON: AuditLogService | None = None


def _get_service() -> AuditLogService:
    global _SERVICE_SINGLETON
    if _SERVICE_SINGLETON is None:
        _SERVICE_SINGLETON = build_audit_log_service()
    return _SERVICE_SINGLETON


router = APIRouter(
    prefix="/api/audit",
    tags=["audit"],
)


@router.get(
    "/events",
    summary="List Audit Events",
    response_model=dict,
    dependencies=[Depends(_audit_read_dep)],
)
def list_audit_events(
    actorid: str | None = Query(default=None, alias="actorid"),
    requestid: str | None = Query(default=None, alias="requestid"),
    traceid: str | None = Query(default=None, alias="traceid"),
    verdict: str | None = Query(default=None, alias="verdict"),
    eventtype: str | None = Query(default=None, alias="eventtype"),
    limit: int = Query(default=100, ge=1, le=500),
    service: AuditLogService = Depends(_get_service),
) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    if actorid:
        filters["actor_id"] = actorid
    if requestid:
        filters["request_id"] = requestid
    if traceid:
        filters["trace_id"] = traceid
    if verdict:
        filters["result"] = verdict
    if eventtype:
        filters["action"] = eventtype

    events = service.list_logs(limit=limit, filters=filters or None)
    return {"events": events, "count": len(events)}


@router.post(
    "/events",
    summary="Create Audit Event",
    response_model=dict,
    dependencies=[Depends(_audit_write_dep)],
)
def create_audit_event(
    payload: dict[str, Any],
    service: AuditLogService = Depends(_get_service),
) -> dict[str, Any]:
    return service.write_log(payload)


@router.get(
    "/events/by-actor/{actorid}",
    summary="List Audit Events By Actor",
    response_model=list,
    dependencies=[Depends(_audit_read_dep)],
)
def list_audit_events_by_actor(
    actorid: str,
    limit: int = Query(default=100, ge=1, le=500),
    service: AuditLogService = Depends(_get_service),
) -> list[dict[str, Any]]:
    return service.list_logs(actor_id=actorid, limit=limit)


@router.get(
    "/events/by-request/{requestid}",
    summary="List Audit Events By Request",
    response_model=list,
    dependencies=[Depends(_audit_read_dep)],
)
def list_audit_events_by_request(
    requestid: str,
    limit: int = Query(default=100, ge=1, le=500),
    service: AuditLogService = Depends(_get_service),
) -> list[dict[str, Any]]:
    return service.list_logs(request_id=requestid, limit=limit)


@router.get(
    "/events/by-trace/{traceid}",
    summary="List Audit Events By Trace",
    response_model=list,
    dependencies=[Depends(_audit_read_dep)],
)
def list_audit_events_by_trace(
    traceid: str,
    limit: int = Query(default=100, ge=1, le=500),
    service: AuditLogService = Depends(_get_service),
) -> list[dict[str, Any]]:
    return service.list_logs(filters={"trace_id": traceid}, limit=limit)


@router.get(
    "/events/{log_id}",
    summary="Get Audit Event By ID",
    response_model=dict,
    dependencies=[Depends(_audit_read_dep)],
)
def get_audit_event(
    log_id: str,
    service: AuditLogService = Depends(_get_service),
) -> dict[str, Any]:
    record = service.get_log(log_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Audit event not found")
    return record


@router.get(
    "/summary",
    summary="Audit Log Summary",
    response_model=dict,
    dependencies=[Depends(_audit_read_dep)],
)
def get_audit_summary(
    organization_id: str | None = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=5000),
    service: AuditLogService = Depends(_get_service),
) -> dict[str, Any]:
    return service.summarize(organization_id=organization_id, limit=limit)
