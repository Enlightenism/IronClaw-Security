from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.dependencies.auth import require_access_dependency
from app.services.auditlogservice import AuditLogService, build_audit_log_service

_audit_read_dep = require_access_dependency(action="audit:read", permission="audit:read")
_audit_write_dep = require_access_dependency(action="audit:write", permission="audit:write")


@lru_cache(maxsize=1)
def _get_service() -> AuditLogService:
    return build_audit_log_service()


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
    "/actor/{actor_id}",
    summary="List Audit Events By Actor",
    response_model=list,
    dependencies=[Depends(_audit_read_dep)],
)
def list_audit_events_by_actor(
    actor_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    service: AuditLogService = Depends(_get_service),
) -> list[dict[str, Any]]:
    return service.list_logs(filters={"actor_id": actor_id}, limit=limit)


@router.get(
    "/request/{request_id}",
    summary="List Audit Events By Request",
    response_model=list,
    dependencies=[Depends(_audit_read_dep)],
)
def list_audit_events_by_request(
    request_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    service: AuditLogService = Depends(_get_service),
) -> list[dict[str, Any]]:
    return service.list_logs(filters={"request_id": request_id}, limit=limit)


@router.get(
    "/trace/{trace_id}",
    summary="List Audit Events By Trace",
    response_model=list,
    dependencies=[Depends(_audit_read_dep)],
)
def list_audit_events_by_trace(
    trace_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    service: AuditLogService = Depends(_get_service),
) -> list[dict[str, Any]]:
    return service.list_logs(filters={"trace_id": trace_id}, limit=limit)


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
