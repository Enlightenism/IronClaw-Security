from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from app.core.auth import require_api_key
from app.services.audit_log_service import (
    list_audit_events,
    list_audit_events_for_actor,
    list_audit_events_for_request,
    list_audit_events_for_session,
    list_audit_events_for_trace,
)
from app.services.telemetry import (
    append_telemetry_event,
    read_telemetry_events,
    summarize_telemetry_events,
)

router = APIRouter(
    prefix="/audit",
    tags=["audit-log"],
    dependencies=[Depends(require_api_key)],
)


@router.get("/events")
def get_audit_events(
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    append_telemetry_event(
        "audit_events_list_requested",
        {
            "limit": limit,
        },
    )
    return list_audit_events(limit=limit)


@router.get("/events/by-session/{session_id}")
def get_audit_events_by_session(
    session_id: str,
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    append_telemetry_event(
        "audit_events_by_session_requested",
        {
            "session_id": session_id,
            "limit": limit,
        },
    )
    return list_audit_events_for_session(session_id=session_id, limit=limit)


@router.get("/events/by-actor/{actor_id}")
def get_audit_events_by_actor(
    actor_id: str,
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    append_telemetry_event(
        "audit_events_by_actor_requested",
        {
            "actor_id": actor_id,
            "limit": limit,
        },
    )
    return list_audit_events_for_actor(actor_id=actor_id, limit=limit)


@router.get("/events/by-request/{request_id}")
def get_audit_events_by_request(request_id: str) -> list[dict[str, Any]]:
    append_telemetry_event(
        "audit_events_by_request_requested",
        {
            "request_id": request_id,
        },
    )
    return list_audit_events_for_request(request_id=request_id)


@router.get("/events/by-trace/{trace_id}")
def get_audit_events_by_trace(trace_id: str) -> list[dict[str, Any]]:
    append_telemetry_event(
        "audit_events_by_trace_requested",
        {
            "trace_id": trace_id,
        },
    )
    return list_audit_events_for_trace(trace_id=trace_id)


@router.get("/telemetry/events")
def get_telemetry_events(
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    append_telemetry_event(
        "telemetry_events_list_requested",
        {
            "limit": limit,
        },
    )
    return read_telemetry_events(limit=limit)


@router.get("/telemetry/summary")
def get_telemetry_summary(
    limit: int = Query(500, ge=1, le=5000),
) -> dict[str, Any]:
    append_telemetry_event(
        "telemetry_summary_requested",
        {
            "limit": limit,
        },
    )
    return summarize_telemetry_events(limit=limit)