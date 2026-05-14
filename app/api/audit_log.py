from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from app.services.audit_log_service import (
    list_audit_events,
    list_audit_events_for_actor,
    list_audit_events_for_request,
    list_audit_events_for_session,
    list_audit_events_for_trace,
)

router = APIRouter(prefix="/audit", tags=["audit-log"])


@router.get("/events", summary="List audit events.")
def get_audit_events(
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    return list_audit_events(limit=limit)


@router.get("/events/by-session/{session_id}", summary="Audit events by session.")
def get_audit_events_by_session(
    session_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    return list_audit_events_for_session(session_id=session_id, limit=limit)


@router.get("/events/by-actor/{actor_id}", summary="Audit events by actor.")
def get_audit_events_by_actor(
    actor_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    return list_audit_events_for_actor(actor_id=actor_id, limit=limit)


@router.get("/events/by-request/{request_id}", summary="Audit events by request.")
def get_audit_events_by_request(
    request_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    return list_audit_events_for_request(request_id=request_id)


@router.get("/events/by-trace/{trace_id}", summary="Audit events by trace.")
def get_audit_events_by_trace(
    trace_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    return list_audit_events_for_trace(trace_id=trace_id)


@router.get("/telemetry/events", summary="List telemetry events.")
def get_telemetry_events(
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    return {"telemetry_events": [], "limit": limit}


@router.get("/telemetry/summary", summary="Telemetry summary.")
def get_telemetry_summary(
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    return {"summary": [], "limit": limit}
