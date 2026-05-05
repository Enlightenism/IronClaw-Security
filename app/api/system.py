from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from app.services.review_queue_service import get_review_queue_summary
from app.services.telemetry import (
    append_telemetry_event,
    read_telemetry_events,
    summarize_telemetry_events,
)

router = APIRouter(prefix="/system", tags=["system"])

SERVICE_NAME = "IronClaw-Security"
SERVICE_VERSION = "1.0.0"
DEGRADED_STATUS = "degraded"
OK_STATUS = "ok"
START_TIME = datetime.now(UTC)


class ComponentStatus(BaseModel):
    name: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class LivenessResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str
    uptime_seconds: int


class ReadinessResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str
    uptime_seconds: int
    checks: list[ComponentStatus]


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str
    uptime_seconds: int
    live: bool
    ready: bool
    checks: list[ComponentStatus]


class MetricsSummaryResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str
    uptime_seconds: int
    telemetry_summary: dict[str, Any]
    review_summary: dict[str, Any]
    recent_telemetry_events: list[dict[str, Any]]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _uptime_seconds() -> int:
    return max(0, int((_utc_now() - START_TIME).total_seconds()))


def _base_response_fields() -> dict[str, Any]:
    return {
        "service": SERVICE_NAME,
        "version": _resolve_version(),
        "timestamp": _iso(_utc_now()),
        "uptime_seconds": _uptime_seconds(),
    }


def _safe_append_telemetry_event(event_name: str, payload: dict[str, Any]) -> None:
    try:
        append_telemetry_event(event_name, payload)
    except Exception:
        pass


def _resolve_version() -> str:
    return SERVICE_VERSION


@lru_cache(maxsize=1)
def _load_action_execute_pipeline_factory():
    from app.dependencies.action_execute import get_action_execute_pipeline

    return get_action_execute_pipeline


def _build_component_status(
    *,
    name: str,
    ok: bool,
    details: dict[str, Any],
) -> ComponentStatus:
    return ComponentStatus(
        name=name,
        status=OK_STATUS if ok else DEGRADED_STATUS,
        details=details,
    )


def _build_readiness_checks() -> list[ComponentStatus]:
    checks: list[ComponentStatus] = []

    pipeline = None
    pipeline_close_available = False
    pipeline_ready = False
    pipeline_error: str | None = None
    try:
        get_action_execute_pipeline = _load_action_execute_pipeline_factory()
        pipeline = get_action_execute_pipeline()
        pipeline_ready = pipeline is not None
        pipeline_close_available = callable(getattr(pipeline, "close", None)) if pipeline is not None else False
    except Exception as exc:
        pipeline_error = str(exc)

    checks.append(
        _build_component_status(
            name="action_execute_pipeline",
            ok=pipeline_ready,
            details={
                "initialized": pipeline_ready,
                "close_supported": pipeline_close_available,
                **({"error": pipeline_error} if pipeline_error else {}),
            },
        )
    )

    telemetry_ok = True
    telemetry_error: str | None = None
    telemetry_recent_count = 0
    try:
        recent = read_telemetry_events(limit=5)
        telemetry_recent_count = len(recent)
    except Exception as exc:
        telemetry_ok = False
        telemetry_error = str(exc)

    checks.append(
        _build_component_status(
            name="telemetry_store",
            ok=telemetry_ok,
            details={
                "recent_events_checked": telemetry_recent_count,
                **({"error": telemetry_error} if telemetry_error else {}),
            },
        )
    )

    review_ok = True
    review_error: str | None = None
    review_summary: dict[str, Any] = {}
    try:
        review_summary = get_review_queue_summary()
    except Exception as exc:
        review_ok = False
        review_error = str(exc)

    checks.append(
        _build_component_status(
            name="review_queue",
            ok=review_ok,
            details={
                "pending_items": review_summary.get("pending_items"),
                "critical_items": review_summary.get("critical_items"),
                "total_items": review_summary.get("total_items"),
                **({"error": review_error} if review_error else {}),
            },
        )
    )

    return checks


def _overall_status_from_checks(checks: list[ComponentStatus]) -> tuple[str, bool]:
    ready = all(check.status == OK_STATUS for check in checks)
    return (OK_STATUS if ready else DEGRADED_STATUS, ready)


def _status_from_summary_payloads(*payloads: dict[str, Any]) -> str:
    degraded_values = {DEGRADED_STATUS, "error", "failed", "unavailable"}
    for payload in payloads:
        if payload.get("status") in degraded_values or "error" in payload:
            return DEGRADED_STATUS
    return OK_STATUS


@router.get("/live", response_model=LivenessResponse, summary="Liveness probe")
def get_liveness() -> LivenessResponse:
    """
    Fast, dependency-light probe that answers:
    is the process alive and serving requests?
    """
    response = LivenessResponse(
        status=OK_STATUS,
        **_base_response_fields(),
    )

    _safe_append_telemetry_event(
        "system_liveness_requested",
        {
            "status": response.status,
            "uptime_seconds": response.uptime_seconds,
        },
    )

    return response


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness probe")
def get_readiness(response: Response) -> ReadinessResponse:
    """
    Readiness probe that checks whether core in-process services
    are initialized enough to safely receive traffic.
    """
    checks = _build_readiness_checks()
    overall_status, ready = _overall_status_from_checks(checks)

    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    result = ReadinessResponse(
        status=overall_status,
        checks=checks,
        **_base_response_fields(),
    )

    _safe_append_telemetry_event(
        "system_readiness_requested",
        {
            "status": result.status,
            "ready": ready,
            "check_count": len(checks),
        },
    )

    return result


@router.get("/health", response_model=HealthResponse, summary="Combined health snapshot")
def get_health(response: Response) -> HealthResponse:
    """
    Combined operational health snapshot for dashboards and lightweight UI polling.
    """
    checks = _build_readiness_checks()
    overall_status, ready = _overall_status_from_checks(checks)

    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    result = HealthResponse(
        status=overall_status,
        live=True,
        ready=ready,
        checks=checks,
        **_base_response_fields(),
    )

    _safe_append_telemetry_event(
        "system_health_requested",
        {
            "status": result.status,
            "live": result.live,
            "ready": result.ready,
            "check_count": len(checks),
        },
    )

    return result


@router.get(
    "/metrics/summary",
    response_model=MetricsSummaryResponse,
    summary="Lightweight metrics and telemetry summary",
)
def get_metrics_summary() -> MetricsSummaryResponse:
    """
    Lightweight operational summary intended for internal dashboards.
    """
    telemetry_summary: dict[str, Any]
    try:
        telemetry_summary = summarize_telemetry_events(limit=500)
    except Exception as exc:
        telemetry_summary = {
            "status": DEGRADED_STATUS,
            "error": str(exc),
        }

    review_summary: dict[str, Any]
    try:
        review_summary = get_review_queue_summary()
    except Exception as exc:
        review_summary = {
            "status": DEGRADED_STATUS,
            "error": str(exc),
        }

    recent_events: list[dict[str, Any]]
    try:
        recent_events = read_telemetry_events(limit=25)
    except Exception as exc:
        recent_events = [
            {
                "type": "telemetry_read_error",
                "error": str(exc),
            }
        ]

    overall_status = _status_from_summary_payloads(telemetry_summary, review_summary)

    result = MetricsSummaryResponse(
        status=overall_status,
        telemetry_summary=telemetry_summary,
        review_summary=review_summary,
        recent_telemetry_events=recent_events,
        **_base_response_fields(),
    )

    _safe_append_telemetry_event(
        "system_metrics_summary_requested",
        {
            "status": result.status,
            "telemetry_event_count": len(recent_events),
            "has_review_summary": bool(review_summary),
        },
    )

    return result