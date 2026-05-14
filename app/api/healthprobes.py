from __future__ import annotations

from datetime import UTC, datetime
from time import monotonic

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.dependencies.action_execute import get_action_execute_pipeline

SERVICE_NAME = "ironclaw-security"
SERVICE_VERSION = "1.0.0"
PROCESS_STARTED_AT = monotonic()

router = APIRouter(tags=["system"])


class ComponentStatus(BaseModel):
    name: str
    status: str
    details: dict[str, object] = Field(default_factory=dict)


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
    ready: bool
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


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _uptime_seconds() -> int:
    return max(0, int(monotonic() - PROCESS_STARTED_AT))


def _readiness_checks() -> list[ComponentStatus]:
    pipeline_ok = get_action_execute_pipeline() is not None
    return [
        ComponentStatus(
            name="action_execute_pipeline",
            status="ok" if pipeline_ok else "unavailable",
            details={"initialized": pipeline_ok},
        ),
        ComponentStatus(
            name="api_router",
            status="ok",
            details={"registered": True},
        ),
        ComponentStatus(
            name="process",
            status="ok",
            details={"uptime_seconds": _uptime_seconds()},
        ),
    ]


@router.get(
    "/system/live",
    response_model=LivenessResponse,
    summary="Liveness probe",
    description="Fast, dependency-light probe that answers: is the process alive and serving requests?",
)
def get_liveness() -> LivenessResponse:
    return LivenessResponse(
        status="ok",
        service=SERVICE_NAME,
        version=SERVICE_VERSION,
        timestamp=_timestamp(),
        uptime_seconds=_uptime_seconds(),
    )


@router.get(
    "/system/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    description="Readiness probe that checks whether core in-process services initialized enough to safely receive traffic.",
)
def get_readiness() -> ReadinessResponse:
    checks = _readiness_checks()
    ready = all(check.status == "ok" for check in checks)
    return ReadinessResponse(
        status="ok" if ready else "degraded",
        service=SERVICE_NAME,
        version=SERVICE_VERSION,
        timestamp=_timestamp(),
        uptime_seconds=_uptime_seconds(),
        ready=ready,
        checks=checks,
    )


@router.get(
    "/system/health",
    response_model=HealthResponse,
    summary="Combined health snapshot",
    description="Combined operational health snapshot for dashboards and lightweight UI polling.",
)
def get_health() -> HealthResponse:
    checks = _readiness_checks()
    ready = all(check.status == "ok" for check in checks)
    return HealthResponse(
        status="ok" if ready else "degraded",
        service=SERVICE_NAME,
        version=SERVICE_VERSION,
        timestamp=_timestamp(),
        uptime_seconds=_uptime_seconds(),
        live=True,
        ready=ready,
        checks=checks,
    )
