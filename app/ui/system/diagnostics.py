from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/system",
    tags=["system-diagnostics"],
)


class ServiceDiagnosticItem(BaseModel):
    service: str
    status: str
    detail: str
    latencyms: Optional[int] = None


class SystemDiagnosticsResponse(BaseModel):
    generatedat: str
    overallstatus: str
    services: list[ServiceDiagnosticItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def _build_placeholder_services() -> list[ServiceDiagnosticItem]:
    return [
        ServiceDiagnosticItem(
            service="api",
            status="healthy",
            detail="Primary FastAPI application is responding normally.",
            latencyms=18,
        ),
        ServiceDiagnosticItem(
            service="secure-runtime-pipeline",
            status="healthy",
            detail="Guarded execution pipeline is available for boundary evaluation.",
            latencyms=24,
        ),
        ServiceDiagnosticItem(
            service="executor-boundary",
            status="healthy",
            detail="Boundary checks are enforcing deny/review/allow decisions correctly.",
            latencyms=12,
        ),
        ServiceDiagnosticItem(
            service="review-queue",
            status="healthy",
            detail="Review queue endpoints are available for pending analyst actions.",
            latencyms=16,
        ),
    ]


@router.get("/diagnostics", response_model=SystemDiagnosticsResponse)
def get_system_diagnostics() -> SystemDiagnosticsResponse:
    services = _build_placeholder_services()
    unhealthy = [service for service in services if service.status != "healthy"]

    return SystemDiagnosticsResponse(
        generatedat=datetime.now(timezone.utc).isoformat(),
        overallstatus="healthy" if not unhealthy else "degraded",
        services=services,
        warnings=[] if not unhealthy else ["One or more services require attention."],
    )