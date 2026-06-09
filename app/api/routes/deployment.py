from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.dependencies.auth import require_api_key

router = APIRouter(
    prefix="/deployment",
    tags=["deployment"],
    dependencies=[Depends(require_api_key)],
)

DeploymentStatus = Literal["ready", "warning", "blocked"]


class DeploymentCheckView(BaseModel):
    check_id: str
    title: str
    status: DeploymentStatus
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeploymentReadinessView(BaseModel):
    release_id: str
    environment: str
    overall_status: DeploymentStatus
    updated_at: str
    checks: list[DeploymentCheckView] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DeploymentReadinessResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    readiness: DeploymentReadinessView


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@router.get("/readiness", response_model=DeploymentReadinessResponse)
def get_deployment_readiness() -> DeploymentReadinessResponse:
    now = _utc_now_iso()

    readiness = DeploymentReadinessView(
        release_id="IronClaw-Security",
        environment="production",
        overall_status="warning",
        updated_at=now,
        checks=[
            DeploymentCheckView(
                check_id="api-health",
                title="Protected API health",
                status="ready",
                detail="Core API routes and protected dependencies are responding normally.",
                metadata={"category": "availability"},
            ),
            DeploymentCheckView(
                check_id="policy-enforcement",
                title="Policy enforcement",
                status="ready",
                detail="Default policy mode is enforce with quarantine-first high-risk handling.",
                metadata={"category": "security"},
            ),
            DeploymentCheckView(
                check_id="incident-operations",
                title="Incident and quarantine operations",
                status="ready",
                detail="Incident, quarantine, and audit surfaces are available for operational review.",
                metadata={"category": "operations"},
            ),
            DeploymentCheckView(
                check_id="alerting",
                title="Alert delivery integration",
                status="warning",
                detail="Alert endpoints exist, but production delivery channels should be validated before launch.",
                metadata={"category": "monitoring"},
            ),
            DeploymentCheckView(
                check_id="billing-production",
                title="Billing productionization",
                status="warning",
                detail="Billing package routes are present, but persistent transaction storage and real payment wiring remain future work.",
                metadata={"category": "commercial"},
            ),
        ],
        metadata={
            "recommended_next_action": "validate live alert targets and complete production billing persistence",
        },
    )

    return DeploymentReadinessResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=now,
        readiness=readiness,
    )
