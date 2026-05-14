from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/health-snapshot", tags=["health-snapshot"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class HealthSignalView(BaseModel):
    label: str
    status: str
    detail: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class HealthDependencyView(BaseModel):
    dependency: str
    status: str
    latency_ms: float
    required: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class HealthSnapshotSummaryView(BaseModel):
    overall_status: str
    readiness: str
    liveness: str
    environment: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class HealthSnapshotLinkView(BaseModel):
    label: str
    path: str
    description: str


class HealthSnapshotResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    summary: HealthSnapshotSummaryView
    signals: list[HealthSignalView] = Field(default_factory=list)
    dependencies: list[HealthDependencyView] = Field(default_factory=list)
    links: list[HealthSnapshotLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_signals() -> list[HealthSignalView]:
    return [
        HealthSignalView(
            label="API liveness",
            status="ok",
            detail="Process is available and serving requests.",
            metadata={"source": "health-snapshot-ui"},
        ),
        HealthSignalView(
            label="Runtime readiness",
            status="ok",
            detail="Core in-process services are initialized.",
            metadata={"source": "health-snapshot-ui"},
        ),
        HealthSignalView(
            label="Policy guard state",
            status="ok",
            detail="Guarded routing is available in default mode.",
            metadata={"source": "health-snapshot-ui"},
        ),
    ]


def _build_dependencies() -> list[HealthDependencyView]:
    return [
        HealthDependencyView(
            dependency="Core API",
            status="healthy",
            latency_ms=0.0,
            required=True,
            metadata={"role": "primary-service"},
        ),
        HealthDependencyView(
            dependency="Prompt Guard",
            status="healthy",
            latency_ms=0.0,
            required=True,
            metadata={"role": "policy-service"},
        ),
        HealthDependencyView(
            dependency="Billing Wallet",
            status="healthy",
            latency_ms=0.0,
            required=False,
            metadata={"role": "support-service"},
        ),
    ]


def _build_links() -> list[HealthSnapshotLinkView]:
    return [
        HealthSnapshotLinkView(
            label="Runtime status",
            path="/ui/runtime-status",
            description="Runtime health and readiness overview.",
        ),
        HealthSnapshotLinkView(
            label="System diagnostics",
            path="/ui/system-diagnostics",
            description="Expanded diagnostic details and troubleshooting signals.",
        ),
        HealthSnapshotLinkView(
            label="Metrics summary",
            path="/ui/metrics-summary",
            description="Operational KPI and latency snapshot.",
        ),
        HealthSnapshotLinkView(
            label="Telemetry access summary",
            path="/ui/telemetry-access-summary",
            description="Telemetry visibility and recent access context.",
        ),
    ]


@router.get("", response_model=HealthSnapshotResponse)
def get_health_snapshot() -> HealthSnapshotResponse:
    return HealthSnapshotResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        summary=HealthSnapshotSummaryView(
            overall_status="healthy",
            readiness="ready",
            liveness="live",
            environment="local",
            metadata={
                "ui_surface": "health-snapshot",
                "default_mode": "safe-static",
            },
        ),
        signals=_build_signals(),
        dependencies=_build_dependencies(),
        links=_build_links(),
        notes=[
            "Health snapshot provides a compact UI-facing summary of current service health.",
            "This Gen1 page returns a stable default structure until live health hydration is connected.",
            "The response contract is designed to support future readiness, liveness, and dependency enrichment.",
        ],
    )
