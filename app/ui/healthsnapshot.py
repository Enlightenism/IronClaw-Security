from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(tags=["health-snapshot"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class HealthSnapshotKpi(BaseModel):
    label: str
    value: str
    tone: str = "neutral"


class HealthSnapshotServiceStatus(BaseModel):
    name: str
    status: str
    detail: str
    tone: str = "neutral"


class HealthSnapshotSignal(BaseModel):
    label: str
    value: str
    tone: str = "neutral"


class HealthSnapshotSummary(BaseModel):
    title: str
    subtitle: str
    overall_status: str
    overall_tone: str
    generated_at: str


class HealthSnapshotResponse(BaseModel):
    title: str = "Health Snapshot"
    status: str = "ok"
    service: str = "ironclaw-ui"
    timestamp: str
    summary: HealthSnapshotSummary
    kpis: list[HealthSnapshotKpi] = Field(default_factory=list)
    services: list[HealthSnapshotServiceStatus] = Field(default_factory=list)
    signals: list[HealthSnapshotSignal] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


@router.get("/ui/health-snapshot", response_model=HealthSnapshotResponse, operation_id="get_health_snapshot")
def get_health_snapshot() -> HealthSnapshotResponse:
    timestamp = _utc_now_iso()

    return HealthSnapshotResponse(
        timestamp=timestamp,
        summary=HealthSnapshotSummary(
            title="IronClaw runtime health",
            subtitle="Operational readiness snapshot for guardrails, review workflows, and protected execution.",
            overall_status="healthy",
            overall_tone="positive",
            generated_at=timestamp,
        ),
        kpis=[
            HealthSnapshotKpi(label="Overall health", value="Healthy", tone="positive"),
            HealthSnapshotKpi(label="Guard pipeline", value="Online", tone="positive"),
            HealthSnapshotKpi(label="Review queue", value="Available", tone="positive"),
            HealthSnapshotKpi(label="Runtime boundary", value="Enforced", tone="positive"),
        ],
        services=[
            HealthSnapshotServiceStatus(
                name="API process",
                status="healthy",
                detail="FastAPI control plane is serving requests.",
                tone="positive",
            ),
            HealthSnapshotServiceStatus(
                name="Policy enforcement",
                status="healthy",
                detail="Guardrail decisions are available for prompt and action review.",
                tone="positive",
            ),
            HealthSnapshotServiceStatus(
                name="Review workflow",
                status="healthy",
                detail="Human review queue endpoints are reachable.",
                tone="positive",
            ),
            HealthSnapshotServiceStatus(
                name="Execution boundary",
                status="healthy",
                detail="Protected runtime controls are configured for guarded execution.",
                tone="positive",
            ),
        ],
        signals=[
            HealthSnapshotSignal(label="Prompt inspection", value="Active", tone="positive"),
            HealthSnapshotSignal(label="Tool control", value="Active", tone="positive"),
            HealthSnapshotSignal(label="Telemetry path", value="Receiving", tone="positive"),
            HealthSnapshotSignal(label="Audit visibility", value="Enabled", tone="positive"),
        ],
        notes=[
            "This snapshot is designed for UI-facing operational health display.",
            "Values are safe defaults until deeper runtime signal wiring is attached.",
            "Keep this response shape stable for dashboard and test consumers.",
        ],
        metadata={
            "layer": "ui-pages",
            "domain": "health",
            "source": "app.ui.healthsnapshot",
            "mode": "local-first",
        },
    )
