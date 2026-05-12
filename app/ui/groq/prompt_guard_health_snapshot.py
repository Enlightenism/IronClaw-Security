from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_incident_summary import build_prompt_guard_incident_summary
from app.ui.groq.prompt_guard_policy import build_prompt_guard_policy_view
from app.ui.groq.prompt_guard_trends import build_prompt_guard_trend_series

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-health-snapshot"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


HealthStatus = Literal["healthy", "degraded", "warning", "critical"]


@dataclass(slots=True)
class PromptGuardHealthSnapshot:
    generated_at: str
    overall_status: HealthStatus
    policy_mode: str
    policy_health: str
    incident_coverage_ratio: float
    review_queue_total: int
    critical_alerts: int
    trend_status: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "policy_mode": self.policy_mode,
            "policy_health": self.policy_health,
            "incident_coverage_ratio": self.incident_coverage_ratio,
            "review_queue_total": self.review_queue_total,
            "critical_alerts": self.critical_alerts,
            "trend_status": self.trend_status,
            "metadata": dict(self.metadata),
        }


class PromptGuardHealthSnapshotResponse(BaseModel):
    generated_at: str
    overall_status: HealthStatus
    policy_mode: str
    policy_health: str
    incident_coverage_ratio: float
    review_queue_total: int
    critical_alerts: int
    trend_status: str
    metadata: dict[str, Any] = Field(default_factory=dict)


def _derive_trend_status(
    latest_point: dict[str, Any] | None,
    critical_alerts: int,
) -> str:
    if not latest_point:
        return "no-data"

    blocked = int(latest_point.get("blocked_requests", 0) or 0)
    flagged = int(latest_point.get("flagged_requests", 0) or 0)
    total = int(latest_point.get("total_requests", 0) or 0)

    if critical_alerts > 0:
        return "critical"

    if blocked > 0 or flagged > 0:
        return "elevated"

    if total > 0:
        return "stable"

    return "idle"


def _derive_overall_status(
    policy_health: str,
    incident_coverage_ratio: float,
    review_queue_total: int,
    critical_alerts: int,
    trend_status: str,
) -> HealthStatus:
    normalized_health = (policy_health or "").strip().lower()
    normalized_trend = (trend_status or "").strip().lower()

    if normalized_health in {"critical", "failed"} or critical_alerts > 0:
        return "critical"

    if normalized_health in {"degraded", "warning"}:
        return "degraded"

    if incident_coverage_ratio < 0.5:
        return "warning"

    if review_queue_total >= 10:
        return "warning"

    if normalized_trend in {"critical", "elevated"}:
        return "degraded"

    return "healthy"


def build_prompt_guard_health_snapshot() -> PromptGuardHealthSnapshot:
    policy = build_prompt_guard_policy_view()
    incident_summary = build_prompt_guard_incident_summary()
    alerts = build_prompt_guard_alerts_overview()
    trends = build_prompt_guard_trend_series()

    latest_point: dict[str, Any] | None = None
    if trends.points:
        latest_point = trends.points[-1].to_dict()

    summary = incident_summary.to_dict()
    incident_coverage_ratio = float(summary.get("incident_coverage_ratio", 0.0))
    review_queue_total = int(alerts.review_queue_total)
    critical_alerts = int(alerts.critical_alerts)
    trend_status = _derive_trend_status(latest_point, critical_alerts)

    overall_status = _derive_overall_status(
        policy_health=policy.health,
        incident_coverage_ratio=incident_coverage_ratio,
        review_queue_total=review_queue_total,
        critical_alerts=critical_alerts,
        trend_status=trend_status,
    )

    return PromptGuardHealthSnapshot(
        generated_at=_utc_now(),
        overall_status=overall_status,
        policy_mode=policy.mode,
        policy_health=policy.health,
        incident_coverage_ratio=incident_coverage_ratio,
        review_queue_total=review_queue_total,
        critical_alerts=critical_alerts,
        trend_status=trend_status,
        metadata={
            "source_modules": [
                "prompt_guard_policy",
                "prompt_guard_incident_summary",
                "prompt_guard_alerts_overview",
                "prompt_guard_trends",
            ],
            "latest_trend_point": latest_point,
            "trend_interval_minutes": getattr(trends, "interval_minutes", None),
            "trend_lookback_hours": getattr(trends, "lookback_hours", None),
        },
    )


@router.get(
    "/prompt-guard/health-snapshot",
    response_model=PromptGuardHealthSnapshotResponse,
)
def get_prompt_guard_health_snapshot() -> PromptGuardHealthSnapshotResponse:
    snapshot = build_prompt_guard_health_snapshot()
    data = snapshot.to_dict()

    return PromptGuardHealthSnapshotResponse(
        generated_at=data["generated_at"],
        overall_status=data["overall_status"],
        policy_mode=data["policy_mode"],
        policy_health=data["policy_health"],
        incident_coverage_ratio=data["incident_coverage_ratio"],
        review_queue_total=data["review_queue_total"],
        critical_alerts=data["critical_alerts"],
        trend_status=data["trend_status"],
        metadata=data["metadata"],
    )