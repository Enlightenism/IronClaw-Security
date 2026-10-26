from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.guard.prompt_guard_incident_summary import build_prompt_guard_incident_summary
from app.ui.guard.prompt_guard_metrics import build_prompt_guard_metrics_view
from app.ui.guard.prompt_guard_policy import build_prompt_guard_policy_view
from app.ui.guard.prompt_guard_recommendations import build_prompt_guard_recommendations_view
from app.ui.guard.prompt_guard_trends import build_prompt_guard_trend_series

router = APIRouter(
    prefix="/ui/guard",
    tags=["guard-prompt-guard-ops-dashboard"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PromptGuardOpsDashboard:
    generated_at: str
    policy: dict[str, Any]
    metrics: dict[str, Any]
    incident_summary: dict[str, Any]
    trends: dict[str, Any]
    recommendations: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "policy": dict(self.policy),
            "metrics": dict(self.metrics),
            "incident_summary": dict(self.incident_summary),
            "trends": dict(self.trends),
            "recommendations": list(self.recommendations),
            "metadata": dict(self.metadata),
        }


class PromptGuardOpsDashboardResponse(BaseModel):
    generated_at: str
    policy: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, Any] = Field(default_factory=dict)
    incident_summary: dict[str, Any] = Field(default_factory=dict)
    trends: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def build_prompt_guard_ops_dashboard() -> PromptGuardOpsDashboard:
    policy = build_prompt_guard_policy_view()
    metrics = build_prompt_guard_metrics_view()
    incident_summary = build_prompt_guard_incident_summary()
    trend_series = build_prompt_guard_trend_series()
    recommendations = build_prompt_guard_recommendations_view()

    latest_point: dict[str, Any] | None = None
    if trend_series.points:
        latest_point = trend_series.points[-1].to_dict()

    return PromptGuardOpsDashboard(
        generated_at=_utc_now(),
        policy={
            "title": policy.title,
            "mode": policy.mode,
            "health": policy.health,
            "enabled_rule_count": sum(1 for rule in policy.rules if rule.enabled),
            "total_rule_count": len(policy.rules),
        },
        metrics={
            "title": metrics.title,
            "kpis": [kpi.to_dict() for kpi in metrics.kpis],
            "breakdowns": metrics.breakdowns,
        },
        incident_summary=incident_summary.to_dict(),
        trends={
            "generated_at": trend_series.generated_at,
            "interval_minutes": trend_series.interval_minutes,
            "lookback_hours": trend_series.lookback_hours,
            "point_count": len(trend_series.points),
            "latest_point": latest_point,
        },
        recommendations=[item.to_dict() for item in recommendations.items],
        metadata={
            "source_modules": [
                "prompt_guard_policy",
                "prompt_guard_metrics",
                "prompt_guard_incident_summary",
                "prompt_guard_trends",
                "prompt_guard_recommendations",
            ],
        },
    )


@router.get("/prompt-guard/ops-dashboard", response_model=PromptGuardOpsDashboardResponse)
def get_prompt_guard_ops_dashboard() -> PromptGuardOpsDashboardResponse:
    dashboard = build_prompt_guard_ops_dashboard()
    data = dashboard.to_dict()

    return PromptGuardOpsDashboardResponse(
        generated_at=data["generated_at"],
        policy=data["policy"],
        metrics=data["metrics"],
        incident_summary=data["incident_summary"],
        trends=data["trends"],
        recommendations=data["recommendations"],
        metadata=data["metadata"],
    )
