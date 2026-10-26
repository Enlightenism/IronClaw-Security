from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.guard.prompt_guard_incident_summary import build_prompt_guard_incident_summary
from app.ui.guard.prompt_guard_metrics import build_prompt_guard_metrics_view
from app.ui.guard.prompt_guard_policy import build_prompt_guard_policy_view
from app.ui.guard.prompt_guard_recommendations import build_prompt_guard_recommendations_view
from app.ui.guard.prompt_guard_trends import build_prompt_guard_trend_series

router = APIRouter(
    prefix="/ui/guard",
    tags=["guard-prompt-guard-activity-feed"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


ActivityType = Literal[
    "policy_update",
    "policy_health",
    "metric_kpi",
    "incident_created",
    "incident_status_changed",
    "incident_severity_changed",
    "trend_snapshot",
    "recommendation_created",
]


@dataclass(slots=True)
class PromptGuardActivityItem:
    id: str
    type: ActivityType
    title: str
    severity: str | None
    status: str | None
    timestamp: str
    source_module: str
    details: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "timestamp": self.timestamp,
            "source_module": self.source_module,
            "details": dict(self.details),
            "tags": list(self.tags),
        }


class PromptGuardActivityItemResponse(BaseModel):
    id: str
    type: ActivityType
    title: str
    severity: str | None = None
    status: str | None = None
    timestamp: str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class PromptGuardActivityFeedResponse(BaseModel):
    generated_at: str
    total_items: int
    items: list[PromptGuardActivityItemResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _iso(ts: str | None = None) -> str:
    if ts:
        return ts
    return _utc_now()


def build_prompt_guard_activity_feed() -> PromptGuardActivityFeedResponse:
    policy = build_prompt_guard_policy_view()
    metrics = build_prompt_guard_metrics_view()
    incident_summary = build_prompt_guard_incident_summary()
    trends = build_prompt_guard_trend_series()
    recommendations = build_prompt_guard_recommendations_view()

    items: list[PromptGuardActivityItem] = []

    # Policy headline
    items.append(
        PromptGuardActivityItem(
            id=f"policy:{policy.mode}",
            type="policy_update",
            title=f"Prompt guard policy mode set to '{policy.mode}'",
            severity=None,
            status=policy.health,
            timestamp=_iso(policy.generated_at) if hasattr(policy, "generated_at") else _utc_now(),
            source_module="prompt_guard_policy",
            details={
                "title": policy.title,
                "mode": policy.mode,
                "health": policy.health,
                "rule_count": len(policy.rules),
                "enabled_rules": sum(1 for rule in policy.rules if rule.enabled),
            },
            tags=["policy", policy.mode, policy.health],
        ),
    )

    # Policy health as a dedicated item (if health is available)
    if getattr(policy, "health", None):
        items.append(
            PromptGuardActivityItem(
                id=f"policy-health:{policy.health}",
                type="policy_health",
                title=f"Policy health reported as {policy.health}",
                severity=None,
                status=policy.health,
                timestamp=_iso(policy.generated_at) if hasattr(policy, "generated_at") else _utc_now(),
                source_module="prompt_guard_policy",
                details={
                    "title": policy.title,
                    "mode": policy.mode,
                },
                tags=["policy", "health"],
            ),
        )

    # Metrics KPIs
    for kpi in metrics.kpis:
        kpi_dict = kpi.to_dict()
        items.append(
            PromptGuardActivityItem(
                id=f"kpi:{kpi.name}",
                type="metric_kpi",
                title=f"KPI '{kpi.name}' updated",
                severity=None,
                status=None,
                timestamp=_iso(metrics.generated_at) if hasattr(metrics, "generated_at") else _utc_now(),
                source_module="prompt_guard_metrics",
                details=kpi_dict,
                tags=["metrics", kpi.name],
            ),
        )

    # Incident coverage + breakdowns
    summary = incident_summary.to_dict()
    items.append(
        PromptGuardActivityItem(
            id="incident:coverage",
            type="incident_status_changed",
            title="Prompt guard incident coverage updated",
            severity=None,
            status=None,
            timestamp=_iso(summary.get("generated_at")),
            source_module="prompt_guard_incident_summary",
            details={
                "total_incidents": summary["total_incidents"],
                "linked_incidents": summary["linked_incidents"],
                "unlinked_incidents": summary["unlinked_incidents"],
                "incident_coverage_ratio": summary["incident_coverage_ratio"],
                "by_severity": summary["by_severity"],
                "by_status": summary["by_status"],
            },
            tags=["incidents", "coverage"],
        ),
    )

    # Trend latest snapshot
    latest_point: dict[str, Any] | None = None
    if trends.points:
        latest_point = trends.points[-1].to_dict()
        items.append(
            PromptGuardActivityItem(
                id=f"trend:{latest_point.get('bucket_start', 'latest')}",
                type="trend_snapshot",
                title="Prompt guard trend snapshot updated",
                severity=None,
                status=None,
                timestamp=_iso(trends.generated_at),
                source_module="prompt_guard_trends",
                details={
                    "interval_minutes": trends.interval_minutes,
                    "lookback_hours": trends.lookback_hours,
                    "point": latest_point,
                    "point_count": len(trends.points),
                },
                tags=["trends"],
            ),
        )

    # Recommendations
    for rec in recommendations.items:
        rec_dict = rec.to_dict()
        items.append(
            PromptGuardActivityItem(
                id=f"rec:{rec_dict.get('id', rec_dict.get('title', 'unknown'))}",
                type="recommendation_created",
                title=rec_dict.get("title", "New prompt guard recommendation"),
                severity=rec_dict.get("severity"),
                status=rec_dict.get("status"),
                timestamp=_iso(rec_dict.get("generated_at") or recommendations.generated_at),
                source_module="prompt_guard_recommendations",
                details=rec_dict,
                tags=["recommendation", rec_dict.get("category", "general")],
            ),
        )

    # Sort newest first by timestamp
    items.sort(key=lambda i: i.timestamp, reverse=True)

    generated_at = _utc_now()

    return PromptGuardActivityFeedResponse(
        generated_at=generated_at,
        total_items=len(items),
        items=[
            PromptGuardActivityItemResponse(
                **item.to_dict(),
            )
            for item in items
        ],
        metadata={
            "source_modules": [
                "prompt_guard_policy",
                "prompt_guard_metrics",
                "prompt_guard_incident_summary",
                "prompt_guard_trends",
                "prompt_guard_recommendations",
            ],
            "interval_minutes": getattr(trends, "interval_minutes", None),
            "lookback_hours": getattr(trends, "lookback_hours", None),
        },
    )


@router.get(
    "/prompt-guard/activity-feed",
    response_model=PromptGuardActivityFeedResponse,
)
def get_prompt_guard_activity_feed() -> PromptGuardActivityFeedResponse:
    """Unified operational activity stream for the prompt guard UI.

    This aggregates policy changes, key KPIs, incident coverage, trend snapshots,
    and recommendations into a single normalized feed for dashboard consumption.
    """
    return build_prompt_guard_activity_feed()
