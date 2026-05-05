from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_activity_feed import build_prompt_guard_activity_feed
from app.ui.groq.prompt_guard_incident_summary import build_prompt_guard_incident_summary
from app.ui.groq.prompt_guard_metrics import build_prompt_guard_metrics_view
from app.ui.groq.prompt_guard_recommendations import build_prompt_guard_recommendations_view


router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-alerts-overview"],
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


AlertSeverity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(slots=True)
class PromptGuardAlertItem:
    id: str
    title: str
    severity: AlertSeverity
    status: str | None
    timestamp: str
    source_module: str
    details: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "timestamp": self.timestamp,
            "source_module": self.source_module,
            "details": dict(self.details),
            "tags": list(self.tags),
        }


class PromptGuardAlertItemResponse(BaseModel):
    id: str
    title: str
    severity: AlertSeverity
    status: str | None = None
    timestamp: str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class PromptGuardAlertsOverviewResponse(BaseModel):
    generated_at: str
    open_alerts: int
    critical_alerts: int
    warning_alerts: int
    review_queue_total: int
    latest_alerts: list[PromptGuardAlertItemResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _normalize_severity(value: str | None) -> AlertSeverity:
    if not value:
        return "info"

    normalized = value.strip().lower()
    mapping: dict[str, AlertSeverity] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(normalized, "info")


def _sort_key(item: PromptGuardAlertItem) -> tuple[int, str]:
    rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return (rank.get(item.severity, 4), item.timestamp)


def build_prompt_guard_alerts_overview() -> PromptGuardAlertsOverviewResponse:
    generated_at = _utc_now()

    incident_summary = build_prompt_guard_incident_summary()
    metrics = build_prompt_guard_metrics_view()
    recommendations = build_prompt_guard_recommendations_view()
    activity_feed = build_prompt_guard_activity_feed()

    review_queue_total = next(
        (kpi.value for kpi in metrics.kpis if kpi.name == "total_reviews"),
        0,
    )

    latest_alerts: list[PromptGuardAlertItem] = []

    summary = incident_summary.to_dict()
    severity_counts = summary.get("by_severity", {})
    status_counts = summary.get("by_status", {})

    critical_incidents = int(
        severity_counts.get("critical", 0)
        + severity_counts.get("high", 0)
    )

    warning_incidents = int(
        severity_counts.get("medium", 0)
        + severity_counts.get("low", 0)
    )

    open_alerts = int(
        status_counts.get("open", 0)
        + status_counts.get("investigating", 0)
        + status_counts.get("triaged", 0)
        + status_counts.get("pending", 0)
    )

    if critical_incidents > 0:
        latest_alerts.append(
            PromptGuardAlertItem(
                id="alert:incident-critical-summary",
                title="Critical incident volume requires attention",
                severity="critical",
                status="open" if open_alerts > 0 else None,
                timestamp=summary["generated_at"],
                source_module="prompt_guard_incident_summary",
                details={
                    "critical_incidents": critical_incidents,
                    "severity_breakdown": severity_counts,
                    "status_breakdown": status_counts,
                },
                tags=["incidents", "critical"],
            )
        )

    if review_queue_total > 0:
        latest_alerts.append(
            PromptGuardAlertItem(
                id="alert:review-queue",
                title="Prompt guard review queue has pending workload",
                severity="high" if review_queue_total >= 10 else "medium",
                status="pending",
                timestamp=generated_at,
                source_module="prompt_guard_metrics",
                details={
                    "review_queue_total": review_queue_total,
                },
                tags=["reviews", "queue"],
            )
        )

    for rec in recommendations.items:
        rec_dict = rec.to_dict()
        severity = _normalize_severity(rec_dict.get("severity"))
        latest_alerts.append(
            PromptGuardAlertItem(
                id=f"alert:recommendation:{rec_dict.get('id', rec_dict.get('title', 'unknown'))}",
                title=rec_dict.get("title", "Prompt guard recommendation"),
                severity=severity,
                status=rec_dict.get("status"),
                timestamp=rec_dict.get("generated_at", generated_at),
                source_module="prompt_guard_recommendations",
                details=rec_dict,
                tags=["recommendation", rec_dict.get("category", "general")],
            )
        )

    for item in activity_feed.items:
        if item.type not in {"incident_status_changed", "recommendation_created"}:
            continue

        severity = _normalize_severity(item.severity)
        latest_alerts.append(
            PromptGuardAlertItem(
                id=f"alert:activity:{item.id}",
                title=item.title,
                severity=severity,
                status=item.status,
                timestamp=item.timestamp,
                source_module=item.source_module,
                details=item.details,
                tags=list(item.tags),
            )
        )

    latest_alerts.sort(key=_sort_key)
    latest_alerts = latest_alerts[:10]

    critical_alerts = sum(1 for alert in latest_alerts if alert.severity == "critical")
    warning_alerts = sum(1 for alert in latest_alerts if alert.severity in {"high", "medium"})

    return PromptGuardAlertsOverviewResponse(
        generated_at=generated_at,
        open_alerts=max(open_alerts, len([a for a in latest_alerts if (a.status or "").lower() in {"open", "pending", "investigating", "triaged"}])),
        critical_alerts=critical_alerts,
        warning_alerts=warning_alerts,
        review_queue_total=review_queue_total,
        latest_alerts=[
            PromptGuardAlertItemResponse(**alert.to_dict())
            for alert in latest_alerts
        ],
        metadata={
            "source_modules": [
                "prompt_guard_incident_summary",
                "prompt_guard_metrics",
                "prompt_guard_recommendations",
                "prompt_guard_activity_feed",
            ],
            "latest_alert_limit": 10,
            "severity_strategy": {
                "critical": ["critical", "high incident summary rollup"],
                "warning": ["high", "medium"],
            },
        },
    )


@router.get(
    "/prompt-guard/alerts-overview",
    response_model=PromptGuardAlertsOverviewResponse,
)
def get_prompt_guard_alerts_overview() -> PromptGuardAlertsOverviewResponse:
    return build_prompt_guard_alerts_overview()