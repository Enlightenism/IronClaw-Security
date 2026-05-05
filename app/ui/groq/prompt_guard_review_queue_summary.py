from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_activity_feed import build_prompt_guard_activity_feed
from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_metrics import build_prompt_guard_metrics_view
from app.ui.groq.prompt_guard_recommendations import build_prompt_guard_recommendations_view


router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-review-queue-summary"],
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


QueueStatus = Literal["idle", "normal", "busy", "elevated", "critical"]


@dataclass(slots=True)
class PromptGuardReviewQueueItem:
    id: str
    title: str
    severity: str
    status: str | None
    timestamp: str
    source_module: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "timestamp": self.timestamp,
            "source_module": self.source_module,
            "details": dict(self.details),
        }


@dataclass(slots=True)
class PromptGuardReviewQueueSummary:
    generated_at: str
    queue_status: QueueStatus
    review_queue_total: int
    critical_alerts: int
    warning_alerts: int
    recommendation_backlog: int
    oldest_queue_signal: dict[str, Any] | None = None
    queue_items: list[PromptGuardReviewQueueItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "queue_status": self.queue_status,
            "review_queue_total": self.review_queue_total,
            "critical_alerts": self.critical_alerts,
            "warning_alerts": self.warning_alerts,
            "recommendation_backlog": self.recommendation_backlog,
            "oldest_queue_signal": dict(self.oldest_queue_signal) if self.oldest_queue_signal else None,
            "queue_items": [item.to_dict() for item in self.queue_items],
            "metadata": dict(self.metadata),
        }


class PromptGuardReviewQueueItemResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: str | None = None
    timestamp: str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)


class PromptGuardReviewQueueSummaryResponse(BaseModel):
    generated_at: str
    queue_status: QueueStatus
    review_queue_total: int
    critical_alerts: int
    warning_alerts: int
    recommendation_backlog: int
    oldest_queue_signal: dict[str, Any] | None = None
    queue_items: list[PromptGuardReviewQueueItemResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _derive_queue_status(
    review_queue_total: int,
    critical_alerts: int,
    warning_alerts: int,
) -> QueueStatus:
    if critical_alerts > 0:
        return "critical"
    if review_queue_total >= 15:
        return "elevated"
    if review_queue_total >= 8 or warning_alerts >= 5:
        return "busy"
    if review_queue_total > 0 or warning_alerts > 0:
        return "normal"
    return "idle"


def _extract_review_queue_total(metrics: Any, alerts: Any) -> int:
    metrics_total = next(
        (kpi.value for kpi in metrics.kpis if kpi.name == "total_reviews"),
        None,
    )
    if metrics_total is not None:
        return int(metrics_total)
    return int(alerts.review_queue_total)


def build_prompt_guard_review_queue_summary() -> PromptGuardReviewQueueSummary:
    generated_at = _utc_now()

    metrics = build_prompt_guard_metrics_view()
    alerts = build_prompt_guard_alerts_overview()
    activity_feed = build_prompt_guard_activity_feed()
    recommendations = build_prompt_guard_recommendations_view()

    review_queue_total = _extract_review_queue_total(metrics, alerts)
    critical_alerts = int(alerts.critical_alerts)
    warning_alerts = int(alerts.warning_alerts)
    recommendation_backlog = len(recommendations.items)

    queue_items: list[PromptGuardReviewQueueItem] = []

    for alert in alerts.latest_alerts:
        queue_items.append(
            PromptGuardReviewQueueItem(
                id=f"queue-alert:{alert.id}",
                title=alert.title,
                severity=alert.severity,
                status=alert.status,
                timestamp=alert.timestamp,
                source_module=alert.source_module,
                details=alert.details,
            )
        )

    for rec in recommendations.items:
        rec_data = rec.to_dict()
        queue_items.append(
            PromptGuardReviewQueueItem(
                id=f"queue-rec:{rec_data.get('id', rec_data.get('title', 'unknown'))}",
                title=rec_data.get("title", "Prompt guard recommendation"),
                severity=str(rec_data.get("severity", "medium")),
                status=rec_data.get("status"),
                timestamp=rec_data.get("generated_at", generated_at),
                source_module="prompt_guard_recommendations",
                details=rec_data,
            )
        )

    for item in activity_feed.items:
        if item.type not in {"recommendation_created", "incident_status_changed"}:
            continue
        queue_items.append(
            PromptGuardReviewQueueItem(
                id=f"queue-activity:{item.id}",
                title=item.title,
                severity=str(item.severity or "info"),
                status=item.status,
                timestamp=item.timestamp,
                source_module=item.source_module,
                details=item.details,
            )
        )

    queue_items.sort(key=lambda item: item.timestamp)
    oldest_queue_signal = queue_items[0].to_dict() if queue_items else None

    queue_status = _derive_queue_status(
        review_queue_total=review_queue_total,
        critical_alerts=critical_alerts,
        warning_alerts=warning_alerts,
    )

    return PromptGuardReviewQueueSummary(
        generated_at=generated_at,
        queue_status=queue_status,
        review_queue_total=review_queue_total,
        critical_alerts=critical_alerts,
        warning_alerts=warning_alerts,
        recommendation_backlog=recommendation_backlog,
        oldest_queue_signal=oldest_queue_signal,
        queue_items=queue_items[:12],
        metadata={
            "source_modules": [
                "prompt_guard_metrics",
                "prompt_guard_alerts_overview",
                "prompt_guard_activity_feed",
                "prompt_guard_recommendations",
            ],
            "queue_item_limit": 12,
        },
    )


@router.get(
    "/prompt-guard/review-queue-summary",
    response_model=PromptGuardReviewQueueSummaryResponse,
)
def get_prompt_guard_review_queue_summary() -> PromptGuardReviewQueueSummaryResponse:
    summary = build_prompt_guard_review_queue_summary()
    data = summary.to_dict()

    return PromptGuardReviewQueueSummaryResponse(
        generated_at=data["generated_at"],
        queue_status=data["queue_status"],
        review_queue_total=data["review_queue_total"],
        critical_alerts=data["critical_alerts"],
        warning_alerts=data["warning_alerts"],
        recommendation_backlog=data["recommendation_backlog"],
        oldest_queue_signal=data["oldest_queue_signal"],
        queue_items=[
            PromptGuardReviewQueueItemResponse(**item)
            for item in data["queue_items"]
        ],
        metadata=data["metadata"],
    )