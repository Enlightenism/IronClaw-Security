from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_metrics import build_prompt_guard_metrics_view
from app.ui.groq.prompt_guard_trends import build_prompt_guard_trend_series


router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-performance-snapshot"],
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class PromptGuardPerformanceSnapshot:
    generated_at: str
    request_volume: int
    blocked_requests: int
    flagged_requests: int
    review_queue_total: int
    error_pressure: float
    trend_window: dict[str, Any]
    latest_point: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "request_volume": self.request_volume,
            "blocked_requests": self.blocked_requests,
            "flagged_requests": self.flagged_requests,
            "review_queue_total": self.review_queue_total,
            "error_pressure": self.error_pressure,
            "trend_window": dict(self.trend_window),
            "latest_point": dict(self.latest_point) if self.latest_point is not None else None,
            "metadata": dict(self.metadata),
        }


class PromptGuardPerformanceSnapshotResponse(BaseModel):
    generated_at: str
    request_volume: int
    blocked_requests: int
    flagged_requests: int
    review_queue_total: int
    error_pressure: float = Field(
        ...,
        description="Ratio of (blocked + flagged) to total requests in the current trend window.",
    )
    trend_window: dict[str, Any] = Field(
        default_factory=dict,
        description="Details about the active trend window (interval_minutes, lookback_hours, point_count).",
    )
    latest_point: dict[str, Any] | None = Field(
        default=None,
        description="Most recent trend bucket, if any.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


def _compute_error_pressure(latest_point: dict[str, Any] | None) -> float:
    if not latest_point:
        return 0.0

    total = int(latest_point.get("total_requests", 0) or 0)
    blocked = int(latest_point.get("blocked_requests", 0) or 0)
    flagged = int(latest_point.get("flagged_requests", 0) or 0)

    if total <= 0:
        return 0.0

    pressure = (blocked + flagged) / total
    return round(pressure, 4)


def build_prompt_guard_performance_snapshot() -> PromptGuardPerformanceSnapshot:
    trends = build_prompt_guard_trend_series()
    metrics = build_prompt_guard_metrics_view()
    alerts = build_prompt_guard_alerts_overview()

    latest_point: dict[str, Any] | None = None
    if trends.points:
        latest_point = trends.points[-1].to_dict()

    if latest_point:
        total_requests = int(latest_point.get("total_requests", 0) or 0)
        blocked_requests = int(latest_point.get("blocked_requests", 0) or 0)
        flagged_requests = int(latest_point.get("flagged_requests", 0) or 0)
    else:
        total_requests = 0
        blocked_requests = 0
        flagged_requests = 0

    error_pressure = _compute_error_pressure(latest_point)

    review_queue_total = int(alerts.review_queue_total)

    trend_window = {
        "interval_minutes": getattr(trends, "interval_minutes", None),
        "lookback_hours": getattr(trends, "lookback_hours", None),
        "point_count": len(trends.points),
    }

    throughput_kpi = next(
        (kpi for kpi in metrics.kpis if kpi.name in {"throughput_rpm", "throughput_rps"}),
        None,
    )

    metadata: dict[str, Any] = {
        "source_modules": [
            "prompt_guard_trends",
            "prompt_guard_metrics",
            "prompt_guard_alerts_overview",
        ],
        "throughput_kpi": throughput_kpi.to_dict() if throughput_kpi is not None else None,
    }

    return PromptGuardPerformanceSnapshot(
        generated_at=_utc_now(),
        request_volume=total_requests,
        blocked_requests=blocked_requests,
        flagged_requests=flagged_requests,
        review_queue_total=review_queue_total,
        error_pressure=error_pressure,
        trend_window=trend_window,
        latest_point=latest_point,
        metadata=metadata,
    )


@router.get(
    "/prompt-guard/performance-snapshot",
    response_model=PromptGuardPerformanceSnapshotResponse,
)
def get_prompt_guard_performance_snapshot() -> PromptGuardPerformanceSnapshotResponse:
    snapshot = build_prompt_guard_performance_snapshot()
    data = snapshot.to_dict()
    return PromptGuardPerformanceSnapshotResponse(
        generated_at=data["generated_at"],
        request_volume=data["request_volume"],
        blocked_requests=data["blocked_requests"],
        flagged_requests=data["flagged_requests"],
        review_queue_total=data["review_queue_total"],
        error_pressure=data["error_pressure"],
        trend_window=data["trend_window"],
        latest_point=data["latest_point"],
        metadata=data["metadata"],
    )