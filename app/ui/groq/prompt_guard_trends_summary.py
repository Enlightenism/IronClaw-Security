from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_health_snapshot import build_prompt_guard_health_snapshot
from app.ui.groq.prompt_guard_performance_snapshot import build_prompt_guard_performance_snapshot
from app.ui.groq.prompt_guard_signals_summary import build_prompt_guard_signals_summary
from app.ui.groq.prompt_guard_trends import build_prompt_guard_trend_series

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-trends-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


TrendStatus = Literal["stable", "watch", "elevated", "critical", "idle"]


@dataclass(slots=True)
class PromptGuardTrendSnapshot:
    timestamp: str
    total_requests: int
    blocked_requests: int
    flagged_requests: int
    status: TrendStatus
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "flagged_requests": self.flagged_requests,
            "status": self.status,
            "details": dict(self.details),
        }


@dataclass(slots=True)
class PromptGuardTrendsSummary:
    generated_at: str
    trend_status: TrendStatus
    interval_minutes: int
    lookback_hours: int
    point_count: int
    total_request_volume: int
    total_blocked_requests: int
    total_flagged_requests: int
    latest_snapshot: dict[str, Any] | None = None
    snapshots: list[PromptGuardTrendSnapshot] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "trend_status": self.trend_status,
            "interval_minutes": self.interval_minutes,
            "lookback_hours": self.lookback_hours,
            "point_count": self.point_count,
            "total_request_volume": self.total_request_volume,
            "total_blocked_requests": self.total_blocked_requests,
            "total_flagged_requests": self.total_flagged_requests,
            "latest_snapshot": dict(self.latest_snapshot) if self.latest_snapshot else None,
            "snapshots": [snapshot.to_dict() for snapshot in self.snapshots],
            "metadata": dict(self.metadata),
        }


class PromptGuardTrendSnapshotResponse(BaseModel):
    timestamp: str
    total_requests: int
    blocked_requests: int
    flagged_requests: int
    status: TrendStatus
    details: dict[str, Any] = Field(default_factory=dict)


class PromptGuardTrendsSummaryResponse(BaseModel):
    generated_at: str
    trend_status: TrendStatus
    interval_minutes: int
    lookback_hours: int
    point_count: int
    total_request_volume: int
    total_blocked_requests: int
    total_flagged_requests: int
    latest_snapshot: dict[str, Any] | None = None
    snapshots: list[PromptGuardTrendSnapshotResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _derive_point_status(
    total_requests: int,
    blocked_requests: int,
    flagged_requests: int,
) -> TrendStatus:
    if total_requests <= 0 and blocked_requests <= 0 and flagged_requests <= 0:
        return "idle"
    if blocked_requests >= 10:
        return "critical"
    if blocked_requests > 0:
        return "elevated"
    if flagged_requests > 0:
        return "watch"
    return "stable"


def _rollup_status(statuses: list[TrendStatus]) -> TrendStatus:
    rank: dict[TrendStatus, int] = {
        "idle": 0,
        "stable": 1,
        "watch": 2,
        "elevated": 3,
        "critical": 4,
    }
    if not statuses:
        return "idle"
    return max(statuses, key=lambda item: rank[item])


def build_prompt_guard_trends_summary() -> PromptGuardTrendsSummary:
    generated_at = _utc_now()

    trends = build_prompt_guard_trend_series()
    health = build_prompt_guard_health_snapshot()
    performance = build_prompt_guard_performance_snapshot()
    signals = build_prompt_guard_signals_summary()

    snapshots: list[PromptGuardTrendSnapshot] = []
    total_request_volume = 0
    total_blocked_requests = 0
    total_flagged_requests = 0

    for point in trends.points:
        point_data = point.to_dict()
        total_requests = int(point_data.get("total_requests", 0) or 0)
        blocked_requests = int(point_data.get("blocked_requests", 0) or 0)
        flagged_requests = int(point_data.get("flagged_requests", 0) or 0)

        total_request_volume += total_requests
        total_blocked_requests += blocked_requests
        total_flagged_requests += flagged_requests

        status = _derive_point_status(
            total_requests=total_requests,
            blocked_requests=blocked_requests,
            flagged_requests=flagged_requests,
        )

        snapshots.append(
            PromptGuardTrendSnapshot(
                timestamp=point_data.get("bucket_start", generated_at),
                total_requests=total_requests,
                blocked_requests=blocked_requests,
                flagged_requests=flagged_requests,
                status=status,
                details=point_data,
            ),
        )

    latest_snapshot = snapshots[-1].to_dict() if snapshots else None
    trend_status = _rollup_status([snapshot.status for snapshot in snapshots])

    if health.trend_status in {"critical", "elevated"}:
        trend_status = "critical" if health.trend_status == "critical" else "elevated"

    return PromptGuardTrendsSummary(
        generated_at=generated_at,
        trend_status=trend_status,
        interval_minutes=int(getattr(trends, "interval_minutes", 0) or 0),
        lookback_hours=int(getattr(trends, "lookback_hours", 0) or 0),
        point_count=len(snapshots),
        total_request_volume=total_request_volume,
        total_blocked_requests=total_blocked_requests,
        total_flagged_requests=total_flagged_requests,
        latest_snapshot=latest_snapshot,
        snapshots=snapshots,
        metadata={
            "source_modules": [
                "prompt_guard_trends",
                "prompt_guard_health_snapshot",
                "prompt_guard_performance_snapshot",
                "prompt_guard_signals_summary",
            ],
            "performance_request_volume": performance.request_volume,
            "signal_pressure": signals.signal_pressure,
            "snapshot_count": len(snapshots),
        },
    )


@router.get(
    "/prompt-guard/trends-summary",
    response_model=PromptGuardTrendsSummaryResponse,
)
def get_prompt_guard_trends_summary() -> PromptGuardTrendsSummaryResponse:
    summary = build_prompt_guard_trends_summary()
    data = summary.to_dict()

    return PromptGuardTrendsSummaryResponse(
        generated_at=data["generated_at"],
        trend_status=data["trend_status"],
        interval_minutes=data["interval_minutes"],
        lookback_hours=data["lookback_hours"],
        point_count=data["point_count"],
        total_request_volume=data["total_request_volume"],
        total_blocked_requests=data["total_blocked_requests"],
        total_flagged_requests=data["total_flagged_requests"],
        latest_snapshot=data["latest_snapshot"],
        snapshots=[PromptGuardTrendSnapshotResponse(**snapshot) for snapshot in data["snapshots"]],
        metadata=data["metadata"],
    )
