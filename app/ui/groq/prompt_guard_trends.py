from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_metrics import build_prompt_guard_metrics_view

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-trends"],
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass(slots=True)
class PromptGuardTrendPoint:
    captured_at: str
    total_reviews: int
    pending_reviews: int
    approved_reviews: int
    rejected_reviews: int
    total_allowlist_entries: int
    active_allowlist_entries: int
    disabled_allowlist_entries: int
    total_audit_events: int
    simulation_events: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "total_reviews": self.total_reviews,
            "pending_reviews": self.pending_reviews,
            "approved_reviews": self.approved_reviews,
            "rejected_reviews": self.rejected_reviews,
            "total_allowlist_entries": self.total_allowlist_entries,
            "active_allowlist_entries": self.active_allowlist_entries,
            "disabled_allowlist_entries": self.disabled_allowlist_entries,
            "total_audit_events": self.total_audit_events,
            "simulation_events": self.simulation_events,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class PromptGuardTrendSeries:
    points: list[PromptGuardTrendPoint]
    generated_at: str
    interval_minutes: int
    lookback_hours: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "points": [point.to_dict() for point in self.points],
            "generated_at": self.generated_at,
            "interval_minutes": self.interval_minutes,
            "lookback_hours": self.lookback_hours,
            "metadata": dict(self.metadata),
        }


class PromptGuardTrendPointView(BaseModel):
    captured_at: str
    total_reviews: int
    pending_reviews: int
    approved_reviews: int
    rejected_reviews: int
    total_allowlist_entries: int
    active_allowlist_entries: int
    disabled_allowlist_entries: int
    total_audit_events: int
    simulation_events: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromptGuardTrendsResponse(BaseModel):
    points: list[PromptGuardTrendPointView]
    generated_at: str
    interval_minutes: int
    lookback_hours: int
    metadata: dict[str, Any] = Field(default_factory=dict)


def _bounded_interval(interval_minutes: int) -> int:
    return max(1, min(interval_minutes, 60))


def _bounded_lookback(lookback_hours: int) -> int:
    return max(1, min(lookback_hours, 168))


def _extract_current_metrics() -> dict[str, int]:
    view = build_prompt_guard_metrics_view()

    breakdowns = view.breakdowns
    review_statuses = breakdowns.get("review_statuses", {})
    allowlist_statuses = breakdowns.get("allowlist_statuses", {})
    audit_event_types = breakdowns.get("audit_event_types", {})

    kpi_values = {kpi.name: kpi.value for kpi in view.kpis}

    return {
        "total_reviews": int(kpi_values.get("total_reviews", 0)),
        "pending_reviews": int(review_statuses.get("pending", 0)),
        "approved_reviews": int(review_statuses.get("approved", 0)),
        "rejected_reviews": int(review_statuses.get("rejected", 0)),
        "total_allowlist_entries": int(kpi_values.get("total_allowlist_entries", 0)),
        "active_allowlist_entries": int(allowlist_statuses.get("active", 0)),
        "disabled_allowlist_entries": int(allowlist_statuses.get("disabled", 0)),
        "total_audit_events": int(kpi_values.get("total_audit_events", 0)),
        "simulation_events": int(audit_event_types.get("simulation", 0)),
    }


def _build_trend_point(
    *,
    captured_at: datetime,
    index_from_oldest: int,
    total_points: int,
    current: dict[str, int],
) -> PromptGuardTrendPoint:
    progress = 0.0
    if total_points > 1:
        progress = index_from_oldest / (total_points - 1)

    review_penalty = int(round((1.0 - progress) * 4))
    allowlist_penalty = int(round((1.0 - progress) * 2))
    audit_penalty = int(round((1.0 - progress) * 6))

    total_reviews = max(0, current["total_reviews"] - review_penalty)
    pending_reviews = max(0, min(total_reviews, current["pending_reviews"] + int(round((1.0 - progress) * 2))))
    approved_reviews = max(
        0,
        min(
            total_reviews - pending_reviews,
            current["approved_reviews"] - int(round((1.0 - progress) * 1)),
        ),
    )
    rejected_reviews = max(0, total_reviews - pending_reviews - approved_reviews)

    total_allowlist_entries = max(0, current["total_allowlist_entries"] - allowlist_penalty)
    active_allowlist_entries = max(0, min(total_allowlist_entries, current["active_allowlist_entries"]))
    disabled_allowlist_entries = max(0, total_allowlist_entries - active_allowlist_entries)

    total_audit_events = max(0, current["total_audit_events"] - audit_penalty)
    simulation_events = max(0, min(total_audit_events, current["simulation_events"] - int(round((1.0 - progress) * 2))))

    return PromptGuardTrendPoint(
        captured_at=_iso(captured_at),
        total_reviews=total_reviews,
        pending_reviews=pending_reviews,
        approved_reviews=approved_reviews,
        rejected_reviews=rejected_reviews,
        total_allowlist_entries=total_allowlist_entries,
        active_allowlist_entries=active_allowlist_entries,
        disabled_allowlist_entries=disabled_allowlist_entries,
        total_audit_events=total_audit_events,
        simulation_events=simulation_events,
        metadata={
            "synthetic": True,
            "source": "groq-prompt-guard-trends",
        },
    )


def build_prompt_guard_trend_series(
    *,
    interval_minutes: int = 15,
    lookback_hours: int = 24,
) -> PromptGuardTrendSeries:
    interval_minutes = _bounded_interval(interval_minutes)
    lookback_hours = _bounded_lookback(lookback_hours)

    now = _utc_now()
    start = now - timedelta(hours=lookback_hours)
    step = timedelta(minutes=interval_minutes)
    current = _extract_current_metrics()

    timestamps: list[datetime] = []
    cursor = start
    while cursor <= now:
        timestamps.append(cursor)
        cursor += step

    if not timestamps or timestamps[-1] != now:
        timestamps.append(now)

    points = [
        _build_trend_point(
            captured_at=ts,
            index_from_oldest=index,
            total_points=len(timestamps),
            current=current,
        )
        for index, ts in enumerate(timestamps)
    ]

    return PromptGuardTrendSeries(
        points=points,
        generated_at=_iso(now),
        interval_minutes=interval_minutes,
        lookback_hours=lookback_hours,
        metadata={
            "focus": "prompt_guard_trends",
            "synthetic": True,
        },
    )


@router.get("/prompt-guard/trends", response_model=PromptGuardTrendsResponse)
def get_prompt_guard_trends(
    interval_minutes: int = Query(
        15,
        ge=1,
        le=60,
        description="Trend interval in minutes.",
    ),
    lookback_hours: int = Query(
        24,
        ge=1,
        le=168,
        description="How many hours of trend points to return.",
    ),
) -> PromptGuardTrendsResponse:
    series = build_prompt_guard_trend_series(
        interval_minutes=interval_minutes,
        lookback_hours=lookback_hours,
    )
    data = series.to_dict()

    return PromptGuardTrendsResponse(
        points=[PromptGuardTrendPointView(**point) for point in data["points"]],
        generated_at=data["generated_at"],
        interval_minutes=data["interval_minutes"],
        lookback_hours=data["lookback_hours"],
        metadata=data["metadata"],
    )
