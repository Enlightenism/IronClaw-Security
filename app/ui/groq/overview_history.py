from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.services.groq_security_brain import GroqMode
from app.ui.groq.control_panel import CONTROL_FLAGS
from app.ui.groq.overview import build_groq_security_overview

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-overview-history"],
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass(slots=True)
class OverviewHistoryPoint:
    captured_at: str
    overall_score: int
    mode: GroqMode
    total_requests: int
    high_risk_requests: int
    blocked_or_quarantined: int
    open_incidents: int
    high_or_critical_incidents: int
    suggested_actions: int
    queued_actions: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "overall_score": self.overall_score,
            "mode": self.mode,
            "total_requests": self.total_requests,
            "high_risk_requests": self.high_risk_requests,
            "blocked_or_quarantined": self.blocked_or_quarantined,
            "open_incidents": self.open_incidents,
            "high_or_critical_incidents": self.high_or_critical_incidents,
            "suggested_actions": self.suggested_actions,
            "queued_actions": self.queued_actions,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class OverviewHistorySeries:
    points: list[OverviewHistoryPoint]
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


class OverviewHistoryPointView(BaseModel):
    captured_at: str
    overall_score: int
    mode: GroqMode
    total_requests: int
    high_risk_requests: int
    blocked_or_quarantined: int
    open_incidents: int
    high_or_critical_incidents: int
    suggested_actions: int
    queued_actions: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class OverviewHistoryResponse(BaseModel):
    points: list[OverviewHistoryPointView]
    generated_at: str
    interval_minutes: int
    lookback_hours: int
    metadata: dict[str, Any] = Field(default_factory=dict)


def _bounded_interval(interval_minutes: int) -> int:
    return max(1, min(interval_minutes, 60))


def _bounded_lookback(lookback_hours: int) -> int:
    return max(1, min(lookback_hours, 168))


def _build_history_point(
    *,
    captured_at: datetime,
    index_from_oldest: int,
    total_points: int,
) -> OverviewHistoryPoint:
    overview = build_groq_security_overview()

    posture = overview.posture
    traffic = overview.traffic
    incidents = overview.incidents
    remediation = overview.remediation

    progress = 0.0
    if total_points > 1:
        progress = index_from_oldest / (total_points - 1)

    score_penalty = int(round((1.0 - progress) * 8))
    request_penalty = int(round((1.0 - progress) * 6))
    incident_penalty = int(round((1.0 - progress) * 2))
    remediation_penalty = int(round((1.0 - progress) * 2))

    overall_score = max(0, min(100, posture.overall_score - score_penalty))
    total_requests = max(0, traffic.total_requests - request_penalty)
    high_risk_requests = max(0, traffic.high_risk_requests - max(0, request_penalty // 2))
    blocked_or_quarantined = max(
        0,
        traffic.blocked_or_quarantined - max(0, request_penalty // 3),
    )
    open_incidents = max(0, incidents.open_incidents - incident_penalty)
    high_or_critical_incidents = max(
        0,
        incidents.high_or_critical_incidents - max(0, incident_penalty // 2),
    )
    suggested_actions = max(0, remediation.suggested_actions - remediation_penalty)
    queued_actions = max(0, remediation.queued_actions - max(0, remediation_penalty // 2))

    return OverviewHistoryPoint(
        captured_at=_iso(captured_at),
        overall_score=overall_score,
        mode=CONTROL_FLAGS.mode,
        total_requests=total_requests,
        high_risk_requests=high_risk_requests,
        blocked_or_quarantined=blocked_or_quarantined,
        open_incidents=open_incidents,
        high_or_critical_incidents=high_or_critical_incidents,
        suggested_actions=suggested_actions,
        queued_actions=queued_actions,
        metadata={
            "synthetic": True,
            "source": "groq-overview-history",
        },
    )


def build_overview_history_series(
    *,
    interval_minutes: int = 15,
    lookback_hours: int = 24,
) -> OverviewHistorySeries:
    interval_minutes = _bounded_interval(interval_minutes)
    lookback_hours = _bounded_lookback(lookback_hours)

    now = _utc_now()
    start = now - timedelta(hours=lookback_hours)
    step = timedelta(minutes=interval_minutes)

    points: list[OverviewHistoryPoint] = []
    current = start

    timestamps: list[datetime] = []
    while current <= now:
        timestamps.append(current)
        current += step

    if not timestamps or timestamps[-1] != now:
        timestamps.append(now)

    for idx, ts in enumerate(timestamps):
        points.append(
            _build_history_point(
                captured_at=ts,
                index_from_oldest=idx,
                total_points=len(timestamps),
            )
        )

    return OverviewHistorySeries(
        points=points,
        generated_at=_iso(now),
        interval_minutes=interval_minutes,
        lookback_hours=lookback_hours,
        metadata={
            "focus": "overview_trend_snapshots",
            "synthetic": True,
        },
    )


@router.get("/overview/history", response_model=OverviewHistoryResponse)
def get_overview_history(
    interval_minutes: int = Query(
        15,
        ge=1,
        le=60,
        description="Snapshot interval in minutes.",
    ),
    lookback_hours: int = Query(
        24,
        ge=1,
        le=168,
        description="How many hours of overview history to return.",
    ),
) -> OverviewHistoryResponse:
    series = build_overview_history_series(
        interval_minutes=interval_minutes,
        lookback_hours=lookback_hours,
    )
    data = series.to_dict()

    return OverviewHistoryResponse(
        points=[OverviewHistoryPointView(**point) for point in data["points"]],
        generated_at=data["generated_at"],
        interval_minutes=data["interval_minutes"],
        lookback_hours=data["lookback_hours"],
        metadata=data["metadata"],
    )