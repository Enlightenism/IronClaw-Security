from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/usage-reports", tags=["usage-reports"])


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class UsageSummaryItemView(BaseModel):
    summary_id: str
    period_start: str
    period_end: str
    total_requests: int
    total_scans: int
    total_blocked: int
    total_warned: int
    total_quarantined: int
    total_allowed: int
    unique_clients: int
    unique_sessions: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageSummaryListView(BaseModel):
    status: str
    service: str
    timestamp: str
    period: str
    limit: int
    items: list[UsageSummaryItemView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class UsageEventView(BaseModel):
    event_id: str
    occurred_at: str
    client_id: str | None = None
    session_id: str | None = None
    action_type: str
    verdict: str
    units_consumed: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageEventListView(BaseModel):
    status: str
    service: str
    timestamp: str
    limit: int
    events: list[UsageEventView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class UsageReportsResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    summaries: UsageSummaryListView
    events: UsageEventListView
    notes: list[str] = Field(default_factory=list)


def _build_mock_summaries(period: str, limit: int) -> UsageSummaryListView:
    items: list[UsageSummaryItemView] = [
        UsageSummaryItemView(
            summary_id=f"usage-{period}",
            period_start=_utc_now_iso(),
            period_end=_utc_now_iso(),
            total_requests=0,
            total_scans=0,
            total_blocked=0,
            total_warned=0,
            total_quarantined=0,
            total_allowed=0,
            unique_clients=0,
            unique_sessions=0,
            metadata={
                "period": period,
                "sampled": True,
                "limit": limit,
            },
        )
    ]

    return UsageSummaryListView(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        period=period,
        limit=limit,
        items=items[:limit],
        notes=[
            "Usage summaries are aggregated from the underlying usage-reports API.",
            "This UI view provides a safe default zeroed snapshot when no data is available.",
        ],
    )


def _build_mock_events(limit: int) -> UsageEventListView:
    events: list[UsageEventView] = []

    return UsageEventListView(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        limit=limit,
        events=events,
        notes=[
            "Usage events are sourced from the usage-reports events API.",
            "This UI view intentionally returns an empty list when no recent events are present.",
        ],
    )


@router.get("", response_model=UsageReportsResponse)
def get_usage_reports(
    period: str = Query(default="24h", min_length=2, max_length=16),
    limit: int = Query(default=10, ge=1, le=100),
) -> UsageReportsResponse:
    summaries = _build_mock_summaries(period=period, limit=limit)
    events = _build_mock_events(limit=limit)

    return UsageReportsResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        summaries=summaries,
        events=events,
        notes=[
            "Usage reports UI provides a consolidated snapshot of recent security usage.",
            "For full historical exports, use the usage-reports API endpoints directly.",
        ],
    )