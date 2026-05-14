from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.core.auth import require_api_key
from app.core.usage_metering import UsageEvent, UsageSummary, get_usage_metering_registry

router = APIRouter(
    prefix="/usage-reports",
    tags=["usage-reports"],
    dependencies=[Depends(require_api_key)],
)


class UsageRouteCount(BaseModel):
    route: str
    requests: int


class UsageSummaryView(BaseModel):
    api_key_id: str
    total_requests: int
    total_units: int
    last_seen_at: str | None = None
    routes: list[UsageRouteCount] = Field(default_factory=list)


class UsageEventView(BaseModel):
    timestamp: str
    api_key_id: str
    route: str
    method: str
    status_code: int
    units: int
    metadata: dict[str, Any] = Field(default_factory=dict)


class UsageSummaryListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total_keys: int
    summaries: list[UsageSummaryView] = Field(default_factory=list)


class UsageEventListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total_events: int
    events: list[UsageEventView] = Field(default_factory=list)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _summary_to_view(summary: UsageSummary) -> UsageSummaryView:
    routes = [
        UsageRouteCount(route=route, requests=requests)
        for route, requests in sorted(
            summary.routes.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]
    return UsageSummaryView(
        api_key_id=summary.api_key_id,
        total_requests=summary.total_requests,
        total_units=summary.total_units,
        last_seen_at=_to_iso(summary.last_seen_at),
        routes=routes,
    )


def _event_to_view(event: UsageEvent) -> UsageEventView:
    return UsageEventView(
        timestamp=_to_iso(event.timestamp) or _utc_now_iso(),
        api_key_id=event.api_key_id,
        route=event.route,
        method=event.method,
        status_code=event.status_code,
        units=event.units,
        metadata=event.metadata or {},
    )


@router.get("", response_model=UsageSummaryListResponse)
def list_usage_summaries() -> UsageSummaryListResponse:
    registry = get_usage_metering_registry()
    summaries = registry.list_summaries()
    summaries = sorted(
        summaries,
        key=lambda summary: (-summary.total_units, -summary.total_requests, summary.api_key_id),
    )

    return UsageSummaryListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total_keys=len(summaries),
        summaries=[_summary_to_view(summary) for summary in summaries],
    )


@router.get("/events", response_model=UsageEventListResponse)
def list_usage_events(
    limit: int = Query(default=50, ge=1, le=200),
) -> UsageEventListResponse:
    registry = get_usage_metering_registry()
    events = registry.recent_events(limit=limit)

    return UsageEventListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total_events=len(events),
        events=[_event_to_view(event) for event in reversed(events)],
    )
