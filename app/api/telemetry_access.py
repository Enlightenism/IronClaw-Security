from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.services.telemetry import (
    append_telemetry_event,
    read_telemetry_events,
    summarize_telemetry_events,
)

router = APIRouter(prefix="/telemetry-access", tags=["telemetry-access"])


class TelemetryAccessSummaryResponse(BaseModel):
    telemetry_summary: dict[str, Any] = Field(default_factory=dict)
    recent_events: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/summary", response_model=TelemetryAccessSummaryResponse)
def get_telemetry_access_summary(
    summary_limit: int = Query(500, ge=1, le=5000),
    events_limit: int = Query(50, ge=1, le=500),
) -> TelemetryAccessSummaryResponse:
    telemetry_summary = summarize_telemetry_events(limit=summary_limit)
    recent_events = read_telemetry_events(limit=events_limit)

    try:
        append_telemetry_event(
            "telemetry_access_summary_requested",
            {
                "summary_limit": summary_limit,
                "events_limit": events_limit,
                "returned_event_count": len(recent_events),
            },
        )
    except Exception:
        pass

    return TelemetryAccessSummaryResponse(
        telemetry_summary=telemetry_summary,
        recent_events=recent_events,
    )