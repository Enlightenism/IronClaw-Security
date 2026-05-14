from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/telemetry-access-summary",
    tags=["telemetry-access-summary"],
)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class TelemetrySummaryCounterView(BaseModel):
    label: str
    value: int
    trend: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class TelemetrySummaryWindowView(BaseModel):
    summary_limit: int
    events_limit: int
    time_window: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class TelemetrySummaryEventView(BaseModel):
    event_id: str
    occurred_at: str
    event_type: str
    actor_id: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    outcome: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class TelemetrySummaryLinkView(BaseModel):
    label: str
    path: str
    description: str


class TelemetryAccessSummaryResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    window: TelemetrySummaryWindowView
    counters: list[TelemetrySummaryCounterView] = Field(default_factory=list)
    recent_events: list[TelemetrySummaryEventView] = Field(default_factory=list)
    links: list[TelemetrySummaryLinkView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_counters(
    summary_limit: int,
    events_limit: int,
) -> list[TelemetrySummaryCounterView]:
    return [
        TelemetrySummaryCounterView(
            label="Telemetry reads",
            value=0,
            trend="stable",
            metadata={
                "summary_limit": summary_limit,
                "source": "telemetry-access-summary-ui",
            },
        ),
        TelemetrySummaryCounterView(
            label="Audit-linked accesses",
            value=0,
            trend="stable",
            metadata={
                "events_limit": events_limit,
                "source": "telemetry-access-summary-ui",
            },
        ),
        TelemetrySummaryCounterView(
            label="Policy-sensitive events",
            value=0,
            trend="stable",
            metadata={
                "classification": "guard-aware",
                "source": "telemetry-access-summary-ui",
            },
        ),
    ]


def _build_links() -> list[TelemetrySummaryLinkView]:
    return [
        TelemetrySummaryLinkView(
            label="Audit log",
            path="/ui/audit-log",
            description="Inspect audit events related to telemetry access and review activity.",
        ),
        TelemetrySummaryLinkView(
            label="Runtime status",
            path="/ui/runtime-status",
            description="Check runtime health and current service readiness.",
        ),
        TelemetrySummaryLinkView(
            label="Request context",
            path="/ui/request-context",
            description="Inspect normalized request identity and policy context.",
        ),
        TelemetrySummaryLinkView(
            label="Usage reports",
            path="/ui/usage-reports",
            description="Review usage summaries and recent metered events.",
        ),
    ]


@router.get("", response_model=TelemetryAccessSummaryResponse)
def get_telemetry_access_summary(
    summary_limit: int = Query(default=500, ge=1, le=5000),
    events_limit: int = Query(default=50, ge=1, le=500),
) -> TelemetryAccessSummaryResponse:
    return TelemetryAccessSummaryResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        window=TelemetrySummaryWindowView(
            summary_limit=summary_limit,
            events_limit=events_limit,
            time_window="rolling",
            metadata={
                "ui_surface": "telemetry-access-summary",
                "default_mode": "safe-empty",
            },
        ),
        counters=_build_counters(
            summary_limit=summary_limit,
            events_limit=events_limit,
        ),
        recent_events=[],
        links=_build_links(),
        notes=[
            "Telemetry access summary provides a UI-safe overview of telemetry reads and related operational activity.",
            "This Gen1 view returns a stable empty-state structure until live telemetry hydration is connected.",
            "Query parameters let operators tune summary and recent-event window sizes without changing the response contract.",
        ],
    )
