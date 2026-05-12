from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_activity_feed import build_prompt_guard_activity_feed
from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_performance_snapshot import build_prompt_guard_performance_snapshot
from app.ui.groq.prompt_guard_trends import build_prompt_guard_trend_series

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-timeline-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


TimelineSeverity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(slots=True)
class PromptGuardTimelineEntry:
    id: str
    title: str
    severity: TimelineSeverity
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


@dataclass(slots=True)
class PromptGuardTimelineSummary:
    generated_at: str
    total_entries: int
    interval_minutes: int
    lookback_hours: int
    entries: list[PromptGuardTimelineEntry] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "total_entries": self.total_entries,
            "interval_minutes": self.interval_minutes,
            "lookback_hours": self.lookback_hours,
            "entries": [entry.to_dict() for entry in self.entries],
            "metadata": dict(self.metadata),
        }


class PromptGuardTimelineEntryResponse(BaseModel):
    id: str
    title: str
    severity: TimelineSeverity
    status: str | None = None
    timestamp: str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class PromptGuardTimelineSummaryResponse(BaseModel):
    generated_at: str
    total_entries: int
    interval_minutes: int
    lookback_hours: int
    entries: list[PromptGuardTimelineEntryResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _normalize_severity(value: str | None) -> TimelineSeverity:
    normalized = (value or "info").strip().lower()
    mapping: dict[str, TimelineSeverity] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(normalized, "info")


def _trend_entry_severity(point: dict[str, Any]) -> TimelineSeverity:
    blocked = int(point.get("blocked_requests", 0) or 0)
    flagged = int(point.get("flagged_requests", 0) or 0)

    if blocked >= 10:
        return "critical"
    if blocked > 0:
        return "high"
    if flagged > 0:
        return "medium"
    return "low"


def build_prompt_guard_timeline_summary() -> PromptGuardTimelineSummary:
    generated_at = _utc_now()

    trends = build_prompt_guard_trend_series()
    activity_feed = build_prompt_guard_activity_feed()
    alerts = build_prompt_guard_alerts_overview()
    performance = build_prompt_guard_performance_snapshot()

    entries: list[PromptGuardTimelineEntry] = []

    for point in trends.points:
        point_data = point.to_dict()
        entries.append(
            PromptGuardTimelineEntry(
                id=f"timeline:trend:{point_data.get('bucket_start', generated_at)}",
                title="Trend bucket snapshot",
                severity=_trend_entry_severity(point_data),
                status="recorded",
                timestamp=point_data.get("bucket_start", generated_at),
                source_module="prompt_guard_trends",
                details=point_data,
                tags=["trend", "bucket"],
            )
        )

    for item in activity_feed.items:
        entries.append(
            PromptGuardTimelineEntry(
                id=f"timeline:activity:{item.id}",
                title=item.title,
                severity=_normalize_severity(item.severity),
                status=item.status,
                timestamp=item.timestamp,
                source_module=item.source_module,
                details=item.details,
                tags=list(item.tags),
            )
        )

    for alert in alerts.latest_alerts:
        entries.append(
            PromptGuardTimelineEntry(
                id=f"timeline:alert:{alert.id}",
                title=alert.title,
                severity=_normalize_severity(alert.severity),
                status=alert.status,
                timestamp=alert.timestamp,
                source_module=alert.source_module,
                details=alert.details,
                tags=list(alert.tags),
            )
        )

    entries.sort(key=lambda entry: entry.timestamp, reverse=True)
    entries = entries[:24]

    return PromptGuardTimelineSummary(
        generated_at=generated_at,
        total_entries=len(entries),
        interval_minutes=int(getattr(trends, "interval_minutes", 0) or 0),
        lookback_hours=int(getattr(trends, "lookback_hours", 0) or 0),
        entries=entries,
        metadata={
            "source_modules": [
                "prompt_guard_trends",
                "prompt_guard_activity_feed",
                "prompt_guard_alerts_overview",
                "prompt_guard_performance_snapshot",
            ],
            "latest_request_volume": performance.request_volume,
            "latest_error_pressure": performance.error_pressure,
            "entry_limit": 24,
        },
    )


@router.get(
    "/prompt-guard/timeline-summary",
    response_model=PromptGuardTimelineSummaryResponse,
)
def get_prompt_guard_timeline_summary() -> PromptGuardTimelineSummaryResponse:
    summary = build_prompt_guard_timeline_summary()
    data = summary.to_dict()

    return PromptGuardTimelineSummaryResponse(
        generated_at=data["generated_at"],
        total_entries=data["total_entries"],
        interval_minutes=data["interval_minutes"],
        lookback_hours=data["lookback_hours"],
        entries=[
            PromptGuardTimelineEntryResponse(**entry)
            for entry in data["entries"]
        ],
        metadata=data["metadata"],
    )