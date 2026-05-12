from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_signals_summary import build_prompt_guard_signals_summary
from app.ui.groq.prompt_guard_timeline_summary import build_prompt_guard_timeline_summary
from app.ui.groq.prompt_guard_trends_summary import build_prompt_guard_trends_summary

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-alerts-timeline-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


TimelineAlertSeverity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(slots=True)
class PromptGuardAlertsTimelineItem:
    id: str
    title: str
    severity: TimelineAlertSeverity
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
class PromptGuardAlertsTimelineSummary:
    generated_at: str
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    entries: list[PromptGuardAlertsTimelineItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "total_alerts": self.total_alerts,
            "critical_alerts": self.critical_alerts,
            "high_alerts": self.high_alerts,
            "medium_alerts": self.medium_alerts,
            "low_alerts": self.low_alerts,
            "entries": [entry.to_dict() for entry in self.entries],
            "metadata": dict(self.metadata),
        }


class PromptGuardAlertsTimelineItemResponse(BaseModel):
    id: str
    title: str
    severity: TimelineAlertSeverity
    status: str | None = None
    timestamp: str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class PromptGuardAlertsTimelineSummaryResponse(BaseModel):
    generated_at: str
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    entries: list[PromptGuardAlertsTimelineItemResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _normalize_severity(value: str | None) -> TimelineAlertSeverity:
    normalized = (value or "info").strip().lower()
    mapping: dict[str, TimelineAlertSeverity] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(normalized, "info")


def _severity_rank(value: TimelineAlertSeverity) -> int:
    rank: dict[TimelineAlertSeverity, int] = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return rank[value]


def build_prompt_guard_alerts_timeline_summary() -> PromptGuardAlertsTimelineSummary:
    generated_at = _utc_now()

    alerts = build_prompt_guard_alerts_overview()
    timeline = build_prompt_guard_timeline_summary()
    signals = build_prompt_guard_signals_summary()
    trends = build_prompt_guard_trends_summary()

    entries: list[PromptGuardAlertsTimelineItem] = []

    for alert in alerts.latest_alerts:
        entries.append(
            PromptGuardAlertsTimelineItem(
                id=f"alerts-timeline:alert:{alert.id}",
                title=alert.title,
                severity=_normalize_severity(alert.severity),
                status=alert.status,
                timestamp=alert.timestamp,
                source_module=alert.source_module,
                details=alert.details,
                tags=list(alert.tags),
            )
        )

    for entry in timeline.entries:
        severity = _normalize_severity(entry.severity)
        if severity == "info":
            continue
        entries.append(
            PromptGuardAlertsTimelineItem(
                id=f"alerts-timeline:timeline:{entry.id}",
                title=entry.title,
                severity=severity,
                status=entry.status,
                timestamp=entry.timestamp,
                source_module=entry.source_module,
                details=entry.details,
                tags=list(entry.tags),
            )
        )

    for signal in signals.latest_signals:
        severity = _normalize_severity(signal.severity)
        if severity in {"critical", "high", "medium"}:
            entries.append(
                PromptGuardAlertsTimelineItem(
                    id=f"alerts-timeline:signal:{signal.id}",
                    title=signal.title,
                    severity=severity,
                    status=signal.status,
                    timestamp=signal.timestamp,
                    source_module=signal.source_module,
                    details=signal.details,
                    tags=list(signal.tags),
                )
            )

    latest_snapshot = trends.latest_snapshot
    if latest_snapshot is not None:
        blocked = int(latest_snapshot.get("blocked_requests", 0) or 0)
        flagged = int(latest_snapshot.get("flagged_requests", 0) or 0)
        severity: TimelineAlertSeverity = (
            "critical" if blocked >= 10 else
            "high" if blocked > 0 else
            "medium" if flagged > 0 else
            "low"
        )
        entries.append(
            PromptGuardAlertsTimelineItem(
                id=f"alerts-timeline:trend:{latest_snapshot.get('timestamp', generated_at)}",
                title="Latest trend snapshot alert state",
                severity=severity,
                status=trends.trend_status,
                timestamp=latest_snapshot.get("timestamp", generated_at),
                source_module="prompt_guard_trends_summary",
                details=latest_snapshot,
                tags=["trend", "snapshot"],
            )
        )

    entries.sort(key=lambda item: (_severity_rank(item.severity), item.timestamp), reverse=False)
    entries = sorted(entries, key=lambda item: item.timestamp, reverse=True)[:24]

    critical_alerts = sum(1 for item in entries if item.severity == "critical")
    high_alerts = sum(1 for item in entries if item.severity == "high")
    medium_alerts = sum(1 for item in entries if item.severity == "medium")
    low_alerts = sum(1 for item in entries if item.severity == "low")

    return PromptGuardAlertsTimelineSummary(
        generated_at=generated_at,
        total_alerts=len(entries),
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,
        entries=entries,
        metadata={
            "source_modules": [
                "prompt_guard_alerts_overview",
                "prompt_guard_timeline_summary",
                "prompt_guard_signals_summary",
                "prompt_guard_trends_summary",
            ],
            "entry_limit": 24,
            "trend_status": trends.trend_status,
        },
    )


@router.get(
    "/prompt-guard/alerts-timeline-summary",
    response_model=PromptGuardAlertsTimelineSummaryResponse,
)
def get_prompt_guard_alerts_timeline_summary() -> PromptGuardAlertsTimelineSummaryResponse:
    summary = build_prompt_guard_alerts_timeline_summary()
    data = summary.to_dict()

    return PromptGuardAlertsTimelineSummaryResponse(
        generated_at=data["generated_at"],
        total_alerts=data["total_alerts"],
        critical_alerts=data["critical_alerts"],
        high_alerts=data["high_alerts"],
        medium_alerts=data["medium_alerts"],
        low_alerts=data["low_alerts"],
        entries=[
            PromptGuardAlertsTimelineItemResponse(**entry)
            for entry in data["entries"]
        ],
        metadata=data["metadata"],
    )