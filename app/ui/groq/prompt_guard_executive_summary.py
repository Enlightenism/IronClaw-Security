from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_health_snapshot import build_prompt_guard_health_snapshot
from app.ui.groq.prompt_guard_performance_snapshot import build_prompt_guard_performance_snapshot
from app.ui.groq.prompt_guard_review_queue_summary import build_prompt_guard_review_queue_summary
from app.ui.groq.prompt_guard_risk_posture_summary import build_prompt_guard_risk_posture_summary
from app.ui.groq.prompt_guard_status_board_summary import build_prompt_guard_status_board_summary

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-executive-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


ExecutiveTone = Literal["stable", "watch", "action-required", "critical"]


@dataclass(slots=True)
class PromptGuardExecutiveHighlight:
    id: str
    title: str
    tone: ExecutiveTone
    summary: str
    source_module: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "tone": self.tone,
            "summary": self.summary,
            "source_module": self.source_module,
            "details": dict(self.details),
        }


@dataclass(slots=True)
class PromptGuardExecutiveSummary:
    generated_at: str
    overall_tone: ExecutiveTone
    headline: str
    key_message: str
    highlights: list[PromptGuardExecutiveHighlight] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_tone": self.overall_tone,
            "headline": self.headline,
            "key_message": self.key_message,
            "highlights": [item.to_dict() for item in self.highlights],
            "metadata": dict(self.metadata),
        }


class PromptGuardExecutiveHighlightResponse(BaseModel):
    id: str
    title: str
    tone: ExecutiveTone
    summary: str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)


class PromptGuardExecutiveSummaryResponse(BaseModel):
    generated_at: str
    overall_tone: ExecutiveTone
    headline: str
    key_message: str
    highlights: list[PromptGuardExecutiveHighlightResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _tone_rank(value: str) -> int:
    mapping = {
        "stable": 0,
        "healthy": 0,
        "watch": 1,
        "warning": 1,
        "normal": 1,
        "moderate": 1,
        "action-required": 2,
        "degraded": 2,
        "busy": 2,
        "elevated": 2,
        "high": 2,
        "critical": 3,
    }
    return mapping.get((value or "").strip().lower(), 0)


def _normalize_tone(value: str) -> ExecutiveTone:
    normalized = (value or "").strip().lower()
    if normalized in {"critical"}:
        return "critical"
    if normalized in {"action-required", "degraded", "busy", "elevated", "high"}:
        return "action-required"
    if normalized in {"watch", "warning", "normal", "moderate"}:
        return "watch"
    return "stable"


def _derive_headline(overall_tone: ExecutiveTone) -> str:
    if overall_tone == "critical":
        return "Prompt Guard is operating under critical risk pressure"
    if overall_tone == "action-required":
        return "Prompt Guard needs focused operational follow-up"
    if overall_tone == "watch":
        return "Prompt Guard is stable with items to monitor"
    return "Prompt Guard is stable and operating within expected bounds"


def _derive_key_message(
    health: Any,
    risk: Any,
    queue: Any,
    performance: Any,
    alerts: Any,
) -> str:
    if risk.overall_risk_level == "critical" or alerts.critical_alerts > 0:
        return f"Critical signals are present with {alerts.critical_alerts} critical alerts, {queue.review_queue_total} reviews queued, and trend status '{health.trend_status}'."
    if queue.queue_status in {"critical", "elevated", "busy"}:
        return f"Review operations are under load with {queue.review_queue_total} queued items and {alerts.warning_alerts} warning alerts requiring attention."
    if performance.error_pressure >= 0.1:
        return f"Traffic is flowing, but error pressure is elevated at {performance.error_pressure} with {performance.blocked_requests} blocked and {performance.flagged_requests} flagged requests."
    return f"System health is {health.overall_status}, risk posture is {risk.overall_risk_level}, and the review queue is at {queue.review_queue_total} items."


def build_prompt_guard_executive_summary() -> PromptGuardExecutiveSummary:
    generated_at = _utc_now()

    health = build_prompt_guard_health_snapshot()
    risk = build_prompt_guard_risk_posture_summary()
    performance = build_prompt_guard_performance_snapshot()
    queue = build_prompt_guard_review_queue_summary()
    alerts = build_prompt_guard_alerts_overview()
    status_board = build_prompt_guard_status_board_summary()

    tones = [
        _normalize_tone(health.overall_status),
        _normalize_tone(risk.overall_risk_level),
        _normalize_tone(queue.queue_status),
        _normalize_tone(status_board.overall_status),
        "critical" if alerts.critical_alerts > 0 else "watch" if alerts.warning_alerts > 0 else "stable",
    ]
    overall_tone = max(tones, key=_tone_rank)

    headline = _derive_headline(overall_tone)
    key_message = _derive_key_message(
        health=health,
        risk=risk,
        queue=queue,
        performance=performance,
        alerts=alerts,
    )

    highlights = [
        PromptGuardExecutiveHighlight(
            id="exec:health",
            title="System health",
            tone=_normalize_tone(health.overall_status),
            summary=(f"Overall health is {health.overall_status} with policy mode '{health.policy_mode}' and trend status '{health.trend_status}'."),
            source_module="prompt_guard_health_snapshot",
            details={
                "policy_mode": health.policy_mode,
                "policy_health": health.policy_health,
                "trend_status": health.trend_status,
            },
        ),
        PromptGuardExecutiveHighlight(
            id="exec:risk",
            title="Risk posture",
            tone=_normalize_tone(risk.overall_risk_level),
            summary=(f"Risk posture is {risk.overall_risk_level} with {risk.critical_alerts} critical alerts and incident coverage ratio {risk.incident_coverage_ratio}."),
            source_module="prompt_guard_risk_posture_summary",
            details={
                "overall_risk_level": risk.overall_risk_level,
                "critical_alerts": risk.critical_alerts,
                "incident_coverage_ratio": risk.incident_coverage_ratio,
            },
        ),
        PromptGuardExecutiveHighlight(
            id="exec:queue",
            title="Review queue",
            tone=_normalize_tone(queue.queue_status),
            summary=(f"Queue status is {queue.queue_status} with {queue.review_queue_total} total reviews and backlog pressure from {queue.recommendation_backlog} recommendations."),
            source_module="prompt_guard_review_queue_summary",
            details={
                "queue_status": queue.queue_status,
                "review_queue_total": queue.review_queue_total,
                "recommendation_backlog": queue.recommendation_backlog,
            },
        ),
        PromptGuardExecutiveHighlight(
            id="exec:performance",
            title="Traffic pressure",
            tone="action-required" if performance.error_pressure >= 0.1 else "watch" if performance.error_pressure > 0 else "stable",
            summary=(f"Current request volume is {performance.request_volume} with {performance.blocked_requests} blocked, {performance.flagged_requests} flagged, and error pressure {performance.error_pressure}."),
            source_module="prompt_guard_performance_snapshot",
            details={
                "request_volume": performance.request_volume,
                "blocked_requests": performance.blocked_requests,
                "flagged_requests": performance.flagged_requests,
                "error_pressure": performance.error_pressure,
            },
        ),
    ]

    return PromptGuardExecutiveSummary(
        generated_at=generated_at,
        overall_tone=overall_tone,
        headline=headline,
        key_message=key_message,
        highlights=highlights,
        metadata={
            "source_modules": [
                "prompt_guard_health_snapshot",
                "prompt_guard_risk_posture_summary",
                "prompt_guard_performance_snapshot",
                "prompt_guard_review_queue_summary",
                "prompt_guard_alerts_overview",
                "prompt_guard_status_board_summary",
            ],
            "highlight_count": len(highlights),
            "status_board_overall_status": status_board.overall_status,
        },
    )


@router.get(
    "/prompt-guard/executive-summary",
    response_model=PromptGuardExecutiveSummaryResponse,
)
def get_prompt_guard_executive_summary() -> PromptGuardExecutiveSummaryResponse:
    summary = build_prompt_guard_executive_summary()
    data = summary.to_dict()

    return PromptGuardExecutiveSummaryResponse(
        generated_at=data["generated_at"],
        overall_tone=data["overall_tone"],
        headline=data["headline"],
        key_message=data["key_message"],
        highlights=[PromptGuardExecutiveHighlightResponse(**item) for item in data["highlights"]],
        metadata=data["metadata"],
    )
