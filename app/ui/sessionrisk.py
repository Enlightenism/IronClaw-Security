from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/ui/session-risk", tags=["session-risk"])


class SessionRiskFilterOption(BaseModel):
    value: str
    label: str


class SessionRiskSeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class SessionRiskSummaryCard(BaseModel):
    key: str
    label: str
    value: str
    tone: str = "neutral"


class SessionRiskSignalItem(BaseModel):
    key: str
    label: str
    value: str
    tone: str = "neutral"


class SessionRiskTimelineEvent(BaseModel):
    timestamp: str
    title: str
    status: str
    risk_score: int = 0
    severity: str = "low"
    summary: str
    source: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionRiskReviewItem(BaseModel):
    review_id: str
    title: str
    status: str
    priority: str
    href: str


class SessionRiskRelatedLink(BaseModel):
    label: str
    href: str


class SessionRiskResponse(BaseModel):
    title: str
    description: str
    session_id: str
    client_id: str | None = None
    overall_risk_level: str
    policy_mode: str
    generated_at: str
    summary_cards: list[SessionRiskSummaryCard] = Field(default_factory=list)
    severity_breakdown: SessionRiskSeverityBreakdown = Field(default_factory=SessionRiskSeverityBreakdown)
    signals: list[SessionRiskSignalItem] = Field(default_factory=list)
    recent_reviews: list[SessionRiskReviewItem] = Field(default_factory=list)
    timeline: list[SessionRiskTimelineEvent] = Field(default_factory=list)
    available_filters: list[SessionRiskFilterOption] = Field(default_factory=list)
    related_links: list[SessionRiskRelatedLink] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


_DEFAULT_FILTERS: tuple[SessionRiskFilterOption, ...] = (
    SessionRiskFilterOption(value="all", label="All activity"),
    SessionRiskFilterOption(value="executions", label="Executions"),
    SessionRiskFilterOption(value="reviews", label="Reviews"),
    SessionRiskFilterOption(value="policy", label="Policy"),
)


def _normalize_session_id(session_id: str) -> str:
    return session_id.strip()


def _normalize_client_id(client_id: str | None) -> str | None:
    if client_id is None:
        return None
    normalized = client_id.strip()
    return normalized or None


def _risk_level_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def _tone_for_level(level: str) -> str:
    return {
        "critical": "danger",
        "high": "danger",
        "medium": "warning",
        "low": "success",
    }.get(level, "neutral")


def _build_summary_cards(
    highest_risk_score: int,
    total_events: int,
    pending_reviews: int,
    risk_level: str,
) -> list[SessionRiskSummaryCard]:
    return [
        SessionRiskSummaryCard(
            key="risk_level",
            label="Overall Risk",
            value=risk_level.replace("_", " ").title(),
            tone=_tone_for_level(risk_level),
        ),
        SessionRiskSummaryCard(
            key="highest_risk",
            label="Highest Risk Score",
            value=str(highest_risk_score),
            tone=_tone_for_level(_risk_level_from_score(highest_risk_score)),
        ),
        SessionRiskSummaryCard(
            key="pending_reviews",
            label="Pending Reviews",
            value=str(pending_reviews),
            tone="warning" if pending_reviews > 0 else "success",
        ),
        SessionRiskSummaryCard(
            key="total_events",
            label="Tracked Events",
            value=str(total_events),
            tone="neutral",
        ),
    ]


def _build_signals(
    *,
    session_id: str,
    client_id: str | None,
    highest_risk_score: int,
    pending_reviews: int,
    policy_mode: str,
    risk_level: str,
) -> list[SessionRiskSignalItem]:
    return [
        SessionRiskSignalItem(key="session_id", label="Session ID", value=session_id),
        SessionRiskSignalItem(key="client_id", label="Client ID", value=client_id or "unknown"),
        SessionRiskSignalItem(key="policy_mode", label="Policy Mode", value=policy_mode.title()),
        SessionRiskSignalItem(
            key="risk_level",
            label="Risk Level",
            value=risk_level.title(),
            tone=_tone_for_level(risk_level),
        ),
        SessionRiskSignalItem(
            key="highest_risk",
            label="Highest Risk",
            value=str(highest_risk_score),
            tone=_tone_for_level(_risk_level_from_score(highest_risk_score)),
        ),
        SessionRiskSignalItem(
            key="pending_reviews",
            label="Pending Reviews",
            value=str(pending_reviews),
            tone="warning" if pending_reviews > 0 else "success",
        ),
    ]


def _build_related_links(session_id: str) -> list[SessionRiskRelatedLink]:
    return [
        SessionRiskRelatedLink(label="Session timeline", href=f"/ui/activity/session/{session_id}"),
        SessionRiskRelatedLink(label="Request context", href="/request-context"),
        SessionRiskRelatedLink(label="Runtime status", href="/ui/runtime-status"),
        SessionRiskRelatedLink(label="Review queue", href="/reviews/queue"),
    ]


@router.get("/{session_id}", response_model=SessionRiskResponse, summary="Get session risk")
def get_session_risk(
    session_id: str,
    client_id: str | None = Query(default=None),
) -> SessionRiskResponse:
    normalized_session_id = _normalize_session_id(session_id)
    normalized_client_id = _normalize_client_id(client_id)

    generated_at = "2026-04-27T15:55:00Z"
    highest_risk_score = 0
    pending_reviews = 0
    total_events = 0
    policy_mode = "review"
    risk_level = _risk_level_from_score(highest_risk_score)

    return SessionRiskResponse(
        title="Session Risk",
        description="Session-scoped risk view for execution pressure, review load, and policy signals.",
        session_id=normalized_session_id,
        client_id=normalized_client_id,
        overall_risk_level=risk_level,
        policy_mode=policy_mode,
        generated_at=generated_at,
        summary_cards=_build_summary_cards(
            highest_risk_score=highest_risk_score,
            total_events=total_events,
            pending_reviews=pending_reviews,
            risk_level=risk_level,
        ),
        severity_breakdown=SessionRiskSeverityBreakdown(),
        signals=_build_signals(
            session_id=normalized_session_id,
            client_id=normalized_client_id,
            highest_risk_score=highest_risk_score,
            pending_reviews=pending_reviews,
            policy_mode=policy_mode,
            risk_level=risk_level,
        ),
        recent_reviews=[],
        timeline=[],
        available_filters=list(_DEFAULT_FILTERS),
        related_links=_build_related_links(normalized_session_id),
        metadata={
            "empty_state": True,
            "session_found": False,
            "integration_mode": "ui-shell",
        },
    )
