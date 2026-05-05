from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_health_snapshot import build_prompt_guard_health_snapshot
from app.ui.groq.prompt_guard_performance_snapshot import build_prompt_guard_performance_snapshot
from app.ui.groq.prompt_guard_review_queue_summary import build_prompt_guard_review_queue_summary
from app.ui.groq.prompt_guard_risk_posture_summary import build_prompt_guard_risk_posture_summary
from app.ui.groq.prompt_guard_signals_summary import build_prompt_guard_signals_summary


router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-status-board-summary"],
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


BoardStatus = Literal["healthy", "warning", "degraded", "critical"]


@dataclass(slots=True)
class PromptGuardStatusBoardCard:
    id: str
    title: str
    status: str
    value: str
    source_module: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "value": self.value,
            "source_module": self.source_module,
            "details": dict(self.details),
        }


@dataclass(slots=True)
class PromptGuardStatusBoardSummary:
    generated_at: str
    overall_status: BoardStatus
    board_cards: list[PromptGuardStatusBoardCard] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "board_cards": [card.to_dict() for card in self.board_cards],
            "metadata": dict(self.metadata),
        }


class PromptGuardStatusBoardCardResponse(BaseModel):
    id: str
    title: str
    status: str
    value: str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)


class PromptGuardStatusBoardSummaryResponse(BaseModel):
    generated_at: str
    overall_status: BoardStatus
    board_cards: list[PromptGuardStatusBoardCardResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _status_rank(value: str) -> int:
    mapping = {
        "healthy": 0,
        "low": 0,
        "moderate": 1,
        "warning": 1,
        "normal": 1,
        "busy": 2,
        "degraded": 2,
        "elevated": 2,
        "high": 2,
        "critical": 3,
    }
    return mapping.get((value or "").strip().lower(), 0)


def _derive_overall_status(statuses: list[str]) -> BoardStatus:
    highest = max((_status_rank(status) for status in statuses), default=0)
    if highest >= 3:
        return "critical"
    if highest == 2:
        return "degraded"
    if highest == 1:
        return "warning"
    return "healthy"


def build_prompt_guard_status_board_summary() -> PromptGuardStatusBoardSummary:
    generated_at = _utc_now()

    health = build_prompt_guard_health_snapshot()
    risk = build_prompt_guard_risk_posture_summary()
    performance = build_prompt_guard_performance_snapshot()
    queue = build_prompt_guard_review_queue_summary()
    alerts = build_prompt_guard_alerts_overview()
    signals = build_prompt_guard_signals_summary()

    board_cards = [
        PromptGuardStatusBoardCard(
            id="card:health",
            title="System health",
            status=health.overall_status,
            value=health.overall_status.upper(),
            source_module="prompt_guard_health_snapshot",
            details={
                "policy_mode": health.policy_mode,
                "policy_health": health.policy_health,
                "trend_status": health.trend_status,
            },
        ),
        PromptGuardStatusBoardCard(
            id="card:risk",
            title="Risk posture",
            status=risk.overall_risk_level,
            value=risk.overall_risk_level.upper(),
            source_module="prompt_guard_risk_posture_summary",
            details={
                "critical_alerts": risk.critical_alerts,
                "open_alerts": risk.open_alerts,
                "incident_coverage_ratio": risk.incident_coverage_ratio,
            },
        ),
        PromptGuardStatusBoardCard(
            id="card:performance",
            title="Request pressure",
            status="critical" if performance.error_pressure >= 0.2 else "degraded" if performance.error_pressure >= 0.1 else "healthy",
            value=str(performance.request_volume),
            source_module="prompt_guard_performance_snapshot",
            details={
                "blocked_requests": performance.blocked_requests,
                "flagged_requests": performance.flagged_requests,
                "error_pressure": performance.error_pressure,
            },
        ),
        PromptGuardStatusBoardCard(
            id="card:queue",
            title="Review queue",
            status=queue.queue_status,
            value=str(queue.review_queue_total),
            source_module="prompt_guard_review_queue_summary",
            details={
                "critical_alerts": queue.critical_alerts,
                "warning_alerts": queue.warning_alerts,
                "recommendation_backlog": queue.recommendation_backlog,
            },
        ),
        PromptGuardStatusBoardCard(
            id="card:alerts",
            title="Open alerts",
            status="critical" if alerts.critical_alerts > 0 else "warning" if alerts.warning_alerts > 0 else "healthy",
            value=str(alerts.open_alerts),
            source_module="prompt_guard_alerts_overview",
            details={
                "critical_alerts": alerts.critical_alerts,
                "warning_alerts": alerts.warning_alerts,
                "review_queue_total": alerts.review_queue_total,
            },
        ),
        PromptGuardStatusBoardCard(
            id="card:signals",
            title="Signal pressure",
            status="critical" if signals.critical_signals > 0 else "degraded" if signals.high_signals > 0 else "warning" if signals.medium_signals > 0 else "healthy",
            value=str(signals.total_signals),
            source_module="prompt_guard_signals_summary",
            details={
                "critical_signals": signals.critical_signals,
                "high_signals": signals.high_signals,
                "medium_signals": signals.medium_signals,
                "signal_pressure": signals.signal_pressure,
            },
        ),
    ]

    overall_status = _derive_overall_status([card.status for card in board_cards])

    return PromptGuardStatusBoardSummary(
        generated_at=generated_at,
        overall_status=overall_status,
        board_cards=board_cards,
        metadata={
            "source_modules": [
                "prompt_guard_health_snapshot",
                "prompt_guard_risk_posture_summary",
                "prompt_guard_performance_snapshot",
                "prompt_guard_review_queue_summary",
                "prompt_guard_alerts_overview",
                "prompt_guard_signals_summary",
            ],
            "card_count": len(board_cards),
        },
    )


@router.get(
    "/prompt-guard/status-board-summary",
    response_model=PromptGuardStatusBoardSummaryResponse,
)
def get_prompt_guard_status_board_summary() -> PromptGuardStatusBoardSummaryResponse:
    summary = build_prompt_guard_status_board_summary()
    data = summary.to_dict()

    return PromptGuardStatusBoardSummaryResponse(
        generated_at=data["generated_at"],
        overall_status=data["overall_status"],
        board_cards=[
            PromptGuardStatusBoardCardResponse(**card)
            for card in data["board_cards"]
        ],
        metadata=data["metadata"],
    )