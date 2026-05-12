from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_health_snapshot import build_prompt_guard_health_snapshot
from app.ui.groq.prompt_guard_metrics import build_prompt_guard_metrics_view
from app.ui.groq.prompt_guard_performance_snapshot import build_prompt_guard_performance_snapshot
from app.ui.groq.prompt_guard_review_queue_summary import build_prompt_guard_review_queue_summary
from app.ui.groq.prompt_guard_signals_summary import build_prompt_guard_signals_summary

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-kpi-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PromptGuardKpiCard:
    id: str
    name: str
    value: float | int | str
    label: str
    trend: str | None
    source_module: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "value": self.value,
            "label": self.label,
            "trend": self.trend,
            "source_module": self.source_module,
            "details": dict(self.details),
        }


@dataclass(slots=True)
class PromptGuardKpiSummary:
    generated_at: str
    cards: list[PromptGuardKpiCard] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "cards": [card.to_dict() for card in self.cards],
            "metadata": dict(self.metadata),
        }


class PromptGuardKpiCardResponse(BaseModel):
    id: str
    name: str
    value: float | int | str
    label: str
    trend: str | None = None
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)


class PromptGuardKpiSummaryResponse(BaseModel):
    generated_at: str
    cards: list[PromptGuardKpiCardResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _find_kpi_value(metrics: Any, *names: str, default: float | int = 0) -> float | int:
    for name in names:
        match = next((kpi for kpi in metrics.kpis if kpi.name == name), None)
        if match is not None:
            return match.value
    return default


def build_prompt_guard_kpi_summary() -> PromptGuardKpiSummary:
    generated_at = _utc_now()

    metrics = build_prompt_guard_metrics_view()
    health = build_prompt_guard_health_snapshot()
    performance = build_prompt_guard_performance_snapshot()
    queue = build_prompt_guard_review_queue_summary()
    signals = build_prompt_guard_signals_summary()

    throughput_value = _find_kpi_value(metrics, "throughput_rpm", "throughput_rps", default=0)
    total_reviews = _find_kpi_value(metrics, "total_reviews", default=queue.review_queue_total)
    pass_rate = _find_kpi_value(metrics, "pass_rate", "allow_rate", default=0)
    block_rate = _find_kpi_value(metrics, "block_rate", default=0)
    flagged_total = performance.flagged_requests
    blocked_total = performance.blocked_requests
    critical_signals = signals.critical_signals

    cards = [
        PromptGuardKpiCard(
            id="kpi:throughput",
            name="throughput",
            value=throughput_value,
            label="Traffic throughput",
            trend=health.trend_status,
            source_module="prompt_guard_metrics",
            details={
                "raw_value": throughput_value,
                "trend_status": health.trend_status,
            },
        ),
        PromptGuardKpiCard(
            id="kpi:review-queue",
            name="review_queue_total",
            value=total_reviews,
            label="Review queue total",
            trend=queue.queue_status,
            source_module="prompt_guard_review_queue_summary",
            details={
                "queue_status": queue.queue_status,
                "recommendation_backlog": queue.recommendation_backlog,
            },
        ),
        PromptGuardKpiCard(
            id="kpi:blocked",
            name="blocked_requests",
            value=blocked_total,
            label="Blocked requests",
            trend="elevated" if blocked_total > 0 else "stable",
            source_module="prompt_guard_performance_snapshot",
            details={
                "error_pressure": performance.error_pressure,
                "request_volume": performance.request_volume,
            },
        ),
        PromptGuardKpiCard(
            id="kpi:flagged",
            name="flagged_requests",
            value=flagged_total,
            label="Flagged requests",
            trend="watch" if flagged_total > 0 else "stable",
            source_module="prompt_guard_performance_snapshot",
            details={
                "error_pressure": performance.error_pressure,
                "request_volume": performance.request_volume,
            },
        ),
        PromptGuardKpiCard(
            id="kpi:critical-signals",
            name="critical_signals",
            value=critical_signals,
            label="Critical signals",
            trend="critical" if critical_signals > 0 else "stable",
            source_module="prompt_guard_signals_summary",
            details={
                "total_signals": signals.total_signals,
                "signal_pressure": signals.signal_pressure,
            },
        ),
        PromptGuardKpiCard(
            id="kpi:pass-rate",
            name="pass_rate",
            value=pass_rate,
            label="Pass rate",
            trend="healthy" if isinstance(pass_rate, (int, float)) and pass_rate >= 0.9 else "watch",
            source_module="prompt_guard_metrics",
            details={
                "health_status": health.overall_status,
                "policy_mode": health.policy_mode,
            },
        ),
        PromptGuardKpiCard(
            id="kpi:block-rate",
            name="block_rate",
            value=block_rate,
            label="Block rate",
            trend="watch" if isinstance(block_rate, (int, float)) and block_rate > 0 else "stable",
            source_module="prompt_guard_metrics",
            details={
                "policy_health": health.policy_health,
                "policy_mode": health.policy_mode,
            },
        ),
    ]

    return PromptGuardKpiSummary(
        generated_at=generated_at,
        cards=cards,
        metadata={
            "source_modules": [
                "prompt_guard_metrics",
                "prompt_guard_health_snapshot",
                "prompt_guard_performance_snapshot",
                "prompt_guard_review_queue_summary",
                "prompt_guard_signals_summary",
            ],
            "card_count": len(cards),
        },
    )


@router.get(
    "/prompt-guard/kpi-summary",
    response_model=PromptGuardKpiSummaryResponse,
)
def get_prompt_guard_kpi_summary() -> PromptGuardKpiSummaryResponse:
    summary = build_prompt_guard_kpi_summary()
    data = summary.to_dict()

    return PromptGuardKpiSummaryResponse(
        generated_at=data["generated_at"],
        cards=[
            PromptGuardKpiCardResponse(**card)
            for card in data["cards"]
        ],
        metadata=data["metadata"],
    )