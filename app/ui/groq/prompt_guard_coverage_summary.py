from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_health_snapshot import build_prompt_guard_health_snapshot
from app.ui.groq.prompt_guard_incident_summary import build_prompt_guard_incident_summary
from app.ui.groq.prompt_guard_metrics import build_prompt_guard_metrics_view
from app.ui.groq.prompt_guard_review_queue_summary import build_prompt_guard_review_queue_summary
from app.ui.groq.prompt_guard_risk_posture_summary import build_prompt_guard_risk_posture_summary
from app.ui.groq.prompt_guard_signals_summary import build_prompt_guard_signals_summary

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-coverage-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


CoverageStatus = Literal["healthy", "moderate", "elevated", "critical"]


@dataclass(slots=True)
class PromptGuardCoverageArea:
    id: str
    title: str
    status: CoverageStatus
    value: float | int | str
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
class PromptGuardCoverageSummary:
    generated_at: str
    coverage_status: CoverageStatus
    incident_coverage_ratio: float
    linked_incidents: int
    unlinked_incidents: int
    coverage_areas: list[PromptGuardCoverageArea] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "coverage_status": self.coverage_status,
            "incident_coverage_ratio": self.incident_coverage_ratio,
            "linked_incidents": self.linked_incidents,
            "unlinked_incidents": self.unlinked_incidents,
            "coverage_areas": [area.to_dict() for area in self.coverage_areas],
            "metadata": dict(self.metadata),
        }


class PromptGuardCoverageAreaResponse(BaseModel):
    id: str
    title: str
    status: CoverageStatus
    value: float | int | str
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)


class PromptGuardCoverageSummaryResponse(BaseModel):
    generated_at: str
    coverage_status: CoverageStatus
    incident_coverage_ratio: float
    linked_incidents: int
    unlinked_incidents: int
    coverage_areas: list[PromptGuardCoverageAreaResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _status_from_ratio(ratio: float) -> CoverageStatus:
    if ratio < 0.35:
        return "critical"
    if ratio < 0.55:
        return "elevated"
    if ratio < 0.8:
        return "moderate"
    return "healthy"


def _status_rank(value: CoverageStatus) -> int:
    rank: dict[CoverageStatus, int] = {
        "healthy": 0,
        "moderate": 1,
        "elevated": 2,
        "critical": 3,
    }
    return rank[value]


def _worst_status(statuses: list[CoverageStatus]) -> CoverageStatus:
    if not statuses:
        return "healthy"
    return max(statuses, key=_status_rank)


def _find_metric_value(metrics: Any, name: str, default: float = 0) -> float | int:
    kpi = next((item for item in metrics.kpis if item.name == name), None)
    if kpi is None:
        return default
    return kpi.value


def build_prompt_guard_coverage_summary() -> PromptGuardCoverageSummary:
    generated_at = _utc_now()

    incident_summary = build_prompt_guard_incident_summary()
    metrics = build_prompt_guard_metrics_view()
    queue = build_prompt_guard_review_queue_summary()
    health = build_prompt_guard_health_snapshot()
    risk = build_prompt_guard_risk_posture_summary()
    signals = build_prompt_guard_signals_summary()

    summary = incident_summary.to_dict()
    incident_coverage_ratio = float(summary.get("incident_coverage_ratio", 0.0))
    linked_incidents = int(summary.get("linked_incidents", 0))
    unlinked_incidents = int(summary.get("unlinked_incidents", 0))
    total_incidents = int(summary.get("total_incidents", 0))

    review_queue_total = int(_find_metric_value(metrics, "total_reviews", queue.review_queue_total))
    critical_signals = int(signals.critical_signals)
    signal_pressure = float(signals.signal_pressure)

    coverage_areas = [
        PromptGuardCoverageArea(
            id="coverage:incidents",
            title="Incident linkage coverage",
            status=_status_from_ratio(incident_coverage_ratio),
            value=incident_coverage_ratio,
            source_module="prompt_guard_incident_summary",
            details={
                "total_incidents": total_incidents,
                "linked_incidents": linked_incidents,
                "unlinked_incidents": unlinked_incidents,
            },
        ),
        PromptGuardCoverageArea(
            id="coverage:queue",
            title="Review queue coverage pressure",
            status="critical" if review_queue_total >= 15 else "elevated" if review_queue_total >= 8 else "moderate" if review_queue_total > 0 else "healthy",
            value=review_queue_total,
            source_module="prompt_guard_review_queue_summary",
            details={
                "queue_status": queue.queue_status,
                "recommendation_backlog": queue.recommendation_backlog,
            },
        ),
        PromptGuardCoverageArea(
            id="coverage:signals",
            title="Signal handling coverage",
            status="critical" if critical_signals > 0 else "elevated" if signal_pressure >= 0.15 else "moderate" if signal_pressure > 0 else "healthy",
            value=signal_pressure,
            source_module="prompt_guard_signals_summary",
            details={
                "critical_signals": critical_signals,
                "total_signals": signals.total_signals,
                "signal_pressure": signal_pressure,
            },
        ),
        PromptGuardCoverageArea(
            id="coverage:health",
            title="System coverage posture",
            status="critical" if health.overall_status == "critical" else "elevated" if health.overall_status == "degraded" else "moderate" if health.overall_status == "warning" else "healthy",
            value=health.overall_status,
            source_module="prompt_guard_health_snapshot",
            details={
                "policy_mode": health.policy_mode,
                "policy_health": health.policy_health,
                "trend_status": health.trend_status,
            },
        ),
        PromptGuardCoverageArea(
            id="coverage:risk",
            title="Risk-aligned coverage posture",
            status="critical" if risk.overall_risk_level == "critical" else "elevated" if risk.overall_risk_level in {"high", "elevated"} else "moderate" if risk.overall_risk_level == "moderate" else "healthy",
            value=risk.overall_risk_level,
            source_module="prompt_guard_risk_posture_summary",
            details={
                "critical_alerts": risk.critical_alerts,
                "open_alerts": risk.open_alerts,
                "recommendation_pressure": risk.recommendation_pressure,
            },
        ),
    ]

    coverage_status = _worst_status([area.status for area in coverage_areas])

    return PromptGuardCoverageSummary(
        generated_at=generated_at,
        coverage_status=coverage_status,
        incident_coverage_ratio=incident_coverage_ratio,
        linked_incidents=linked_incidents,
        unlinked_incidents=unlinked_incidents,
        coverage_areas=coverage_areas,
        metadata={
            "source_modules": [
                "prompt_guard_incident_summary",
                "prompt_guard_metrics",
                "prompt_guard_review_queue_summary",
                "prompt_guard_health_snapshot",
                "prompt_guard_risk_posture_summary",
                "prompt_guard_signals_summary",
            ],
            "coverage_area_count": len(coverage_areas),
        },
    )


@router.get(
    "/prompt-guard/coverage-summary",
    response_model=PromptGuardCoverageSummaryResponse,
)
def get_prompt_guard_coverage_summary() -> PromptGuardCoverageSummaryResponse:
    summary = build_prompt_guard_coverage_summary()
    data = summary.to_dict()

    return PromptGuardCoverageSummaryResponse(
        generated_at=data["generated_at"],
        coverage_status=data["coverage_status"],
        incident_coverage_ratio=data["incident_coverage_ratio"],
        linked_incidents=data["linked_incidents"],
        unlinked_incidents=data["unlinked_incidents"],
        coverage_areas=[PromptGuardCoverageAreaResponse(**area) for area in data["coverage_areas"]],
        metadata=data["metadata"],
    )
