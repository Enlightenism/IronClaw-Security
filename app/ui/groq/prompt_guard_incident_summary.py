from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.incidents import _INCIDENTS
from app.ui.groq.prompt_guard_incident_links import _INCIDENT_LINKS
from app.ui.groq.prompt_guard_metrics import build_prompt_guard_metrics_view

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-incident-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class PromptGuardIncidentSummary:
    generated_at: str
    total_incidents: int
    linked_incidents: int
    unlinked_incidents: int
    total_prompt_links: int
    high_risk_links: int
    incident_coverage_ratio: float
    by_severity: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "total_incidents": self.total_incidents,
            "linked_incidents": self.linked_incidents,
            "unlinked_incidents": self.unlinked_incidents,
            "total_prompt_links": self.total_prompt_links,
            "high_risk_links": self.high_risk_links,
            "incident_coverage_ratio": self.incident_coverage_ratio,
            "by_severity": dict(self.by_severity),
            "by_status": dict(self.by_status),
            "metadata": dict(self.metadata),
        }


class PromptGuardIncidentSummaryResponse(BaseModel):
    generated_at: str
    total_incidents: int
    linked_incidents: int
    unlinked_incidents: int
    total_prompt_links: int
    high_risk_links: int
    incident_coverage_ratio: float
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


def build_prompt_guard_incident_summary() -> PromptGuardIncidentSummary:
    incident_ids_with_links = {link.incident_id for link in _INCIDENT_LINKS}

    total_incidents = len(_INCIDENTS)
    linked_incidents = sum(1 for incident in _INCIDENTS if incident.id in incident_ids_with_links)
    unlinked_incidents = max(0, total_incidents - linked_incidents)

    total_prompt_links = len(_INCIDENT_LINKS)
    high_risk_links = sum(1 for link in _INCIDENT_LINKS if link.risk_score >= 70)

    coverage_ratio = 0.0
    if total_incidents > 0:
        coverage_ratio = round(linked_incidents / total_incidents, 3)

    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for incident in _INCIDENTS:
        by_severity[incident.severity] = by_severity.get(incident.severity, 0) + 1
        by_status[incident.status] = by_status.get(incident.status, 0) + 1

    metrics = build_prompt_guard_metrics_view()

    return PromptGuardIncidentSummary(
        generated_at=_utc_now(),
        total_incidents=total_incidents,
        linked_incidents=linked_incidents,
        unlinked_incidents=unlinked_incidents,
        total_prompt_links=total_prompt_links,
        high_risk_links=high_risk_links,
        incident_coverage_ratio=coverage_ratio,
        by_severity=by_severity,
        by_status=by_status,
        metadata={
            "source_modules": [
                "incidents",
                "prompt_guard_incident_links",
                "prompt_guard_metrics",
            ],
            "review_queue_total": next(
                (kpi.value for kpi in metrics.kpis if kpi.name == "total_reviews"),
                0,
            ),
        },
    )


@router.get("/prompt-guard/incident-summary", response_model=PromptGuardIncidentSummaryResponse)
def get_prompt_guard_incident_summary() -> PromptGuardIncidentSummaryResponse:
    summary = build_prompt_guard_incident_summary()
    data = summary.to_dict()

    return PromptGuardIncidentSummaryResponse(
        generated_at=data["generated_at"],
        total_incidents=data["total_incidents"],
        linked_incidents=data["linked_incidents"],
        unlinked_incidents=data["unlinked_incidents"],
        total_prompt_links=data["total_prompt_links"],
        high_risk_links=data["high_risk_links"],
        incident_coverage_ratio=data["incident_coverage_ratio"],
        by_severity=data["by_severity"],
        by_status=data["by_status"],
        metadata=data["metadata"],
    )
