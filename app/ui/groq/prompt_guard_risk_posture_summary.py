from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.ui.groq.prompt_guard_alerts_overview import build_prompt_guard_alerts_overview
from app.ui.groq.prompt_guard_health_snapshot import build_prompt_guard_health_snapshot
from app.ui.groq.prompt_guard_incident_summary import build_prompt_guard_incident_summary
from app.ui.groq.prompt_guard_policy import build_prompt_guard_policy_view
from app.ui.groq.prompt_guard_recommendations import build_prompt_guard_recommendations_view

router = APIRouter(
    prefix="/ui/groq",
    tags=["groq-prompt-guard-risk-posture-summary"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


RiskLevel = Literal["low", "moderate", "elevated", "high", "critical"]


@dataclass(slots=True)
class PromptGuardRiskPostureSummary:
    generated_at: str
    overall_risk_level: RiskLevel
    policy_mode: str
    policy_health: str
    incident_coverage_ratio: float
    critical_alerts: int
    open_alerts: int
    recommendation_pressure: int
    risk_factors: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_risk_level": self.overall_risk_level,
            "policy_mode": self.policy_mode,
            "policy_health": self.policy_health,
            "incident_coverage_ratio": self.incident_coverage_ratio,
            "critical_alerts": self.critical_alerts,
            "open_alerts": self.open_alerts,
            "recommendation_pressure": self.recommendation_pressure,
            "risk_factors": list(self.risk_factors),
            "metadata": dict(self.metadata),
        }


class PromptGuardRiskFactorResponse(BaseModel):
    id: str
    title: str
    level: RiskLevel
    source_module: str
    details: dict[str, Any] = Field(default_factory=dict)


class PromptGuardRiskPostureSummaryResponse(BaseModel):
    generated_at: str
    overall_risk_level: RiskLevel
    policy_mode: str
    policy_health: str
    incident_coverage_ratio: float
    critical_alerts: int
    open_alerts: int
    recommendation_pressure: int
    risk_factors: list[PromptGuardRiskFactorResponse] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _normalize_policy_risk(policy_health: str) -> RiskLevel:
    value = (policy_health or "").strip().lower()
    if value in {"critical", "failed"}:
        return "critical"
    if value in {"degraded"}:
        return "high"
    if value in {"warning"}:
        return "elevated"
    return "low"


def _derive_coverage_risk(coverage_ratio: float) -> RiskLevel:
    if coverage_ratio < 0.35:
        return "critical"
    if coverage_ratio < 0.55:
        return "high"
    if coverage_ratio < 0.75:
        return "elevated"
    if coverage_ratio < 0.9:
        return "moderate"
    return "low"


def _derive_alert_risk(critical_alerts: int, open_alerts: int) -> RiskLevel:
    if critical_alerts > 0:
        return "critical"
    if open_alerts >= 10:
        return "high"
    if open_alerts >= 5:
        return "elevated"
    if open_alerts > 0:
        return "moderate"
    return "low"


def _derive_recommendation_risk(recommendation_pressure: int) -> RiskLevel:
    if recommendation_pressure >= 8:
        return "high"
    if recommendation_pressure >= 4:
        return "elevated"
    if recommendation_pressure > 0:
        return "moderate"
    return "low"


def _max_risk(levels: list[RiskLevel]) -> RiskLevel:
    rank: dict[RiskLevel, int] = {
        "low": 0,
        "moderate": 1,
        "elevated": 2,
        "high": 3,
        "critical": 4,
    }
    return max(levels, key=lambda level: rank[level])


def build_prompt_guard_risk_posture_summary() -> PromptGuardRiskPostureSummary:
    policy = build_prompt_guard_policy_view()
    incident_summary = build_prompt_guard_incident_summary()
    alerts = build_prompt_guard_alerts_overview()
    health = build_prompt_guard_health_snapshot()
    recommendations = build_prompt_guard_recommendations_view()

    summary = incident_summary.to_dict()
    incident_coverage_ratio = float(summary.get("incident_coverage_ratio", 0.0))
    critical_alerts = int(alerts.critical_alerts)
    open_alerts = int(alerts.open_alerts)
    recommendation_pressure = len(recommendations.items)

    policy_risk = _normalize_policy_risk(policy.health)
    coverage_risk = _derive_coverage_risk(incident_coverage_ratio)
    alert_risk = _derive_alert_risk(critical_alerts, open_alerts)
    recommendation_risk = _derive_recommendation_risk(recommendation_pressure)

    overall_risk_level = _max_risk(
        [
            policy_risk,
            coverage_risk,
            alert_risk,
            recommendation_risk,
        ],
    )

    risk_factors: list[dict[str, Any]] = [
        {
            "id": "risk:policy-health",
            "title": "Policy health posture",
            "level": policy_risk,
            "source_module": "prompt_guard_policy",
            "details": {
                "policy_health": policy.health,
                "policy_mode": policy.mode,
            },
        },
        {
            "id": "risk:incident-coverage",
            "title": "Incident linkage coverage",
            "level": coverage_risk,
            "source_module": "prompt_guard_incident_summary",
            "details": {
                "incident_coverage_ratio": incident_coverage_ratio,
                "linked_incidents": summary.get("linked_incidents", 0),
                "unlinked_incidents": summary.get("unlinked_incidents", 0),
            },
        },
        {
            "id": "risk:alerts",
            "title": "Active alert pressure",
            "level": alert_risk,
            "source_module": "prompt_guard_alerts_overview",
            "details": {
                "critical_alerts": critical_alerts,
                "open_alerts": open_alerts,
                "warning_alerts": alerts.warning_alerts,
            },
        },
        {
            "id": "risk:recommendations",
            "title": "Recommendation backlog pressure",
            "level": recommendation_risk,
            "source_module": "prompt_guard_recommendations",
            "details": {
                "recommendation_pressure": recommendation_pressure,
            },
        },
    ]

    return PromptGuardRiskPostureSummary(
        generated_at=_utc_now(),
        overall_risk_level=overall_risk_level,
        policy_mode=policy.mode,
        policy_health=policy.health,
        incident_coverage_ratio=incident_coverage_ratio,
        critical_alerts=critical_alerts,
        open_alerts=open_alerts,
        recommendation_pressure=recommendation_pressure,
        risk_factors=risk_factors,
        metadata={
            "source_modules": [
                "prompt_guard_policy",
                "prompt_guard_incident_summary",
                "prompt_guard_alerts_overview",
                "prompt_guard_health_snapshot",
                "prompt_guard_recommendations",
            ],
            "health_snapshot_status": health.overall_status,
            "risk_inputs": {
                "policy_risk": policy_risk,
                "coverage_risk": coverage_risk,
                "alert_risk": alert_risk,
                "recommendation_risk": recommendation_risk,
            },
        },
    )


@router.get(
    "/prompt-guard/risk-posture-summary",
    response_model=PromptGuardRiskPostureSummaryResponse,
)
def get_prompt_guard_risk_posture_summary() -> PromptGuardRiskPostureSummaryResponse:
    summary = build_prompt_guard_risk_posture_summary()
    data = summary.to_dict()

    return PromptGuardRiskPostureSummaryResponse(
        generated_at=data["generated_at"],
        overall_risk_level=data["overall_risk_level"],
        policy_mode=data["policy_mode"],
        policy_health=data["policy_health"],
        incident_coverage_ratio=data["incident_coverage_ratio"],
        critical_alerts=data["critical_alerts"],
        open_alerts=data["open_alerts"],
        recommendation_pressure=data["recommendation_pressure"],
        risk_factors=[PromptGuardRiskFactorResponse(**factor) for factor in data["risk_factors"]],
        metadata=data["metadata"],
    )
