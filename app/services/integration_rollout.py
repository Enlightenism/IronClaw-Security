from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RolloutRecommendation(StrEnum):
    SHIP = "ship"
    LIMITED_ROLLOUT = "limited_rollout"
    HOLD = "hold"
    ROLLBACK_READY = "rollback_ready"


@dataclass(frozen=True)
class RolloutSignals:
    compatibility_state: str
    telemetry_state: str
    lifecycle_state: str
    risk_score: float
    has_open_blockers: bool = False
    has_audit_gaps: bool = False
    requires_manual_review: bool = False


@dataclass(frozen=True)
class RolloutDecision:
    recommendation: RolloutRecommendation
    score: float
    reasons: list[str] = field(default_factory=list)
    required_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "recommendation": self.recommendation.value,
            "score": self.score,
            "reasons": list(self.reasons),
            "required_actions": list(self.required_actions),
        }


def recommend_rollout(signals: RolloutSignals) -> RolloutDecision:
    reasons: list[str] = []
    required_actions: list[str] = []

    score = _calculate_rollout_score(signals)

    if signals.compatibility_state == "unsupported":
        reasons.append("Compatibility state is unsupported.")
        required_actions.append("Resolve compatibility failures before rollout.")
        return RolloutDecision(
            recommendation=RolloutRecommendation.HOLD,
            score=score,
            reasons=reasons,
            required_actions=required_actions,
        )

    if signals.lifecycle_state == "blocked":
        reasons.append("Lifecycle state is blocked.")
        required_actions.append("Clear blocking findings before rollout.")
        return RolloutDecision(
            recommendation=RolloutRecommendation.HOLD,
            score=score,
            reasons=reasons,
            required_actions=required_actions,
        )

    if signals.has_open_blockers:
        reasons.append("Open blockers are present.")
        required_actions.append("Close all rollout blockers.")
        return RolloutDecision(
            recommendation=RolloutRecommendation.HOLD,
            score=score,
            reasons=reasons,
            required_actions=required_actions,
        )

    if signals.telemetry_state == "unsupported":
        reasons.append("Telemetry indicates unsupported runtime health.")
        required_actions.append("Stabilize integration health before rollout.")
        return RolloutDecision(
            recommendation=RolloutRecommendation.ROLLBACK_READY,
            score=score,
            reasons=reasons,
            required_actions=required_actions,
        )

    if signals.requires_manual_review:
        reasons.append("Manual review is required.")
        required_actions.append("Complete reviewer sign-off before wider rollout.")

    if signals.has_audit_gaps:
        reasons.append("Audit trail coverage is incomplete.")
        required_actions.append("Backfill or validate audit events for the release window.")

    if signals.telemetry_state == "warning":
        reasons.append("Telemetry contains warnings.")
        required_actions.append("Limit exposure and monitor telemetry during rollout.")

    if signals.lifecycle_state == "degraded":
        reasons.append("Lifecycle state is degraded.")
        required_actions.append("Roll out only to a limited population until health improves.")

    recommendation = _recommendation_from_score(
        score=score,
        signals=signals,
    )

    if recommendation == RolloutRecommendation.SHIP and not reasons:
        reasons.append("All rollout gates passed with healthy support signals.")

    if recommendation == RolloutRecommendation.LIMITED_ROLLOUT and not required_actions:
        required_actions.append("Monitor health, audit, and compatibility signals during phased rollout.")

    if recommendation == RolloutRecommendation.ROLLBACK_READY and not required_actions:
        required_actions.append("Prepare rollback execution steps before proceeding.")

    return RolloutDecision(
        recommendation=recommendation,
        score=score,
        reasons=reasons,
        required_actions=required_actions,
    )


def summarize_rollout_decision(decision: RolloutDecision) -> dict[str, object]:
    return decision.to_dict()


def _calculate_rollout_score(signals: RolloutSignals) -> float:
    score = 100.0

    compatibility_penalties = {
        "supported": 0.0,
        "warning": 12.0,
        "unsupported": 60.0,
    }
    telemetry_penalties = {
        "supported": 0.0,
        "warning": 18.0,
        "unsupported": 55.0,
    }
    lifecycle_penalties = {
        "draft": 15.0,
        "active": 0.0,
        "degraded": 22.0,
        "blocked": 65.0,
        "retired": 100.0,
    }

    score -= compatibility_penalties.get(signals.compatibility_state, 25.0)
    score -= telemetry_penalties.get(signals.telemetry_state, 25.0)
    score -= lifecycle_penalties.get(signals.lifecycle_state, 30.0)

    if signals.has_open_blockers:
        score -= 25.0
    if signals.has_audit_gaps:
        score -= 10.0
    if signals.requires_manual_review:
        score -= 8.0

    score = min(score, float(signals.risk_score))
    return _clamp(score, 0.0, 100.0)


def _recommendation_from_score(
    *,
    score: float,
    signals: RolloutSignals,
) -> RolloutRecommendation:
    if signals.telemetry_state == "unsupported":
        return RolloutRecommendation.ROLLBACK_READY

    if score >= 85 and signals.telemetry_state == "supported" and signals.lifecycle_state == "active":
        return RolloutRecommendation.SHIP

    if score >= 60:
        return RolloutRecommendation.LIMITED_ROLLOUT

    if score >= 40:
        return RolloutRecommendation.ROLLBACK_READY

    return RolloutRecommendation.HOLD


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
