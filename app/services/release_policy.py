from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.services.deployment_readiness import (
    DeploymentReadinessInput,
    DeploymentReadinessResult,
    evaluate_deployment_readiness,
)
from app.services.integration_rollout import (
    RolloutDecision,
    RolloutSignals,
    recommend_rollout,
)
from app.services.release_summary import (
    ReleaseSummary,
    build_release_summary_from_parts,
)


@dataclass(frozen=True)
class ReleasePolicyInput:
    integration_id: str
    compatibility_state: str
    telemetry_state: str
    lifecycle_state: str
    risk_score: float
    has_open_blockers: bool = False
    has_audit_gaps: bool = False
    has_rollback_plan: bool = True
    has_test_evidence: bool = True
    requires_manual_review: bool = False
    manual_review_completed: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReleasePolicyResult:
    integration_id: str
    rollout_decision: RolloutDecision
    readiness_result: DeploymentReadinessResult
    release_summary: ReleaseSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "rollout_decision": self.rollout_decision.to_dict(),
            "readiness_result": self.readiness_result.to_dict(),
            "release_summary": self.release_summary.to_dict(),
        }


def evaluate_release_policy(
    policy_input: ReleasePolicyInput,
) -> ReleasePolicyResult:
    rollout_decision = _evaluate_rollout(policy_input)
    readiness_result = _evaluate_readiness(policy_input, rollout_decision)
    release_summary = build_release_summary_from_parts(
        integration_id=policy_input.integration_id,
        rollout_decision=rollout_decision,
        readiness_result=readiness_result,
        compatibility_state=policy_input.compatibility_state,
        telemetry_state=policy_input.telemetry_state,
        lifecycle_state=policy_input.lifecycle_state,
        metadata=policy_input.metadata,
    )

    return ReleasePolicyResult(
        integration_id=policy_input.integration_id,
        rollout_decision=rollout_decision,
        readiness_result=readiness_result,
        release_summary=release_summary,
    )


def summarize_release_policy(
    result: ReleasePolicyResult,
) -> dict[str, Any]:
    return result.to_dict()


def _evaluate_rollout(policy_input: ReleasePolicyInput) -> RolloutDecision:
    rollout_signals = RolloutSignals(
        compatibility_state=policy_input.compatibility_state,
        telemetry_state=policy_input.telemetry_state,
        lifecycle_state=policy_input.lifecycle_state,
        risk_score=policy_input.risk_score,
        has_open_blockers=policy_input.has_open_blockers,
        has_audit_gaps=policy_input.has_audit_gaps,
        requires_manual_review=(policy_input.requires_manual_review and not policy_input.manual_review_completed),
    )
    return recommend_rollout(rollout_signals)


def _evaluate_readiness(
    policy_input: ReleasePolicyInput,
    rollout_decision: RolloutDecision,
) -> DeploymentReadinessResult:
    readiness_input = DeploymentReadinessInput(
        compatibility_state=policy_input.compatibility_state,
        telemetry_state=policy_input.telemetry_state,
        lifecycle_state=policy_input.lifecycle_state,
        rollout_recommendation=rollout_decision.recommendation.value,
        risk_score=rollout_decision.score,
        has_open_blockers=policy_input.has_open_blockers,
        has_audit_gaps=policy_input.has_audit_gaps,
        has_rollback_plan=policy_input.has_rollback_plan,
        has_test_evidence=policy_input.has_test_evidence,
        requires_manual_review=policy_input.requires_manual_review,
        manual_review_completed=policy_input.manual_review_completed,
    )
    return evaluate_deployment_readiness(readiness_input)
