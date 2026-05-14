from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.services.release_policy import (
    ReleasePolicyInput,
    ReleasePolicyResult,
    evaluate_release_policy,
)


@dataclass
class ReleasePolicyClient:
    """Thin, ergonomic client for evaluating release policy.

    This wraps the underlying service input model so call sites can pass
    simple primitives and get back a structured result or plain dict.
    """

    def evaluate(
        self,
        *,
        integration_id: str,
        compatibility_state: str,
        telemetry_state: str,
        lifecycle_state: str,
        risk_score: float,
        has_open_blockers: bool = False,
        has_audit_gaps: bool = False,
        has_rollback_plan: bool = True,
        has_test_evidence: bool = True,
        requires_manual_review: bool = False,
        manual_review_completed: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> ReleasePolicyResult:
        """Evaluate release policy and return the full typed result."""
        policy_input = ReleasePolicyInput(
            integration_id=integration_id,
            compatibility_state=compatibility_state,
            telemetry_state=telemetry_state,
            lifecycle_state=lifecycle_state,
            risk_score=float(risk_score),
            has_open_blockers=has_open_blockers,
            has_audit_gaps=has_audit_gaps,
            has_rollback_plan=has_rollback_plan,
            has_test_evidence=has_test_evidence,
            requires_manual_review=requires_manual_review,
            manual_review_completed=manual_review_completed,
            metadata=metadata or {},
        )
        return evaluate_release_policy(policy_input)

    def evaluate_as_dict(
        self,
        *,
        integration_id: str,
        compatibility_state: str,
        telemetry_state: str,
        lifecycle_state: str,
        risk_score: float,
        has_open_blockers: bool = False,
        has_audit_gaps: bool = False,
        has_rollback_plan: bool = True,
        has_test_evidence: bool = True,
        requires_manual_review: bool = False,
        manual_review_completed: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Evaluate release policy and return a JSON‑safe dict suitable
        for API responses or logging.
        """
        result = self.evaluate(
            integration_id=integration_id,
            compatibility_state=compatibility_state,
            telemetry_state=telemetry_state,
            lifecycle_state=lifecycle_state,
            risk_score=risk_score,
            has_open_blockers=has_open_blockers,
            has_audit_gaps=has_audit_gaps,
            has_rollback_plan=has_rollback_plan,
            has_test_evidence=has_test_evidence,
            requires_manual_review=requires_manual_review,
            manual_review_completed=manual_review_completed,
            metadata=metadata,
        )
        return result.to_dict()
