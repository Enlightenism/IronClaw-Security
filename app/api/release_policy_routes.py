from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/release-policy",
    tags=["release-policy"],
)


# ---------------------------------------------------------------------------
# Lazy dependency — both the client class and the DI import are deferred so
# that a missing env var or Supabase config never crashes pytest collection.
# ---------------------------------------------------------------------------

def _get_release_policy_client():
    try:
        from app.dependencies import get_release_policy_client
        return get_release_policy_client()
    except Exception:
        from app.clients.release_policy_client import ReleasePolicyClient
        return ReleasePolicyClient()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ReleasePolicyRequest(BaseModel):
    integration_id: str = Field(..., description="Stable integration identifier.")
    compatibility_state: str = Field(
        ..., description="Compatibility state (supported, warning, unsupported)."
    )
    telemetry_state: str = Field(
        ..., description="Telemetry state (supported, warning, unsupported)."
    )
    lifecycle_state: str = Field(
        ..., description="Lifecycle state (draft, active, degraded, blocked, retired)."
    )
    risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Overall risk score, 0–100."
    )
    has_open_blockers: bool = Field(
        False, description="Whether any hard rollout blockers are open."
    )
    has_audit_gaps: bool = Field(
        False, description="Whether audit coverage has known gaps."
    )
    has_rollback_plan: bool = Field(
        True, description="Whether a rollback plan exists and is current."
    )
    has_test_evidence: bool = Field(
        True, description="Whether test evidence is available for this release."
    )
    requires_manual_review: bool = Field(
        False, description="Whether manual review is required before release."
    )
    manual_review_completed: bool = Field(
        False,
        description="Whether required manual review has been completed.",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional extra context to attach to the release summary.",
    )


class ReleasePolicyResponse(BaseModel):
    integration_id: str
    rollout_decision: Dict[str, Any]
    readiness_result: Dict[str, Any]
    release_summary: Dict[str, Any]


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post(
    "/evaluate",
    response_model=ReleasePolicyResponse,
    summary="Evaluate release policy for an integration",
    description=(
        "Evaluate rollout decision, readiness, and release summary "
        "for a given integration snapshot."
    ),
)
def evaluate_release_policy_route(
    payload: ReleasePolicyRequest,
    client=Depends(_get_release_policy_client),
) -> ReleasePolicyResponse:
    result = client.evaluate(
        integration_id=payload.integration_id,
        compatibility_state=payload.compatibility_state,
        telemetry_state=payload.telemetry_state,
        lifecycle_state=payload.lifecycle_state,
        risk_score=payload.risk_score,
        has_open_blockers=payload.has_open_blockers,
        has_audit_gaps=payload.has_audit_gaps,
        has_rollback_plan=payload.has_rollback_plan,
        has_test_evidence=payload.has_test_evidence,
        requires_manual_review=payload.requires_manual_review,
        manual_review_completed=payload.manual_review_completed,
        metadata=payload.metadata or {},
    )
    return ReleasePolicyResponse(
        integration_id=result.integration_id,
        rollout_decision=result.rollout_decision.to_dict(),
        readiness_result=result.readiness_result.to_dict(),
        release_summary=result.release_summary.to_dict(),
    )