from __future__ import annotations

from fastapi import APIRouter

from app.models.guard import (
    ActionDecisionRequest,
    ActionDecisionResponse,
    ActionPolicyRequest,
    ActionPolicyResponse,
    GuardActionRequest,
    GuardActionResponse,
)
from app.services.action_decision import evaluate_action_execution
from app.services.action_guard import analyze_action
from app.services.action_policy import evaluate_action_policy

router = APIRouter(prefix="/guard", tags=["guard"])


@router.post("/action", response_model=GuardActionResponse)
def guard_action(payload: GuardActionRequest) -> GuardActionResponse:
    result = analyze_action(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        client_id=payload.client_id,
        session_id=payload.session_id,
    )
    return GuardActionResponse(**result)


@router.post("/action-policy", response_model=ActionPolicyResponse)
def action_policy(payload: ActionPolicyRequest) -> ActionPolicyResponse:
    result = evaluate_action_policy(
        action_type=payload.action_type,
        target=payload.target,
        client_id=payload.client_id,
        session_id=payload.session_id,
    )
    return ActionPolicyResponse(**result)


@router.post("/action-decision", response_model=ActionDecisionResponse)
def action_decision(payload: ActionDecisionRequest) -> ActionDecisionResponse:
    result = evaluate_action_execution(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        client_id=payload.client_id,
        session_id=payload.session_id,
    )
    return ActionDecisionResponse(**result)
