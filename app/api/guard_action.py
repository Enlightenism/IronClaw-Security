from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.auth import require_api_key
from app.facade import guardaction, guardactiondecision, guardactionpolicy
from app.models.guard_action import (
    ActionDecisionResponse,
    ActionGuardRequest,
    ActionGuardResponse,
    ActionPolicyResponse,
)
from app.services.telemetry import append_telemetry_event

router = APIRouter(
    prefix="/guard/action",
    tags=["guard-action"],
    dependencies=[Depends(require_api_key)],
)


def _request_meta(request: Request) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", None),
        "trace_id": getattr(request.state, "trace_id", None),
        "path": request.url.path,
        "method": request.method,
    }


@router.post("", response_model=ActionGuardResponse)
def guard_action(
    payload: ActionGuardRequest,
    request: Request,
) -> ActionGuardResponse:
    try:
        append_telemetry_event(
            "guard_action_requested",
            {
                **_request_meta(request),
                "action_type": payload.action_type,
                "target": payload.target,
                "client_id": payload.client_id,
                "session_id": payload.session_id,
            },
        )
    except Exception:
        pass

    response_payload = guardaction(payload)
    response = ActionGuardResponse(**response_payload)

    try:
        append_telemetry_event(
            "guard_action_completed",
            {
                **_request_meta(request),
                "action_type": payload.action_type,
                "target": payload.target,
                "client_id": payload.client_id,
                "session_id": payload.session_id,
                "policy_verdict": getattr(response, "policy_verdict", None),
                "risk_score": getattr(response, "risk_score", None),
                "should_halt": getattr(response, "should_halt", None),
                "should_warn": getattr(response, "should_warn", None),
            },
        )
    except Exception:
        pass

    return response


@router.post("/policy", response_model=ActionPolicyResponse)
def guard_action_policy(
    payload: ActionGuardRequest,
    request: Request,
) -> ActionPolicyResponse:
    try:
        append_telemetry_event(
            "guard_action_policy_requested",
            {
                **_request_meta(request),
                "action_type": payload.action_type,
                "target": payload.target,
                "client_id": payload.client_id,
                "session_id": payload.session_id,
            },
        )
    except Exception:
        pass

    response_payload = guardactionpolicy(payload)
    response = ActionPolicyResponse(**response_payload)

    try:
        append_telemetry_event(
            "guard_action_policy_completed",
            {
                **_request_meta(request),
                "action_type": payload.action_type,
                "target": payload.target,
                "client_id": payload.client_id,
                "session_id": payload.session_id,
                "policy_verdict": getattr(response, "policy_verdict", None),
                "risk_score": getattr(response, "risk_score", None),
                "should_execute": getattr(response, "should_execute", None),
                "halted_by_boundary": getattr(response, "halted_by_boundary", None),
            },
        )
    except Exception:
        pass

    return response


@router.post("/decision", response_model=ActionDecisionResponse)
def guard_action_decision(
    payload: ActionGuardRequest,
    request: Request,
) -> ActionDecisionResponse:
    try:
        append_telemetry_event(
            "guard_action_decision_requested",
            {
                **_request_meta(request),
                "action_type": payload.action_type,
                "target": payload.target,
                "client_id": payload.client_id,
                "session_id": payload.session_id,
            },
        )
    except Exception:
        pass

    response_payload = guardactiondecision(payload)
    response = ActionDecisionResponse(**response_payload)

    try:
        append_telemetry_event(
            "guard_action_decision_completed",
            {
                **_request_meta(request),
                "action_type": payload.action_type,
                "target": payload.target,
                "client_id": payload.client_id,
                "session_id": payload.session_id,
                "verdict": getattr(response, "verdict", None),
                "risk_score": getattr(response, "risk_score", None),
                "should_halt": getattr(response, "should_halt", None),
                "should_warn": getattr(response, "should_warn", None),
                "decision_source": getattr(response, "decision_source", None),
            },
        )
    except Exception:
        pass

    return response
