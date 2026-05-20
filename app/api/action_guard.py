from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.dependencies.rate_limit import limit_guard_routes
from app.models.action_guard import (
    ActionDecisionResponse,
    ActionGuardRequest,
    ActionGuardResponse,
    ActionPolicyResponse,
)
from app.services.action_decision import (
    ActionExecutionDecision,
    evaluate_action_execution,
)
from app.services.action_guard import (
    ActionGuardDecision,
    analyze_action,
)
from app.services.action_policy import (
    ActionPolicyDecision,
    evaluate_action_policy,
)
from app.services.behavioral_baseline import get_behavioral_baseline_store
from app.services.telemetry import append_telemetry_event

router = APIRouter(dependencies=[Depends(limit_guard_routes)])


_ALLOWED_REASON_SOURCES = {"policy", "scan", "ai"}
_REASON_SOURCE_MAP = {
    "promptinjection": "scan",
    "prompt_injection": "scan",
}


def _normalize_reason_source(source: object) -> str:
    value = str(source or "scan").strip().lower()
    if value in _ALLOWED_REASON_SOURCES:
        return value
    return _REASON_SOURCE_MAP.get(value, "scan")


def _normalize_reasons(reasons: list[object]) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []

    for item in reasons:
        if isinstance(item, dict):
            normalized.append(
                {
                    "source": _normalize_reason_source(item.get("source")),
                    "label": str(item.get("label") or item.get("code") or "Explanation"),
                    "details": str(
                        item.get("details") or item.get("message") or item.get("summary") or "",
                    ),
                    "score": (float(item["score"]) if item.get("score") is not None else None),
                },
            )
        else:
            normalized.append(
                {
                    "source": "scan",
                    "label": "Explanation",
                    "details": str(item),
                    "score": None,
                },
            )

    return normalized


def _request_context(payload: ActionGuardRequest, request: Request) -> dict[str, object]:
    return {
        "action_type": payload.action_type,
        "target": payload.target,
        "client_id": payload.client_id,
        "session_id": payload.session_id,
        "request_id": getattr(request.state, "request_id", None),
        "trace_id": getattr(request.state, "trace_id", None),
        "path": request.url.path,
        "method": request.method,
    }


def _record_baseline_observation(
    payload: ActionGuardRequest,
    risk_score: int,
    matched_patterns: list[str],
) -> None:
    """Passively feed each analyzed action into the behavioral baseline store.

    Failures are intentionally swallowed so that baseline instrumentation
    never disrupts the guard response contract.
    """
    agent_id = getattr(payload, "agent_id", None) or payload.client_id
    if not agent_id:
        return
    try:
        get_behavioral_baseline_store().record_observation(
            agent_id=str(agent_id),
            action_type=payload.action_type,
            target=payload.target or "",
            risk_score=risk_score,
            session_id=payload.session_id,
            client_id=payload.client_id,
            matched_patterns=matched_patterns,
        )
    except Exception:  # noqa: BLE001
        pass


@router.post("/action", response_model=ActionGuardResponse)
def guard_action(payload: ActionGuardRequest, request: Request) -> ActionGuardResponse:
    append_telemetry_event(
        "guard_action_requested",
        _request_context(payload, request),
    )

    result: ActionGuardDecision = analyze_action(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        client_id=payload.client_id,
        session_id=payload.session_id,
    )
    result["reasons"] = _normalize_reasons(result.get("reasons", []))

    response = ActionGuardResponse(**result)

    _record_baseline_observation(
        payload,
        risk_score=int(getattr(response, "risk_score", 0) or 0),
        matched_patterns=[str(r.get("label", "")) for r in result.get("reasons", []) if isinstance(r, dict) and r.get("label")],
    )

    append_telemetry_event(
        "guard_action_completed",
        {
            **_request_context(payload, request),
            "risk_score": getattr(response, "risk_score", None),
            "verdict": getattr(response, "verdict", None),
            "reason_count": len(getattr(response, "reasons", [])),
        },
    )

    return response


@router.post("/action-policy", response_model=ActionPolicyResponse)
def guard_action_policy(payload: ActionGuardRequest, request: Request) -> ActionPolicyResponse:
    append_telemetry_event(
        "guard_action_policy_requested",
        _request_context(payload, request),
    )

    result: ActionPolicyDecision = evaluate_action_policy(
        action_type=payload.action_type,
        target=payload.target,
        client_id=payload.client_id,
        session_id=payload.session_id,
    )
    result["reasons"] = _normalize_reasons(result.get("reasons", []))

    response = ActionPolicyResponse(**result)

    _record_baseline_observation(
        payload,
        risk_score=int(getattr(response, "risk_score", 0) or 0),
        matched_patterns=[str(r.get("label", "")) for r in result.get("reasons", []) if isinstance(r, dict) and r.get("label")],
    )

    append_telemetry_event(
        "guard_action_policy_completed",
        {
            **_request_context(payload, request),
            "policy_verdict": getattr(response, "verdict", None),
            "reason_count": len(getattr(response, "reasons", [])),
        },
    )

    return response


@router.post("/action-decision", response_model=ActionDecisionResponse)
def guard_action_decision(payload: ActionGuardRequest, request: Request) -> ActionDecisionResponse:
    append_telemetry_event(
        "guard_action_decision_requested",
        _request_context(payload, request),
    )

    result: ActionExecutionDecision = evaluate_action_execution(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        client_id=payload.client_id,
        session_id=payload.session_id,
    )
    result["reasons"] = _normalize_reasons(result.get("reasons", []))

    response = ActionDecisionResponse(**result)

    _record_baseline_observation(
        payload,
        risk_score=int(getattr(response, "risk_score", 0) or 0),
        matched_patterns=[str(r.get("label", "")) for r in result.get("reasons", []) if isinstance(r, dict) and r.get("label")],
    )

    append_telemetry_event(
        "guard_action_decision_completed",
        {
            **_request_context(payload, request),
            "risk_score": getattr(response, "risk_score", None),
            "verdict": getattr(response, "verdict", None),
            "reason_count": len(getattr(response, "reasons", [])),
        },
    )

    return response
