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

# Verdict severity order — maps action_guard/action_policy verdicts to a
# comparable rank so we can escalate based on threat detection results.
_VERDICT_RANK: dict[str, int] = {
    "allow": 1,
    "warn": 2,
    "quarantine": 3,
    "block": 4,
}

# Map DetectionVerdict values → action_guard VerdictType equivalents
_DETECTION_VERDICT_MAP: dict[str, str] = {
    "allow": "allow",
    "monitor": "warn",
    "review": "quarantine",
    "block": "block",
}


def _max_verdict(a: str, b: str) -> str:
    return a if _VERDICT_RANK.get(a, 0) >= _VERDICT_RANK.get(b, 0) else b


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


def _run_threat_screen(
    payload: ActionGuardRequest,
    current_verdict: str,
    caller_context: str,
) -> tuple[str, list[dict[str, object]]]:
    """
    Call run_detection() from app.api.threat_detection as the single threat
    detection entry point. Returns an (escalated_verdict, extra_reasons) tuple.

    Failures are fail-open: if run_detection is unavailable or raises,
    the original verdict is returned unchanged and no reasons are added.
    """
    try:
        from app.api.threat_detection import run_detection  # noqa: PLC0415
        from app.schemas.threat_detection import DetectionRequest  # noqa: PLC0415

        text_parts = [payload.action_type]
        if payload.target:
            text_parts.append(f"TARGET: {payload.target}")
        if getattr(payload, "content", None):
            text_parts.append(f"CONTENT: {payload.content}")

        detection_payload = DetectionRequest(
            text="\n".join(text_parts),
            agent_id=getattr(payload, "agent_id", None) or payload.client_id,
            session_id=payload.session_id,
            org_id=None,
            metadata={
                "caller": caller_context,
                "action_type": payload.action_type,
                "client_id": payload.client_id,
            },
        )

        result = run_detection(
            detection_payload,
            caller_context=caller_context,
        )

        mapped = _DETECTION_VERDICT_MAP.get(result.verdict.value, "allow")
        escalated = _max_verdict(current_verdict, mapped)

        extra_reasons: list[dict[str, object]] = []
        if mapped != "allow":
            extra_reasons.append(
                {
                    "source": "scan",
                    "label": "Threat detection signal",
                    "details": (f"ThreatDetectionEngine verdict={result.verdict.value} " f"score={result.score:.3f} severity={result.severity.value} " f"ioc_matches={result.ioc_match_count} " f"correlation_signals={result.correlation_signal_count}"),
                    "score": result.score,
                },
            )

        return escalated, extra_reasons

    except Exception:  # noqa: BLE001
        return current_verdict, []


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

    # Threat detection screen — escalate verdict via single entry point
    escalated_verdict, threat_reasons = _run_threat_screen(
        payload,
        current_verdict=result.get("verdict", "allow"),
        caller_context="action_guard",
    )
    if threat_reasons:
        result["reasons"] = list(result["reasons"]) + threat_reasons
    result["verdict"] = escalated_verdict
    result["should_halt"] = escalated_verdict in ("block", "quarantine")
    result["should_warn"] = escalated_verdict in ("warn", "quarantine")

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

    # Threat detection screen — escalate verdict via single entry point
    escalated_verdict, threat_reasons = _run_threat_screen(
        payload,
        current_verdict=result.get("verdict", "allow"),
        caller_context="action_guard_policy",
    )
    if threat_reasons:
        result["reasons"] = list(result["reasons"]) + threat_reasons
    result["verdict"] = escalated_verdict
    result["should_halt"] = escalated_verdict in ("block", "quarantine")
    result["should_warn"] = escalated_verdict in ("warn", "quarantine")

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

    # Threat detection screen — escalate verdict via single entry point
    escalated_verdict, threat_reasons = _run_threat_screen(
        payload,
        current_verdict=result.get("verdict", "allow"),
        caller_context="action_guard_decision",
    )
    if threat_reasons:
        result["reasons"] = list(result["reasons"]) + threat_reasons
    result["verdict"] = escalated_verdict
    result["should_halt"] = escalated_verdict in ("block", "quarantine")
    result["should_warn"] = escalated_verdict in ("warn", "quarantine")

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
