from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Request

from app.dependencies.rate_limit import limit_guard_routes
from app.models.action_guard import (
    ActionDecisionResponse,
    ActionGuardRequest,
    ActionGuardResponse,
    ActionPolicyResponse,
)
from app.services.action_decision import evaluate_action_execution
from app.services.action_guard import (
    ActionGuardDecision,
    analyze_action,
)
from app.services.action_policy import (
    ActionPolicyDecision,
    evaluate_action_policy,
)
from app.services.behavioral_baseline import get_behavioral_baseline_service
from app.services.telemetry import append_telemetry_event
from app.services.telemetry_service import (
    TelemetryEventInput,
    build_agent_event,
    post_telemetry_batch_async,
)
from app.services.verdict_enforcer import EnforcedVerdict

router = APIRouter(dependencies=[Depends(limit_guard_routes)])


_ALLOWED_REASON_SOURCES = {"policy", "scan", "ai"}
_REASON_SOURCE_MAP = {
    "promptinjection": "scan",
    "prompt_injection": "scan",
}


_VERDICT_RANK: dict[str, int] = {
    "allow": 1,
    "warn": 2,
    "quarantine": 3,
    "block": 4,
}


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
        "agent_id": getattr(payload, "agent_id", None),
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
    agent_id = getattr(payload, "agent_id", None) or payload.client_id
    if not agent_id:
        return
    try:
        get_behavioral_baseline_service().record_observation(
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
                    "details": (f"ThreatDetectionEngine verdict={result.verdict.value} score={result.score:.3f} severity={result.severity.value} ioc_matches={result.ioc_match_count} correlation_signals={result.correlation_signal_count}"),
                    "score": result.score,
                },
            )

        return escalated, extra_reasons

    except Exception:  # noqa: BLE001
        return current_verdict, []


async def _flush_guard_events_async(events: list[TelemetryEventInput]) -> None:
    try:
        await post_telemetry_batch_async(events)
    except Exception:  # noqa: BLE001
        pass


def _build_guard_decision_event(
    payload: ActionGuardRequest,
    verdict: str,
    risk_score: int | float | None,
    reason_count: int,
    agent_id: str | None,
    extra_key_seed: str,
) -> TelemetryEventInput:
    return build_agent_event(
        source="ironclaw.action_guard",
        metric_name="action_guard_decision",
        metric_type="event",
        org_id=str(payload.client_id) if payload.client_id else None,
        value_text=verdict,
        value_numeric=float(risk_score) if risk_score is not None else None,
        dimensions={
            "action_type": payload.action_type,
            "target": payload.target,
            "client_id": payload.client_id,
            "session_id": payload.session_id,
            "agent_id": agent_id,
            "verdict": verdict,
            "reason_count": reason_count,
        },
        extra_key_seed=extra_key_seed,
    )


def _build_prompt_injection_event(
    payload: ActionGuardRequest,
    verdict: str,
    risk_score: int | float | None,
    caller_context: str,
    extra_key_seed: str,
) -> TelemetryEventInput:
    return build_agent_event(
        source="ironclaw.action_guard",
        metric_name="prompt_injection_detected",
        metric_type="event",
        org_id=str(payload.client_id) if payload.client_id else None,
        value_text=verdict,
        value_numeric=float(risk_score) if risk_score is not None else None,
        dimensions={
            "action_type": payload.action_type,
            "target": payload.target,
            "client_id": payload.client_id,
            "session_id": payload.session_id,
            "agent_id": getattr(payload, "agent_id", None),
            "verdict": verdict,
            "caller_context": caller_context,
        },
        extra_key_seed=extra_key_seed,
    )


@router.post("/action", response_model=ActionGuardResponse)
def guard_action(
    payload: ActionGuardRequest,
    request: Request,
    background_tasks: BackgroundTasks,
) -> ActionGuardResponse:
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

    risk_score = int(getattr(response, "risk_score", 0) or 0)
    matched_patterns = [str(r.get("label", "")) for r in result.get("reasons", []) if isinstance(r, dict) and r.get("label")]

    _record_baseline_observation(payload, risk_score=risk_score, matched_patterns=matched_patterns)

    append_telemetry_event(
        "guard_action_completed",
        {
            **_request_context(payload, request),
            "risk_score": getattr(response, "risk_score", None),
            "verdict": getattr(response, "verdict", None),
            "reason_count": len(getattr(response, "reasons", [])),
        },
    )

    events: list[TelemetryEventInput] = [
        _build_guard_decision_event(
            payload,
            verdict=escalated_verdict,
            risk_score=risk_score,
            reason_count=len(result.get("reasons", [])),
            agent_id=getattr(payload, "agent_id", None),
            extra_key_seed=f"action:{payload.action_type}:{payload.client_id}:{escalated_verdict}",
        )
    ]
    if escalated_verdict in ("block", "quarantine") and any("injection" in str(r.get("label", "")).lower() for r in result.get("reasons", []) if isinstance(r, dict)):
        events.append(
            _build_prompt_injection_event(
                payload,
                verdict=escalated_verdict,
                risk_score=risk_score,
                caller_context="action_guard",
                extra_key_seed=f"injection:action:{payload.action_type}:{payload.client_id}:{escalated_verdict}",
            )
        )
    background_tasks.add_task(_flush_guard_events_async, events)

    return response


@router.post("/action-policy", response_model=ActionPolicyResponse)
def guard_action_policy(
    payload: ActionGuardRequest,
    request: Request,
    background_tasks: BackgroundTasks,
) -> ActionPolicyResponse:
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

    risk_score = int(getattr(response, "risk_score", 0) or 0)
    matched_patterns = [str(r.get("label", "")) for r in result.get("reasons", []) if isinstance(r, dict) and r.get("label")]

    _record_baseline_observation(payload, risk_score=risk_score, matched_patterns=matched_patterns)

    append_telemetry_event(
        "guard_action_policy_completed",
        {
            **_request_context(payload, request),
            "policy_verdict": getattr(response, "verdict", None),
            "reason_count": len(getattr(response, "reasons", [])),
        },
    )

    events: list[TelemetryEventInput] = [
        _build_guard_decision_event(
            payload,
            verdict=escalated_verdict,
            risk_score=risk_score,
            reason_count=len(result.get("reasons", [])),
            agent_id=getattr(payload, "agent_id", None),
            extra_key_seed=f"policy:{payload.action_type}:{payload.client_id}:{escalated_verdict}",
        )
    ]
    if escalated_verdict in ("block", "quarantine") and any("injection" in str(r.get("label", "")).lower() for r in result.get("reasons", []) if isinstance(r, dict)):
        events.append(
            _build_prompt_injection_event(
                payload,
                verdict=escalated_verdict,
                risk_score=risk_score,
                caller_context="action_guard_policy",
                extra_key_seed=f"injection:policy:{payload.action_type}:{payload.client_id}:{escalated_verdict}",
            )
        )
    background_tasks.add_task(_flush_guard_events_async, events)

    return response


@router.post("/action-decision", response_model=ActionDecisionResponse)
def guard_action_decision(
    payload: ActionGuardRequest,
    request: Request,
    background_tasks: BackgroundTasks,
) -> ActionDecisionResponse:
    append_telemetry_event(
        "guard_action_decision_requested",
        _request_context(payload, request),
    )

    result: EnforcedVerdict = evaluate_action_execution(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        client_id=payload.client_id,
        session_id=payload.session_id,
        agent_id=getattr(payload, "agent_id", None),
    )
    result["reasons"] = _normalize_reasons(result.get("reasons", []))

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

    risk_score = int(getattr(response, "risk_score", 0) or 0)
    agent_id = getattr(response, "agent_id", None) or getattr(payload, "agent_id", None)
    matched_patterns = [str(r.get("label", "")) for r in result.get("reasons", []) if isinstance(r, dict) and r.get("label")]

    _record_baseline_observation(payload, risk_score=risk_score, matched_patterns=matched_patterns)

    append_telemetry_event(
        "guard_action_decision_completed",
        {
            **_request_context(payload, request),
            "risk_score": getattr(response, "risk_score", None),
            "verdict": getattr(response, "verdict", None),
            "reason_count": len(getattr(response, "reasons", [])),
            "categories": getattr(response, "categories", []),
            "agent_id": agent_id,
            "guard_verdict": getattr(response, "guard_verdict", None),
            "guard_risk_score": getattr(response, "guard_risk_score", None),
            "guard_confidence": getattr(response, "guard_confidence", None),
            "guard_latency_ms": getattr(response, "guard_latency_ms", None),
            "guard_model_name": getattr(response, "guard_model_name", None),
            "enforced_at": getattr(response, "enforced_at", None),
            "drift_detected": getattr(response, "drift_report", None) is not None,
        },
    )

    events: list[TelemetryEventInput] = [
        _build_guard_decision_event(
            payload,
            verdict=escalated_verdict,
            risk_score=risk_score,
            reason_count=len(result.get("reasons", [])),
            agent_id=agent_id,
            extra_key_seed=f"decision:{payload.action_type}:{payload.client_id}:{escalated_verdict}",
        )
    ]
    if escalated_verdict in ("block", "quarantine") and any("injection" in str(r.get("label", "")).lower() for r in result.get("reasons", []) if isinstance(r, dict)):
        events.append(
            _build_prompt_injection_event(
                payload,
                verdict=escalated_verdict,
                risk_score=risk_score,
                caller_context="action_guard_decision",
                extra_key_seed=f"injection:decision:{payload.action_type}:{payload.client_id}:{escalated_verdict}",
            )
        )
    background_tasks.add_task(_flush_guard_events_async, events)

    return response
