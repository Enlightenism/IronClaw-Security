from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.dependencies.action_execute import get_action_execute_pipeline
from app.dependencies.rate_limit import limit_guard_routes
from app.facade import guardandexecuteaction
from app.models.action_execute import ExecuteRequest, ExecuteResponse
from app.orchestrator.secure_runtime_pipeline import SecureRuntimePipeline
from app.runtime.install_gate import gate_shell_payload
from app.services.action_guard import (
    ActionGuardDecision,
    analyze_action,
    normalize_action_type,
)
from app.services.behavioral_baseline import get_behavioral_baseline_service
from app.services.telemetry import append_telemetry_event

router = APIRouter(dependencies=[Depends(limit_guard_routes)])

_INSTALL_CHECKED_ACTIONS = frozenset({"shell_command", "command", "tool_call", "toolcall"})

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


def _request_meta(request: Request) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", None),
        "trace_id": getattr(request.state, "trace_id", None),
        "path": request.url.path,
        "method": request.method,
    }


def _record_baseline_observation(
    payload: ExecuteRequest,
    risk_score: int,
    matched_patterns: list[str],
) -> None:
    agent_id = payload.agent_id or payload.client_id
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


def _run_detection(payload: ExecuteRequest) -> ActionGuardDecision | None:
    if not payload.action_type:
        return None
    try:
        result: ActionGuardDecision = analyze_action(
            action_type=normalize_action_type(payload.action_type),
            target=payload.target,
            content=payload.content or "",
            client_id=payload.client_id,
            session_id=payload.session_id,
            agent_id=payload.agent_id,
        )
        result["reasons"] = _normalize_reasons(result.get("reasons", []))
        return result
    except Exception:  # noqa: BLE001
        return None


@router.post("/execute", response_model=ExecuteResponse)
def guarded_execute(
    payload: ExecuteRequest,
    request: Request,
    pipeline: SecureRuntimePipeline = Depends(get_action_execute_pipeline),
) -> ExecuteResponse:
    meta = _request_meta(request)

    append_telemetry_event("execute_requested", {**meta, "action_type": payload.action_type})

    detection = _run_detection(payload)
    execution_risk_score = payload.risk_score
    if detection is not None:
        verdict = str(detection.get("verdict", "allow")).lower()
        raw_risk_score = detection.get("risk_score")
        if verdict not in {"allow", "block"} or isinstance(raw_risk_score, bool) or not isinstance(raw_risk_score, int) or not 0 <= raw_risk_score <= 100:
            execution_risk_score = max(execution_risk_score, RISK_THRESHOLD_BLOCK_MIN)
        else:
            execution_risk_score = max(execution_risk_score, raw_risk_score)
            if verdict == "block":
                execution_risk_score = max(execution_risk_score, RISK_THRESHOLD_BLOCK_MIN)

        risk_score = execution_risk_score
        matched_patterns = [str(r.get("label", "")) for r in detection.get("reasons", []) if isinstance(r, dict) and r.get("label")]

        _record_baseline_observation(payload, risk_score=risk_score, matched_patterns=matched_patterns)

        append_telemetry_event(
            "execute_detection_completed",
            {
                **meta,
                "action_type": payload.action_type,
                "verdict": verdict,
                "risk_score": risk_score,
                "reason_count": len(detection.get("reasons", [])),
            },
        )
    else:
        execution_risk_score = max(execution_risk_score, RISK_THRESHOLD_BLOCK_MIN)

    if normalize_action_type(payload.action_type) in _INSTALL_CHECKED_ACTIONS:
        install_decision = gate_shell_payload(
            payload.content,
            platform=payload.client_id,
            agent_id=payload.agent_id,
            client_id=payload.client_id,
        )
        if install_decision is not None and not install_decision.allowed:
            execution_risk_score = max(execution_risk_score, RISK_THRESHOLD_BLOCK_MIN)

    execution_payload = payload.model_copy(update={"risk_score": execution_risk_score})
    response: ExecuteResponse = guardandexecuteaction(execution_payload, pipeline)

    append_telemetry_event(
        "execute_completed",
        {
            **meta,
            "verdict": getattr(response, "verdict", None),
            "action_type": payload.action_type,
        },
    )

    return response
