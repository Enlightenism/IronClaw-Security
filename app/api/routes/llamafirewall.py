from __future__ import annotations

from typing import Any
import uuid

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from app.adapters.llamafirewall_adapter import (
    adapt_policy_decision_to_llamafirewall,
    build_llamafirewall_adapter_request,
    summarize_llamafirewall_adapter_response,
)
from app.core.auth import require_api_key
from app.orchestrator.policy_enforcer import evaluate_policy, initialize_policy_engine

router = APIRouter(prefix="/integrations/llamafirewall", tags=["llamafirewall"])

_ENGINE = initialize_policy_engine(mode="enforce")
_AUDIT_EVENTS: list[dict[str, Any]] = []


def _build_trace_id() -> str:
    return str(uuid.uuid4())


def _append_audit_event(event: dict[str, Any]) -> None:
    _AUDIT_EVENTS.append(event)
    if len(_AUDIT_EVENTS) > 500:
        del _AUDIT_EVENTS[:-500]


class LlamaFirewallScanRequest(BaseModel):
    action_type: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    content: str = ""
    prompt: str | None = None
    scanner_id: str | None = None
    policy_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    risk_score: int = Field(default=0, ge=0, le=100)
    mode: str = Field(default="enforce", pattern="^(enforce|monitor)$")
    scan_result: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.post("/scan", dependencies=[Depends(require_api_key)])
def llamafirewall_scan(payload: LlamaFirewallScanRequest, request: Request) -> dict[str, Any]:
    trace_id = _build_trace_id()

    adapter_request = build_llamafirewall_adapter_request(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        prompt=payload.prompt,
        scanner_id=payload.scanner_id,
        policy_id=payload.policy_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        metadata=dict(payload.metadata),
    )

    decision = evaluate_policy(
        _ENGINE,
        adapter_request.to_policy_input(),
        risk_score=payload.risk_score,
    )

    scan_result = dict(payload.scan_result) if payload.scan_result else None

    adapter_response = adapt_policy_decision_to_llamafirewall(
        decision,
        mode=payload.mode,  # type: ignore[arg-type]
        trace_id=trace_id,
        request=adapter_request,
        scan_result=scan_result,
        metadata=dict(payload.metadata),
    )

    response = adapter_response.to_dict()
    response["trace_id"] = trace_id

    _append_audit_event(
        {
            "event_type": "llamafirewall_scan",
            "trace_id": trace_id,
            "path": str(request.url.path),
            "action_type": payload.action_type,
            "target": payload.target,
            "agent_id": payload.agent_id,
            "session_id": payload.session_id,
            "verdict": adapter_response.verdict,
            "risk_score": adapter_response.risk_score,
            "risk_level": adapter_response.risk_level,
            "lf_verdict": adapter_response.lf_verdict,
            "lf_categories": list(adapter_response.lf_categories),
            "should_hold": adapter_response.should_hold,
            "decision_id": adapter_response.decision_id,
        }
    )

    return response


@router.post("/scan/summarize", dependencies=[Depends(require_api_key)])
def llamafirewall_scan_summarize(payload: LlamaFirewallScanRequest, request: Request) -> dict[str, Any]:
    trace_id = _build_trace_id()

    adapter_request = build_llamafirewall_adapter_request(
        action_type=payload.action_type,
        target=payload.target,
        content=payload.content,
        prompt=payload.prompt,
        scanner_id=payload.scanner_id,
        policy_id=payload.policy_id,
        agent_id=payload.agent_id,
        session_id=payload.session_id,
        metadata=dict(payload.metadata),
    )

    decision = evaluate_policy(
        _ENGINE,
        adapter_request.to_policy_input(),
        risk_score=payload.risk_score,
    )

    scan_result = dict(payload.scan_result) if payload.scan_result else None

    adapter_response = adapt_policy_decision_to_llamafirewall(
        decision,
        mode=payload.mode,  # type: ignore[arg-type]
        trace_id=trace_id,
        request=adapter_request,
        scan_result=scan_result,
        metadata=dict(payload.metadata),
    )

    summary = summarize_llamafirewall_adapter_response(adapter_response)
    summary["trace_id"] = trace_id

    _append_audit_event(
        {
            "event_type": "llamafirewall_scan_summarize",
            "trace_id": trace_id,
            "path": str(request.url.path),
            "action_type": payload.action_type,
            "target": payload.target,
            "agent_id": payload.agent_id,
            "session_id": payload.session_id,
            "verdict": adapter_response.verdict,
            "risk_score": adapter_response.risk_score,
            "lf_verdict": adapter_response.lf_verdict,
            "lf_categories": list(adapter_response.lf_categories),
            "should_hold": adapter_response.should_hold,
            "decision_id": adapter_response.decision_id,
        }
    )

    return summary


@router.get("/audit/events", dependencies=[Depends(require_api_key)])
def get_llamafirewall_audit_events(
    limit: int = Query(default=20, ge=1, le=200),
) -> dict[str, Any]:
    events = list(reversed(_AUDIT_EVENTS[-limit:]))
    return {
        "events": events,
        "count": len(events),
        "limit": limit,
    }


@router.get("/health")
def llamafirewall_integration_health() -> dict[str, Any]:
    return {
        "integration": "llamafirewall",
        "status": "healthy",
        "routes": [
            "POST /integrations/llamafirewall/scan",
            "POST /integrations/llamafirewall/scan/summarize",
            "GET  /integrations/llamafirewall/audit/events",
            "GET  /integrations/llamafirewall/health",
        ],
    }
