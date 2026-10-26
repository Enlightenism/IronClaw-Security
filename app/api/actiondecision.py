from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.actionguard import guardaction
from app.services.verdict_enforcer import EnforcedVerdict, enforce_verdict

router = APIRouter(prefix="/decision", tags=["action-decision"])


DecisionOutcome = Literal["allow", "review", "quarantine", "deny"]
DecisionState = Literal["approved", "queuedforreview", "quarantined", "denied"]


class ActionDecisionRequest(BaseModel):
    actiontype: str = Field(..., description="Action type such as httpfetch or toolcall.")
    target: str = Field(..., description="Target such as URL, shell, file path, or tool id.")
    content: str = Field(..., description="Prompt or action content to evaluate.")
    riskscore: int = Field(..., ge=0, le=100, description="Base risk score before decision logic.")
    clientid: str | None = Field(None, description="Client or actor id.")
    sessionid: str | None = Field(None, description="Session or workflow id.")
    filepath: str | None = Field(None, description="Optional source filepath for attribution.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata from retrieved docs, tools, files, or model outputs.",
    )


class DecisionReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int


class ActionDecisionResponse(BaseModel):
    actiontype: str
    target: str
    outcome: DecisionOutcome
    state: DecisionState
    shouldexecute: bool
    haltedbyboundary: bool
    requiresreview: bool
    filepath: str
    baseriskscore: int
    adjustedriskscore: int
    reason: str
    reasons: list[DecisionReasonView] = Field(default_factory=list)
    promptinjection: dict[str, Any] = Field(default_factory=dict)
    # Guard telemetry — propagated from enforce_verdict to review records
    guard_verdict: str | None = None
    guard_risk_score: int | None = None
    guard_confidence: float | None = None
    guard_latency_ms: float | None = None
    guard_model_name: str | None = None
    guard_signals: list[str] = Field(default_factory=list)
    guard_summary: str | None = None
    guard_decided_at: str | None = None
    enforced_at: str | None = None


def _guard_verdict_to_enforcer_verdict(verdict: str) -> str:
    """Map actionguard verdicts to verdict_enforcer VerdictType."""
    return {
        "allow": "allow",
        "review": "warn",
        "quarantine": "quarantine",
        "deny": "block",
    }.get(verdict, "block")


def decideaction(
    *,
    actiontype: str,
    target: str,
    content: str,
    riskscore: int,
    clientid: str | None = None,
    sessionid: str | None = None,
    filepath: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    guard = guardaction(
        actiontype=actiontype,
        target=target,
        content=content,
        riskscore=riskscore,
        clientid=clientid,
        sessionid=sessionid,
        filepath=filepath,
        metadata=metadata,
    )

    raw_verdict = guard["verdict"]
    enforcer_verdict = _guard_verdict_to_enforcer_verdict(raw_verdict)

    # Build matched_patterns and categories from guard reasons for enforcer audit trail
    reasons_list: list[dict[str, Any]] = [dict(r) if hasattr(r, "__iter__") and not isinstance(r, str) else {"source": "scan", "label": str(r), "details": "", "score": 0} for r in guard.get("reasons", [])]
    matched_patterns: list[str] = [str(r.get("label", "")) for r in reasons_list if isinstance(r, dict) and r.get("label")]
    categories: list[str] = list({str(r.get("source", "")) for r in reasons_list if isinstance(r, dict) and r.get("source")})

    enforced: EnforcedVerdict = enforce_verdict(
        action_type=actiontype,
        target=target,
        content=content,
        verdict=enforcer_verdict,  # type: ignore[arg-type]
        summary=guard.get("reason", ""),
        risk_score=int(guard.get("adjustedriskscore", riskscore)),
        should_halt=not guard.get("allowed", True),
        should_warn=bool(guard.get("requiresreview")),
        matched_patterns=matched_patterns,
        categories=categories,
        decision_source="actiondecision",
        client_id=clientid,
        session_id=sessionid,
        reasons=[{str(k): v for k, v in r.items()} for r in reasons_list if isinstance(r, dict)],
    )

    # Map enforced verdict back to decision chain outcome/state
    final_verdict = enforced["verdict"]
    if final_verdict == "allow":
        outcome: DecisionOutcome = "allow"
        state: DecisionState = "approved"
        shouldexecute = True
        haltedbyboundary = False
        requiresreview = False
        reason = "Decision engine approved execution."
    elif final_verdict == "warn":
        outcome = "review"
        state = "queuedforreview"
        shouldexecute = True
        haltedbyboundary = False
        requiresreview = True
        reason = "Decision engine queued the action for review."
    elif final_verdict == "quarantine":
        outcome = "quarantine"
        state = "quarantined"
        shouldexecute = False
        haltedbyboundary = True
        requiresreview = False
        reason = "Decision engine quarantined execution."
    else:
        outcome = "deny"
        state = "denied"
        shouldexecute = False
        haltedbyboundary = True
        requiresreview = False
        reason = "Decision engine denied execution."

    return {
        "actiontype": actiontype,
        "target": target,
        "outcome": outcome,
        "state": state,
        "shouldexecute": shouldexecute,
        "haltedbyboundary": haltedbyboundary,
        "requiresreview": requiresreview,
        "filepath": guard["filepath"],
        "baseriskscore": guard["baseriskscore"],
        "adjustedriskscore": enforced["risk_score"],
        "reason": reason,
        "reasons": enforced["reasons"],
        "promptinjection": guard["promptinjection"],
        # Guard telemetry — now populated via enforce_verdict, flows to review.py
        "guard_verdict": enforced["guard_verdict"],
        "guard_risk_score": enforced["guard_risk_score"],
        "guard_confidence": enforced["guard_confidence"],
        "guard_latency_ms": enforced["guard_latency_ms"],
        "guard_model_name": enforced["guard_model_name"],
        "guard_signals": enforced["guard_signals"],
        "guard_summary": enforced["guard_summary"],
        "guard_decided_at": enforced["guard_decided_at"],
        "enforced_at": enforced["enforced_at"],
    }


@router.post(
    "/action",
    response_model=ActionDecisionResponse,
    summary="Produce the final runtime action decision with prompt injection awareness.",
)
def actiondecision(payload: ActionDecisionRequest) -> ActionDecisionResponse:
    result = decideaction(
        actiontype=payload.actiontype,
        target=payload.target,
        content=payload.content,
        riskscore=payload.riskscore,
        clientid=payload.clientid,
        sessionid=payload.sessionid,
        filepath=payload.filepath,
        metadata=payload.metadata,
    )
    return ActionDecisionResponse(**result)
