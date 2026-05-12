from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.actionpolicy import evaluateactionpolicy

router = APIRouter(prefix="/guard", tags=["action-guard"])


GuardVerdict = Literal["allow", "review", "quarantine", "deny"]


class ActionGuardRequest(BaseModel):
    actiontype: str = Field(..., description="Action type such as httpfetch or toolcall.")
    target: str = Field(..., description="Execution target such as URL, shell, file path, or tool id.")
    content: str = Field(..., description="Prompt or action content to guard.")
    riskscore: int = Field(..., ge=0, le=100, description="Base risk score for guard evaluation.")
    clientid: str | None = Field(None, description="Client or actor identifier.")
    sessionid: str | None = Field(None, description="Session or workflow identifier.")
    filepath: str | None = Field(None, description="Optional source filepath for audit attribution.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata from retrieved docs, tools, or external sources.",
    )


class GuardReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int


class ActionGuardResponse(BaseModel):
    actiontype: str
    target: str
    verdict: GuardVerdict
    allowed: bool
    haltedbyboundary: bool
    requiresreview: bool
    quarantined: bool
    baseriskscore: int
    adjustedriskscore: int
    filepath: str
    reason: str
    reasons: list[GuardReasonView] = Field(default_factory=list)
    promptinjection: dict[str, Any] = Field(default_factory=dict)


def guardaction(
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
    policy = evaluateactionpolicy(
        actiontype=actiontype,
        target=target,
        content=content,
        riskscore=riskscore,
        clientid=clientid,
        sessionid=sessionid,
        filepath=filepath,
        metadata=metadata,
    )

    policy_action = policy["action"]
    if policy_action == "allow":
        verdict: GuardVerdict = "allow"
        allowed = True
        haltedbyboundary = False
        requiresreview = False
        quarantined = False
        reason = "Guard allowed the action."
    elif policy_action == "review":
        verdict = "review"
        allowed = True
        haltedbyboundary = False
        requiresreview = True
        quarantined = False
        reason = "Guard routed the action for review."
    elif policy_action == "quarantine":
        verdict = "quarantine"
        allowed = False
        haltedbyboundary = True
        requiresreview = False
        quarantined = True
        reason = "Guard quarantined the action."
    else:
        verdict = "deny"
        allowed = False
        haltedbyboundary = True
        requiresreview = False
        quarantined = False
        reason = "Guard denied the action."

    return {
        "actiontype": actiontype,
        "target": target,
        "verdict": verdict,
        "allowed": allowed,
        "haltedbyboundary": haltedbyboundary,
        "requiresreview": requiresreview,
        "quarantined": quarantined,
        "baseriskscore": policy["baseriskscore"],
        "adjustedriskscore": policy["adjustedriskscore"],
        "filepath": policy["filepath"],
        "reason": reason,
        "reasons": policy["reasons"],
        "promptinjection": policy["promptinjection"],
    }


@router.post(
    "/action",
    response_model=ActionGuardResponse,
    summary="Guard a runtime action before execution with prompt injection awareness.",
)
def actionguard(payload: ActionGuardRequest) -> ActionGuardResponse:
    result = guardaction(
        actiontype=payload.actiontype,
        target=payload.target,
        content=payload.content,
        riskscore=payload.riskscore,
        clientid=payload.clientid,
        sessionid=payload.sessionid,
        filepath=payload.filepath,
        metadata=payload.metadata,
    )
    return ActionGuardResponse(**result)