from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.actionguard import guardaction

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

    verdict = guard["verdict"]
    if verdict == "allow":
        outcome: DecisionOutcome = "allow"
        state: DecisionState = "approved"
        shouldexecute = True
        haltedbyboundary = False
        requiresreview = False
        reason = "Decision engine approved execution."
    elif verdict == "review":
        outcome = "review"
        state = "queuedforreview"
        shouldexecute = True
        haltedbyboundary = False
        requiresreview = True
        reason = "Decision engine queued the action for review."
    elif verdict == "quarantine":
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
        "adjustedriskscore": guard["adjustedriskscore"],
        "reason": reason,
        "reasons": guard["reasons"],
        "promptinjection": guard["promptinjection"],
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