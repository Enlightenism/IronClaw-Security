from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter
from pydantic import BaseModel, Field, ConfigDict

from app.api.actiondecision import decideaction


router = APIRouter(prefix="/review", tags=["review"])


ReviewStatus = Literal["pending", "approved", "rejected", "quarantined"]
ReviewResolution = Literal["allow", "deny", "quarantine", "needsreview"]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReviewReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int | None = None


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actiontype: str = Field(
        ...,
        min_length=1,
        description="Action type such as httpfetch or toolcall.",
    )
    target: str = Field(
        ...,
        min_length=1,
        description="Execution target such as URL, shell, or file path.",
    )
    content: str = Field(
        ...,
        description="Prompt or action content under review.",
    )
    riskscore: int = Field(
        ...,
        ge=0,
        le=100,
        description="Base risk score supplied to review.",
    )
    clientid: str | None = Field(None, description="Client or actor id.")
    sessionid: str | None = Field(None, description="Session or workflow id.")
    filepath: str | None = Field(None, description="Optional source filepath for attribution.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional external context, tool outputs, file text, or retrieved content.",
    )


class ReviewResponse(BaseModel):
    reviewitemid: str
    status: ReviewStatus
    resolution: ReviewResolution
    actiontype: str
    target: str
    filepath: str
    baseriskscore: int
    adjustedriskscore: int
    reason: str
    reasons: list[ReviewReasonView] = Field(default_factory=list)
    promptinjection: dict[str, Any] = Field(default_factory=dict)
    hostilecontext: dict[str, Any] = Field(default_factory=dict)
    createdat: str


def createreviewitem(
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
    decision = decideaction(
        actiontype=actiontype,
        target=target,
        content=content,
        riskscore=riskscore,
        clientid=clientid,
        sessionid=sessionid,
        filepath=filepath,
        metadata=metadata or {},
    )

    outcome = decision.get("outcome", "deny")
    if outcome == "allow":
        status: ReviewStatus = "approved"
        resolution: ReviewResolution = "allow"
        reason = "Review workflow approved the action because it remained within safe execution bounds."
    elif outcome == "review":
        status = "pending"
        resolution = "needsreview"
        reason = "Review workflow created a pending item because the action requires human review."
    elif outcome == "quarantine":
        status = "quarantined"
        resolution = "quarantine"
        reason = "Review workflow quarantined the action because the runtime detected containment-level risk."
    else:
        status = "rejected"
        resolution = "deny"
        reason = "Review workflow rejected the action because the runtime denied execution."

    return {
        "reviewitemid": f"review_{uuid4().hex}",
        "status": status,
        "resolution": resolution,
        "actiontype": actiontype,
        "target": target,
        "filepath": str(decision.get("filepath") or filepath or ""),
        "baseriskscore": int(decision.get("baseriskscore", riskscore)),
        "adjustedriskscore": int(decision.get("adjustedriskscore", riskscore)),
        "reason": reason,
        "reasons": decision.get("reasons", []),
        "promptinjection": decision.get("promptinjection") or {},
        "hostilecontext": decision.get("hostilecontext") or {},
        "createdat": _utcnow(),
    }


@router.post(
    "/item",
    response_model=ReviewResponse,
    summary="Create a review workflow item from an action decision.",
)
def createreview(payload: ReviewRequest) -> ReviewResponse:
    result = createreviewitem(
        actiontype=payload.actiontype,
        target=payload.target,
        content=payload.content,
        riskscore=payload.riskscore,
        clientid=payload.clientid,
        sessionid=payload.sessionid,
        filepath=payload.filepath,
        metadata=payload.metadata,
    )
    return ReviewResponse(**result)