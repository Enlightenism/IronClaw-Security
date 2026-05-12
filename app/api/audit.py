from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.api.actiondecision import decideaction

router = APIRouter(prefix="/audit", tags=["audit"])


AuditEventType = Literal[
    "execution_allowed",
    "execution_review",
    "execution_quarantined",
    "execution_denied",
]
AuditSeverity = Literal["info", "warning", "high", "critical"]


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _newid(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _coerceoutcome(value: Any) -> str:
    outcome = str(value or "").strip().lower()
    if outcome in {"allow", "review", "quarantine", "deny", "denied", "block", "blocked"}:
        return outcome
    return "deny"


def _eventshape(outcome: str) -> tuple[AuditEventType, AuditSeverity, str]:
    if outcome == "allow":
        return (
            "execution_allowed",
            "info",
            "Audit recorded an allowed execution path.",
        )
    if outcome == "review":
        return (
            "execution_review",
            "warning",
            "Audit recorded a review-required execution path.",
        )
    if outcome == "quarantine":
        return (
            "execution_quarantined",
            "critical",
            "Audit recorded a quarantined execution path.",
        )
    return (
        "execution_denied",
        "high",
        "Audit recorded a denied execution path.",
    )


class AuditReasonView(BaseModel):
    source: str
    label: str
    details: str
    score: int


class AuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actiontype: str = Field(..., min_length=1, description="Action type such as httpfetch or toolcall.")
    target: str = Field(..., min_length=1, description="Execution target such as URL, shell, or file path.")
    content: str = Field(..., description="Prompt or action content that produced the audit event.")
    riskscore: int = Field(..., ge=0, le=100, description="Base risk score supplied to the audit pipeline.")
    clientid: str | None = Field(None, description="Client or actor id.")
    sessionid: str | None = Field(None, description="Session or workflow id.")
    filepath: str | None = Field(None, description="Optional source filepath for attribution.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional external context, tool outputs, retrieved content, or file text.",
    )

    @field_validator("actiontype", "target", "content", "clientid", "sessionid", "filepath", mode="before")
    @classmethod
    def _stripstrings(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()
        return value

    @field_validator("actiontype", "target")
    @classmethod
    def _requirenonempty(cls, value: str) -> str:
        if not value:
            raise ValueError("must not be empty")
        return value


class AuditResponse(BaseModel):
    auditeventid: str
    eventtype: AuditEventType
    severity: AuditSeverity
    actiontype: str
    target: str
    filepath: str
    traceid: str
    requestid: str
    decisionid: str
    baseriskscore: int
    adjustedriskscore: int
    summary: str
    reasons: list[AuditReasonView] = Field(default_factory=list)
    promptinjection: dict[str, Any] = Field(default_factory=dict)
    hostilecontext: dict[str, Any] = Field(default_factory=dict)
    createdat: str


def createauditevent(
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
    safe_metadata = metadata or {}
    decision = decideaction(
        actiontype=actiontype,
        target=target,
        content=content,
        riskscore=riskscore,
        clientid=clientid,
        sessionid=sessionid,
        filepath=filepath,
        metadata=safe_metadata,
    )

    outcome = _coerceoutcome(decision.get("outcome"))
    eventtype, severity, summary = _eventshape(outcome)

    return {
        "auditeventid": _newid("audit"),
        "eventtype": eventtype,
        "severity": severity,
        "actiontype": actiontype,
        "target": target,
        "filepath": str(decision.get("filepath") or filepath or ""),
        "traceid": str(decision.get("traceid") or _newid("trace")),
        "requestid": str(decision.get("requestid") or _newid("req")),
        "decisionid": str(decision.get("decisionid") or _newid("dec")),
        "baseriskscore": int(decision.get("baseriskscore", riskscore)),
        "adjustedriskscore": int(decision.get("adjustedriskscore", riskscore)),
        "summary": str(decision.get("summary") or summary),
        "reasons": decision.get("reasons") or [],
        "promptinjection": decision.get("promptinjection") or {},
        "hostilecontext": decision.get("hostilecontext") or {},
        "createdat": _utcnow(),
    }


@router.post(
    "/event",
    response_model=AuditResponse,
    summary="Create an audit event from the secured action decision path.",
)
def auditevent(payload: AuditRequest) -> AuditResponse:
    result = createauditevent(
        actiontype=payload.actiontype,
        target=payload.target,
        content=payload.content,
        riskscore=payload.riskscore,
        clientid=payload.clientid,
        sessionid=payload.sessionid,
        filepath=payload.filepath,
        metadata=payload.metadata,
    )
    return AuditResponse(**result)