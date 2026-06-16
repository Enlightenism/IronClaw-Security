from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.api.actiondecision import decideaction
from app.core.auth import require_auth_context
from app.schemas.audit import (
    AuditEvent,
    AuditEventCreate,
    AuditEventResponse,
    AuditListResponse,
)
from app.services.audit_log_service import (
    get_audit_event_as_schema,
    list_audit_events_as_schema,
)

router = APIRouter(prefix="/audit", tags=["audit"])


# ---------------------------------------------------------------------------
# Local literals — intentionally distinct from app.schemas.audit enums
# so legacy callers are not disrupted
# ---------------------------------------------------------------------------

_LegacyEventType = Literal[
    "execution_allowed",
    "execution_review",
    "execution_quarantined",
    "execution_denied",
]
_LegacySeverity = Literal["info", "warning", "high", "critical"]


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _newid(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _coerceoutcome(value: Any) -> str:
    outcome = str(value or "").strip().lower()
    if outcome in {"allow", "review", "quarantine", "deny", "denied", "block", "blocked"}:
        return outcome
    return "deny"


def _eventshape(outcome: str) -> tuple[_LegacyEventType, _LegacySeverity, str]:
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


# ---------------------------------------------------------------------------
# Legacy request / response models — contract preserved
# ---------------------------------------------------------------------------


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
    eventtype: _LegacyEventType
    severity: _LegacySeverity
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


# ---------------------------------------------------------------------------
# Core audit event factory — legacy contract preserved
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/event",
    response_model=AuditResponse,
    summary="Create an audit event from the secured action decision path.",
)
def auditevent(
    payload: AuditRequest,
    _auth: dict = Depends(require_auth_context),
) -> AuditResponse:
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


@router.get(
    "/events",
    response_model=AuditListResponse,
    summary="List recent audit events from the audit log.",
)
def list_events(
    limit: int = Query(default=100, ge=1, le=1000, description="Maximum number of events to return."),
    _auth: dict = Depends(require_auth_context),
) -> AuditListResponse:
    items: list[AuditEventCreate] = list_audit_events_as_schema(limit=limit)
    audit_events: list[AuditEvent] = []
    for i, item in enumerate(items):
        audit_events.append(
            AuditEvent(
                event_id=f"evt_{i}",
                event_type=item.event_type,
                actor=item.actor,
                actor_type=item.actor_type,
                target_type=item.target_type,
                target_id=item.target_id,
                action=item.action,
                outcome=item.outcome,
                severity=item.severity,
                org_id=item.org_id,
                session_id=item.session_id,
                request_id=item.request_id,
                risk_score=item.risk_score,
                categories=item.categories,
                tags=item.tags,
                reasoning=item.reasoning,
                metadata=item.metadata,
            )
        )
    return AuditListResponse(count=len(audit_events), total=len(audit_events), items=audit_events)


@router.get(
    "/events/{event_id}",
    response_model=AuditEventResponse,
    summary="Retrieve a single audit event by event ID.",
)
def get_event(
    event_id: str,
    _auth: dict = Depends(require_auth_context),
) -> AuditEventResponse:
    item = get_audit_event_as_schema(event_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Audit event '{event_id}' not found.")
    return AuditEventResponse(ok=True, event_id=event_id)
